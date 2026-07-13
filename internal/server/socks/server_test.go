package socks

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/xiaozhou26/outway/internal/config"
	"github.com/xiaozhou26/outway/internal/connect"
	"github.com/xiaozhou26/outway/internal/server/socks/proto"
	"github.com/xiaozhou26/outway/internal/serverbase"
)

func TestUDPBatchReaderDetectsConfiguredOversize(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()

	runtime := newUDPRuntime(config.UDPConfig{
		MaxPacketSize: 512,
		BatchSize:     1,
		SendQueueSize: 1,
	}, 1, context.Background())
	reader := newUDPBatchReader(conn, runtime, 0, 64)
	target := conn.LocalAddr().(*net.UDPAddr)

	for _, test := range []struct {
		name      string
		size      int
		truncated bool
	}{
		{name: "exact limit", size: 64, truncated: false},
		{name: "over limit", size: 65, truncated: true},
		{name: "larger than probe buffer", size: 66, truncated: true},
		{name: "reader continues after truncation", size: 32, truncated: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := sender.WriteToUDP(bytes.Repeat([]byte{0x5a}, test.size), target); err != nil {
				t.Fatal(err)
			}
			packets, err := reader.Read()
			if err != nil {
				t.Fatal(err)
			}
			if len(packets) != 1 || packets[0].truncated != test.truncated {
				t.Fatalf("size %d: got %+v", test.size, packets)
			}
			runtime.releaseReadPacket(packets[0])
		})
	}
}

func TestUDPRuntimeAssociationLimit(t *testing.T) {
	runtime := newUDPRuntime(config.UDPConfig{
		MaxPacketSize:   512,
		BatchSize:       1,
		SendQueueSize:   1,
		MaxAssociations: 1,
	}, 8, context.Background())
	if _, ok := runtime.beginAssociation(); !ok {
		t.Fatal("first association should be admitted")
	}
	if _, ok := runtime.beginAssociation(); ok {
		t.Fatal("second association should be rejected")
	}
	runtime.endAssociation()
	if _, ok := runtime.beginAssociation(); !ok {
		t.Fatal("slot should be reusable after association closes")
	}
	runtime.endAssociation()
	if got := runtime.metrics.associationDrops.Load(); got != 1 {
		t.Fatalf("association limit drops = %d, want 1", got)
	}
}

func TestUDPRuntimeBatchBufferBudget(t *testing.T) {
	runtime := newUDPRuntime(config.UDPConfig{
		MaxPacketSize:     512,
		BatchSize:         8,
		BatchBufferBudget: 1,
		SendQueueSize:     1,
	}, 1, context.Background())
	if !runtime.tryAcquireBatchBuffer() {
		t.Fatal("first batch buffer should fit within budget")
	}
	if runtime.tryAcquireBatchBuffer() {
		t.Fatal("second batch buffer should exceed budget")
	}
	runtime.releaseBuffer(runtime.getBuffer(), true)
	if !runtime.tryAcquireBatchBuffer() {
		t.Fatal("released batch budget should be reusable")
	}
	runtime.releaseBuffer(runtime.getBuffer(), true)
}

func TestSOCKS5UDPLargeDatagram(t *testing.T) {
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buffer := make([]byte, 65535)
		n, remote, err := echo.ReadFromUDP(buffer)
		if err == nil {
			_, _ = echo.WriteToUDP(buffer[:n], remote)
		}
	}()

	proxy, err := NewServer(serverbase.Context{
		Bind:           netip.MustParseAddrPort("127.0.0.1:0"),
		Concurrent:     8,
		ConnectTimeout: 5,
		Connector:      connect.New(nil, nil, nil, 5, nil, nil),
		UDP:            config.DefaultBootArgs().UDP,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	go func() { _ = proxy.Start() }()

	association, err := openSOCKS5UDPAssociation(proxy.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer association.control.Close()
	defer association.client.Close()
	if err := association.client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}

	// A single datagram larger than a normal MTU, but within the smallest
	// default per-datagram send limit across platforms (macOS caps UDP
	// datagrams at net.inet.udp.maxdgram = 9216 bytes by default, whereas
	// Linux allows up to 64 KiB). 8 KiB keeps the test portable while still
	// exercising the large-datagram relay path.
	payload := make([]byte, 8*1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	packet := proto.BuildUdpPacket(0, proto.SocketAddress(echo.LocalAddr().(*net.UDPAddr).AddrPort()), payload)
	if _, err := association.client.WriteToUDP(packet, association.relay); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(packet)+32)
	n, _, err := association.client.ReadFromUDP(response)
	if err != nil {
		t.Fatal(err)
	}
	_, headerLength, err := proto.ReadUdpHeader(bytes.NewReader(response[:n]))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response[headerLength:n], payload) {
		t.Fatalf("large UDP payload mismatch: got %d bytes, want %d", n-headerLength, len(payload))
	}
}

type udpStressAssociation struct {
	control *net.TCPConn
	client  *net.UDPConn
	relay   *net.UDPAddr
}

func TestWriteUDPResponseTargetsClient(t *testing.T) {
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()

	remote := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 10), Port: 5353}
	pkt := outboundPacket{payload: []byte("response"), remote: remote}
	clientAddr := client.LocalAddr().(*net.UDPAddr).AddrPort()
	if err := writeUDPResponse(relay, clientAddr, pkt); err != nil {
		t.Fatal(err)
	}

	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 256)
	n, _, err := client.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	header, headerLen, err := proto.ReadUdpHeader(bytes.NewReader(buf[:n]))
	if err != nil {
		t.Fatal(err)
	}
	expectedRemote := netip.MustParseAddrPort("198.51.100.10:5353")
	if header.Address.Socket == nil || header.Address.Socket.Addr().Unmap() != expectedRemote.Addr() || header.Address.Socket.Port() != expectedRemote.Port() {
		t.Fatalf("unexpected remote address: %+v", header.Address)
	}
	if got := string(buf[headerLen:n]); got != "response" {
		t.Fatalf("unexpected payload: %q", got)
	}
}

func TestServerCloseCancelsPendingBind(t *testing.T) {
	proxy, err := NewServer(serverbase.Context{
		Bind:           netip.MustParseAddrPort("127.0.0.1:0"),
		Concurrent:     1,
		ConnectTimeout: 30,
		Connector:      connect.New(nil, nil, nil, 30, nil, nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- proxy.Start() }()

	controlConn, err := net.DialTimeout("tcp4", proxy.listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer controlConn.Close()
	if _, err := controlConn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(controlConn, response); err != nil {
		t.Fatal(err)
	}
	if _, err := controlConn.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	bindResponse := make([]byte, 10)
	if _, err := io.ReadFull(controlConn, bindResponse); err != nil {
		t.Fatal(err)
	}
	if bindResponse[1] != 0x00 {
		t.Fatalf("BIND failed with reply %#x", bindResponse[1])
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- proxy.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("close failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server close did not cancel pending BIND")
	}
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("serve loop failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("serve loop did not stop")
	}
}

func TestSOCKS5ConcurrentTunnelsStress(t *testing.T) {
	countString := os.Getenv("OUTWAY_STRESS_CONNECTIONS")
	if countString == "" {
		t.Skip("set OUTWAY_STRESS_CONNECTIONS to run the high-concurrency stress test")
	}
	count, err := strconv.Atoi(countString)
	if err != nil || count < 1 {
		t.Fatalf("invalid OUTWAY_STRESS_CONNECTIONS value %q", countString)
	}
	rounds := stressRounds(t)

	echo, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()

	proxy, err := NewServer(serverbase.Context{
		Bind:           netip.MustParseAddrPort("127.0.0.1:0"),
		Concurrent:     uint32(count + 128),
		ConnectTimeout: 10,
		Connector:      connect.New(nil, nil, nil, 10, nil, nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	go func() { _ = proxy.Start() }()

	connections := make([]net.Conn, count)
	jobs := make(chan int)
	errorsCh := make(chan error, count)
	workers := 128
	if count < workers {
		workers = count
	}
	var openWG sync.WaitGroup
	for range workers {
		openWG.Add(1)
		go func() {
			defer openWG.Done()
			for index := range jobs {
				conn, err := openSOCKS5Tunnel(proxy.listener.Addr().String(), echo.Addr().(*net.TCPAddr).AddrPort())
				if err != nil {
					errorsCh <- err
					continue
				}
				connections[index] = conn
			}
		}()
	}
	for index := range count {
		jobs <- index
	}
	close(jobs)
	openWG.Wait()
	close(errorsCh)
	for err := range errorsCh {
		t.Errorf("open tunnel: %v", err)
	}
	if t.Failed() {
		for _, conn := range connections {
			if conn != nil {
				conn.Close()
			}
		}
		return
	}

	payload := []byte("outway-stress")
	var roundTripWG sync.WaitGroup
	roundTripErrors := make(chan error, count)
	for _, conn := range connections {
		roundTripWG.Add(1)
		go func() {
			defer roundTripWG.Done()
			response := make([]byte, len(payload))
			for range rounds {
				if _, err := conn.Write(payload); err != nil {
					roundTripErrors <- err
					return
				}
				if _, err := io.ReadFull(conn, response); err != nil {
					roundTripErrors <- err
					return
				}
				if !bytes.Equal(response, payload) {
					roundTripErrors <- fmt.Errorf("unexpected response %q", response)
					return
				}
			}
		}()
	}
	roundTripWG.Wait()
	close(roundTripErrors)
	for err := range roundTripErrors {
		t.Errorf("tunnel round trip: %v", err)
	}
	for _, conn := range connections {
		_ = conn.Close()
	}
}

func stressRounds(t *testing.T) int {
	t.Helper()
	rounds := 1
	if value := os.Getenv("OUTWAY_STRESS_ROUNDS"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 {
			t.Fatalf("invalid OUTWAY_STRESS_ROUNDS value %q", value)
		}
		rounds = parsed
	}
	return rounds
}

func TestSOCKS5UDPAssociationsStress(t *testing.T) {
	associationString := os.Getenv("OUTWAY_STRESS_UDP_ASSOCIATIONS")
	if associationString == "" {
		t.Skip("set OUTWAY_STRESS_UDP_ASSOCIATIONS to run the UDP stress test")
	}
	associationCount, err := strconv.Atoi(associationString)
	if err != nil || associationCount < 1 {
		t.Fatalf("invalid OUTWAY_STRESS_UDP_ASSOCIATIONS value %q", associationString)
	}
	packetsPerAssociation := 100
	if packetString := os.Getenv("OUTWAY_STRESS_UDP_PACKETS"); packetString != "" {
		packetsPerAssociation, err = strconv.Atoi(packetString)
		if err != nil || packetsPerAssociation < 1 {
			t.Fatalf("invalid OUTWAY_STRESS_UDP_PACKETS value %q", packetString)
		}
	}

	// One echo socket per association: a single shared echo socket's kernel
	// receive buffer (net.core.rmem_default) silently drops packets when
	// hundreds of associations burst at once, which would measure the host
	// sysctl instead of the relay.
	echoSockets := make([]*net.UDPConn, associationCount)
	for index := range associationCount {
		echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		echoSockets[index] = echo
		go func() {
			buffer := make([]byte, 2048)
			for {
				n, remote, err := echo.ReadFromUDP(buffer)
				if err != nil {
					return
				}
				_, _ = echo.WriteToUDP(buffer[:n], remote)
			}
		}()
	}
	defer func() {
		for _, echo := range echoSockets {
			_ = echo.Close()
		}
	}()

	proxy, err := NewServer(serverbase.Context{
		Bind:           netip.MustParseAddrPort("127.0.0.1:0"),
		Concurrent:     uint32(associationCount + 128),
		ConnectTimeout: 10,
		Connector:      connect.New(nil, nil, nil, 10, nil, nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	go func() { _ = proxy.Start() }()

	associations := make([]udpStressAssociation, associationCount)
	for index := range associationCount {
		association, err := openSOCKS5UDPAssociation(proxy.listener.Addr().String())
		if err != nil {
			t.Fatalf("open association %d: %v", index, err)
		}
		associations[index] = association
	}
	defer func() {
		for _, association := range associations {
			if association.client != nil {
				association.client.Close()
			}
			if association.control != nil {
				association.control.Close()
			}
		}
	}()

	var wg sync.WaitGroup
	errorsCh := make(chan error, associationCount)
	for associationIndex, association := range associations {
		wg.Add(1)
		go func() {
			defer wg.Done()
			target := echoSockets[associationIndex].LocalAddr().(*net.UDPAddr).AddrPort()
			responseBuffer := make([]byte, 2048)
			for packetIndex := range packetsPerAssociation {
				// The deadline bounds one round trip, not the association
				// lifetime: the test asserts zero loss, not aggregate latency.
				if err := association.client.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
					errorsCh <- err
					return
				}
				var payload [8]byte
				binary.BigEndian.PutUint32(payload[:4], uint32(associationIndex))
				binary.BigEndian.PutUint32(payload[4:], uint32(packetIndex))
				packet := proto.BuildUdpPacket(0, proto.SocketAddress(target), payload[:])
				if _, err := association.client.WriteToUDP(packet, association.relay); err != nil {
					errorsCh <- err
					return
				}
				n, _, err := association.client.ReadFromUDP(responseBuffer)
				if err != nil {
					errorsCh <- err
					return
				}
				_, headerLength, err := proto.ReadUdpHeader(bytes.NewReader(responseBuffer[:n]))
				if err != nil {
					errorsCh <- err
					return
				}
				if !bytes.Equal(responseBuffer[headerLength:n], payload[:]) {
					errorsCh <- fmt.Errorf("association %d packet %d returned invalid payload", associationIndex, packetIndex)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errorsCh)
	for err := range errorsCh {
		t.Error(err)
	}
}

func openSOCKS5UDPAssociation(proxyAddress string) (udpStressAssociation, error) {
	controlConn, err := net.DialTimeout("tcp4", proxyAddress, 5*time.Second)
	if err != nil {
		return udpStressAssociation{}, err
	}
	control := controlConn.(*net.TCPConn)
	fail := func(err error) (udpStressAssociation, error) {
		control.Close()
		return udpStressAssociation{}, err
	}
	if _, err := control.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return fail(err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(control, response); err != nil {
		return fail(err)
	}
	if response[1] != 0x00 {
		return fail(fmt.Errorf("unexpected handshake method %#x", response[1]))
	}
	if _, err := control.Write([]byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}); err != nil {
		return fail(err)
	}
	associateResponse := make([]byte, 10)
	if _, err := io.ReadFull(control, associateResponse); err != nil {
		return fail(err)
	}
	if associateResponse[1] != 0x00 || associateResponse[3] != 0x01 {
		return fail(fmt.Errorf("unexpected UDP associate response %x", associateResponse))
	}
	relay := &net.UDPAddr{
		IP:   net.IPv4(associateResponse[4], associateResponse[5], associateResponse[6], associateResponse[7]),
		Port: int(binary.BigEndian.Uint16(associateResponse[8:10])),
	}
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return fail(err)
	}
	return udpStressAssociation{control: control, client: client, relay: relay}, nil
}

func BenchmarkSOCKS5TunnelRoundTripParallel(b *testing.B) {
	echo, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()

	ctx := serverbase.Context{
		Bind:           netip.MustParseAddrPort("127.0.0.1:0"),
		Concurrent:     10000,
		ConnectTimeout: 5,
		Connector:      connect.New(nil, nil, nil, 5, nil, nil),
	}
	proxy, err := NewServer(ctx)
	if err != nil {
		b.Fatal(err)
	}
	defer proxy.Close()
	go func() { _ = proxy.Start() }()

	target := echo.Addr().(*net.TCPAddr).AddrPort()
	payload := bytes.Repeat([]byte("x"), 1024)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		conn, err := openSOCKS5Tunnel(proxy.listener.Addr().String(), target)
		if err != nil {
			b.Error(err)
			return
		}
		defer conn.Close()
		response := make([]byte, len(payload))
		for pb.Next() {
			if _, err := conn.Write(payload); err != nil {
				b.Error(err)
				return
			}
			if _, err := io.ReadFull(conn, response); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

func openSOCKS5Tunnel(proxyAddress string, target netip.AddrPort) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp4", proxyAddress, 5*time.Second)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, err
	}
	handshakeResponse := make([]byte, 2)
	if _, err := io.ReadFull(conn, handshakeResponse); err != nil {
		conn.Close()
		return nil, err
	}
	if handshakeResponse[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("unexpected handshake method: %#x", handshakeResponse[1])
	}

	ip := target.Addr().As4()
	request := []byte{0x05, 0x01, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], byte(target.Port() >> 8), byte(target.Port())}
	if _, err := conn.Write(request); err != nil {
		conn.Close()
		return nil, err
	}
	connectResponse := make([]byte, 10)
	if _, err := io.ReadFull(conn, connectResponse); err != nil {
		conn.Close()
		return nil, err
	}
	if connectResponse[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("connect failed with reply: %#x", connectResponse[1])
	}
	return conn, nil
}
