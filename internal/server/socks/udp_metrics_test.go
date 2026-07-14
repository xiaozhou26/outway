package socks

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/xiaozhou26/outway/internal/config"
	"github.com/xiaozhou26/outway/internal/connect"
	"github.com/xiaozhou26/outway/internal/server/socks/proto"
	"github.com/xiaozhou26/outway/internal/serverbase"
)

// TestUDPMetricsBatchedCounts drives a known number of datagrams through an
// association and asserts the per-batch-accumulated in/out counters exactly
// match the traffic, guarding the batched-metric accounting.
func TestUDPMetricsBatchedCounts(t *testing.T) {
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
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

	proxy, err := NewServer(serverbase.Context{
		Bind:           netip.MustParseAddrPort("127.0.0.1:0"),
		Concurrent:     8,
		ConnectTimeout: 5,
		Connector:      connect.New(nil, nil, nil, 5, nil, nil, 0),
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
	if err := association.client.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}

	const count = 50
	const payloadSize = 100
	target := echo.LocalAddr().(*net.UDPAddr).AddrPort()
	response := make([]byte, 2048)
	for i := range count {
		payload := make([]byte, payloadSize)
		binary.BigEndian.PutUint32(payload[:4], uint32(i))
		packet := proto.BuildUdpPacket(0, proto.SocketAddress(target), payload)
		if _, err := association.client.WriteToUDP(packet, association.relay); err != nil {
			t.Fatal(err)
		}
		n, _, err := association.client.ReadFromUDP(response)
		if err != nil {
			t.Fatalf("datagram %d: %v", i, err)
		}
		if _, headerLen, err := proto.ReadUdpHeader(bytes.NewReader(response[:n])); err != nil || !bytes.Equal(response[headerLen:n], payload) {
			t.Fatalf("datagram %d payload mismatch (err=%v)", i, err)
		}
	}

	metrics := &proxy.acceptor.udp.metrics
	// The outbound counter flushes just after the client read returns, so poll.
	deadline := time.Now().Add(2 * time.Second)
	for metrics.outPackets.Load() < count && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if got := metrics.inPackets.Load(); got != count {
		t.Fatalf("inPackets = %d, want %d", got, count)
	}
	if got := metrics.outPackets.Load(); got != count {
		t.Fatalf("outPackets = %d, want %d", got, count)
	}
	if got := metrics.inBytes.Load(); got != count*payloadSize {
		t.Fatalf("inBytes = %d, want %d", got, count*payloadSize)
	}
	if got := metrics.outBytes.Load(); got != count*payloadSize {
		t.Fatalf("outBytes = %d, want %d", got, count*payloadSize)
	}
}
