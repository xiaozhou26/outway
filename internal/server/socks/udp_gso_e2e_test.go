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

// TestSOCKS5UDPGSOAssociation drives a single-target uniform-size burst through
// an association with GSO enabled and asserts every datagram is relayed and
// echoed back intact. On a kernel with UDP_SEGMENT the drained batches take the
// GSO path; otherwise the same traffic falls back to sendmmsg. Either way the
// relay must deliver every datagram, so the test also guards the fallback.
func TestSOCKS5UDPGSOAssociation(t *testing.T) {
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	// A generous read buffer so the burst is not dropped before the echo drains.
	_ = echo.SetReadBuffer(4 << 20)
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

	udpConfig := config.DefaultBootArgs().UDP
	udpConfig.GSO = true
	proxy, err := NewServer(serverbase.Context{
		Bind:           netip.MustParseAddrPort("127.0.0.1:0"),
		Concurrent:     8,
		ConnectTimeout: 5,
		Connector:      connect.New(nil, nil, nil, 5, nil, nil, 0),
		UDP:            udpConfig,
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
	_ = association.client.SetReadBuffer(4 << 20)
	if err := association.client.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}

	// Uniform-size datagrams to one target: the GSO eligibility criteria.
	const count = 200
	const payloadSize = 200
	target := echo.LocalAddr().(*net.UDPAddr).AddrPort()
	seen := make([]bool, count)
	for i := range count {
		payload := make([]byte, payloadSize)
		binary.BigEndian.PutUint32(payload[:4], uint32(i))
		packet := proto.BuildUdpPacket(0, proto.SocketAddress(target), payload)
		if _, err := association.client.WriteToUDP(packet, association.relay); err != nil {
			t.Fatal(err)
		}
	}

	response := make([]byte, 2048)
	for received := 0; received < count; received++ {
		n, _, err := association.client.ReadFromUDP(response)
		if err != nil {
			t.Fatalf("received %d of %d datagrams: %v", received, count, err)
		}
		_, headerLen, err := proto.ReadUdpHeader(bytes.NewReader(response[:n]))
		if err != nil {
			t.Fatal(err)
		}
		payload := response[headerLen:n]
		if len(payload) != payloadSize {
			t.Fatalf("datagram length %d, want %d", len(payload), payloadSize)
		}
		index := binary.BigEndian.Uint32(payload[:4])
		if index >= count || seen[index] {
			t.Fatalf("unexpected or duplicate datagram index %d", index)
		}
		seen[index] = true
	}
}
