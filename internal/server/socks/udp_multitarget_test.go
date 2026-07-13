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

// TestSOCKS5UDPMultiTargetBatch bursts many datagrams to several distinct
// targets, spanning both IPv4 and IPv6, through a single association so they are
// drained into one send batch. It verifies that every datagram reaches the
// target its SOCKS5 header names, exercising the per-message addressing of the
// sendmmsg batch path and the family routing across the preferred/fallback
// outbound sockets.
func TestSOCKS5UDPMultiTargetBatch(t *testing.T) {
	const packetsPerTarget = 20

	// Half the targets are IPv4 (routed to the preferred socket) and half IPv6
	// (routed to the fallback socket) under the default dual-stack connector.
	families := []string{"udp4", "udp4", "udp4", "udp6", "udp6", "udp6"}
	targets := len(families)

	echoes := make([]*net.UDPConn, targets)
	for i, network := range families {
		loopback := net.IPv4(127, 0, 0, 1)
		if network == "udp6" {
			loopback = net.IPv6loopback
		}
		echo, err := net.ListenUDP(network, &net.UDPAddr{IP: loopback})
		if err != nil {
			t.Skipf("cannot bind %s echo target: %v", network, err)
		}
		defer echo.Close()
		go func(e *net.UDPConn) {
			buffer := make([]byte, 2048)
			for {
				n, remote, err := e.ReadFromUDP(buffer)
				if err != nil {
					return
				}
				_, _ = e.WriteToUDP(buffer[:n], remote)
			}
		}(echo)
		echoes[i] = echo
	}

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
	if err := association.client.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}

	// Encode (target, sequence) so each echoed datagram identifies its target.
	type key struct{ target, seq uint32 }
	expectedAddr := func(i int) netip.AddrPort {
		return echoes[i].LocalAddr().(*net.UDPAddr).AddrPort()
	}
	outstanding := make(map[key]bool)
	for seq := range packetsPerTarget {
		for targetIndex := range echoes {
			var payload [8]byte
			binary.BigEndian.PutUint32(payload[:4], uint32(targetIndex))
			binary.BigEndian.PutUint32(payload[4:], uint32(seq))
			packet := proto.BuildUdpPacket(0, proto.SocketAddress(expectedAddr(targetIndex)), payload[:])
			if _, err := association.client.WriteToUDP(packet, association.relay); err != nil {
				t.Fatal(err)
			}
			outstanding[key{uint32(targetIndex), uint32(seq)}] = true
		}
	}

	total := targets * packetsPerTarget
	response := make([]byte, 2048)
	for range total {
		n, _, err := association.client.ReadFromUDP(response)
		if err != nil {
			t.Fatalf("missing responses, %d still outstanding: %v", len(outstanding), err)
		}
		header, headerLen, err := proto.ReadUdpHeader(bytes.NewReader(response[:n]))
		if err != nil {
			t.Fatal(err)
		}
		payload := response[headerLen:n]
		if len(payload) != 8 || header.Address.Socket == nil {
			t.Fatalf("unexpected response: payload=%d addr=%+v", len(payload), header.Address)
		}
		k := key{binary.BigEndian.Uint32(payload[:4]), binary.BigEndian.Uint32(payload[4:])}
		if !outstanding[k] {
			t.Fatalf("unexpected or duplicate response target=%d seq=%d", k.target, k.seq)
		}
		// The response must carry the address of the exact target the request
		// header named, confirming per-message (and per-family) routing.
		want := expectedAddr(int(k.target))
		got := *header.Address.Socket
		if got.Addr().Unmap() != want.Addr().Unmap() || got.Port() != want.Port() {
			t.Fatalf("response for target=%d arrived from %v, want %v", k.target, got, want)
		}
		delete(outstanding, k)
	}
	if len(outstanding) != 0 {
		t.Fatalf("%d datagrams were not echoed to their target", len(outstanding))
	}
}
