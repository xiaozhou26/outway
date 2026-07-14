package socks

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/xiaozhou26/outway/internal/config"
	"github.com/xiaozhou26/outway/internal/connect"
	"github.com/xiaozhou26/outway/internal/server/socks/proto"
	"github.com/xiaozhou26/outway/internal/serverbase"
)

// TestSOCKS5ReusePortServer runs the SOCKS5 server with reuse-port enabled so it
// binds multiple SO_REUSEPORT listeners and accept loops, then verifies a UDP
// relay works across it and the multi-listener shutdown is clean.
func TestSOCKS5ReusePortServer(t *testing.T) {
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
		Concurrent:     16,
		ConnectTimeout: 5,
		Connector:      connect.New(nil, nil, nil, 5, nil, nil, 0),
		UDP:            config.DefaultBootArgs().UDP,
		ReusePort:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = proxy.Start() }()

	// Drive a few associations so different shards accept the control connections.
	target := echo.LocalAddr().(*net.UDPAddr).AddrPort()
	for round := range 5 {
		association, err := openSOCKS5UDPAssociation(proxy.listener.Addr().String())
		if err != nil {
			t.Fatalf("round %d open: %v", round, err)
		}
		if err := association.client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		payload := []byte("reuseport")
		packet := proto.BuildUdpPacket(0, proto.SocketAddress(target), payload)
		if _, err := association.client.WriteToUDP(packet, association.relay); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, 2048)
		n, _, err := association.client.ReadFromUDP(response)
		if err != nil {
			t.Fatalf("round %d read: %v", round, err)
		}
		_, headerLen, err := proto.ReadUdpHeader(bytes.NewReader(response[:n]))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(response[headerLen:n], payload) {
			t.Fatalf("round %d payload mismatch", round)
		}
		association.client.Close()
		association.control.Close()
	}

	if err := proxy.Close(); err != nil {
		t.Fatalf("multi-listener close: %v", err)
	}
}
