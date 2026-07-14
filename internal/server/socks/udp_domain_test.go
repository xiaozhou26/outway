package socks

import (
	"bytes"
	"context"
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

// TestSOCKS5UDPDomainTarget relays datagrams whose SOCKS5 header carries a
// domain name. The first datagram takes the cold-lookup worker path; once the
// name is cached, later datagrams take the fast batch path. Echoes are bound on
// both loopback families at the same port so whichever address "localhost"
// resolves to has a listener.
func TestSOCKS5UDPDomainTarget(t *testing.T) {
	if _, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip", "localhost"); err != nil {
		t.Skipf("localhost does not resolve: %v", err)
	}

	v4, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer v4.Close()
	port := v4.LocalAddr().(*net.UDPAddr).Port

	echoLoop := func(conn *net.UDPConn) {
		buffer := make([]byte, 2048)
		for {
			n, remote, err := conn.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buffer[:n], remote)
		}
	}
	go echoLoop(v4)
	if v6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: port}); err == nil {
		defer v6.Close()
		go echoLoop(v6)
	}

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

	domain := proto.DomainAddress("localhost", uint16(port))
	response := make([]byte, 2048)
	const count = 20
	for i := range count {
		var payload [4]byte
		binary.BigEndian.PutUint32(payload[:], uint32(i))
		packet := proto.BuildUdpPacket(0, domain, payload[:])
		if _, err := association.client.WriteToUDP(packet, association.relay); err != nil {
			t.Fatal(err)
		}
		n, _, err := association.client.ReadFromUDP(response)
		if err != nil {
			t.Fatalf("datagram %d (cold path first): %v", i, err)
		}
		_, headerLen, err := proto.ReadUdpHeader(bytes.NewReader(response[:n]))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(response[headerLen:n], payload[:]) {
			t.Fatalf("datagram %d payload mismatch", i)
		}
	}
}
