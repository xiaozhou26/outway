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

func newIdleTimeoutProxy(t *testing.T, idleSecs uint64) (*Socks5Server, netip.AddrPort) {
	t.Helper()
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
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
	udpConfig.AssociationIdleTimeoutSecs = idleSecs
	proxy, err := NewServer(serverbase.Context{
		Bind:           netip.MustParseAddrPort("127.0.0.1:0"),
		Concurrent:     8,
		ConnectTimeout: 5,
		Connector:      connect.New(nil, nil, nil, 5, nil, nil),
		UDP:            udpConfig,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { proxy.Close() })
	go func() { _ = proxy.Start() }()
	return proxy, echo.LocalAddr().(*net.UDPAddr).AddrPort()
}

func udpRoundTrip(t *testing.T, a udpStressAssociation, target netip.AddrPort, seq uint32) {
	t.Helper()
	var payload [4]byte
	binary.BigEndian.PutUint32(payload[:], seq)
	if _, err := a.client.WriteToUDP(proto.BuildUdpPacket(0, proto.SocketAddress(target), payload[:]), a.relay); err != nil {
		t.Fatal(err)
	}
	_ = a.client.SetReadDeadline(time.Now().Add(3 * time.Second))
	response := make([]byte, 2048)
	n, _, err := a.client.ReadFromUDP(response)
	if err != nil {
		t.Fatalf("round trip seq %d: %v", seq, err)
	}
	_, headerLen, err := proto.ReadUdpHeader(bytes.NewReader(response[:n]))
	if err != nil || !bytes.Equal(response[headerLen:n], payload[:]) {
		t.Fatalf("round trip seq %d mismatch (err=%v)", seq, err)
	}
}

// TestSOCKS5UDPIdleTimeoutCloses checks that an idle association is closed by the
// server (the control connection is closed) after the idle timeout elapses.
func TestSOCKS5UDPIdleTimeoutCloses(t *testing.T) {
	proxy, target := newIdleTimeoutProxy(t, 1)
	association, err := openSOCKS5UDPAssociation(proxy.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer association.client.Close()
	defer association.control.Close()

	udpRoundTrip(t, association, target, 1) // one activity, resets idle

	// Go idle. The server must close the control connection within a couple of
	// idle windows; a read that blocks until our own deadline means it did not.
	_ = association.control.SetReadDeadline(time.Now().Add(4 * time.Second))
	if _, err := association.control.Read(make([]byte, 1)); err == nil {
		t.Fatal("control connection should be closed after idle timeout")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("association did not time out — control read hit the test deadline instead of closing")
	}
}

// TestSOCKS5UDPIdleTimeoutStaysAliveWhileActive checks that continuous activity
// keeps the association open well past a single idle window.
func TestSOCKS5UDPIdleTimeoutStaysAliveWhileActive(t *testing.T) {
	proxy, target := newIdleTimeoutProxy(t, 1)
	association, err := openSOCKS5UDPAssociation(proxy.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer association.client.Close()
	defer association.control.Close()

	// Relay every 400ms for ~2s (two idle windows); each round trip must succeed,
	// proving activity keeps resetting the idle deadline.
	for seq := uint32(0); seq < 5; seq++ {
		udpRoundTrip(t, association, target, seq)
		time.Sleep(400 * time.Millisecond)
	}
	// Confirm the control connection is still open (not closed by an idle timeout).
	_ = association.control.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := association.control.Read(make([]byte, 1)); err == nil {
		t.Fatal("unexpected data on control connection")
	} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("association closed while active: %v", err)
	}
}
