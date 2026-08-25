package masque

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"testing"
	"time"

	masquego "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"

	"github.com/xiaozhou26/outway/internal/config"
	"github.com/xiaozhou26/outway/internal/connect"
	"github.com/xiaozhou26/outway/internal/serverbase"
)

func TestMASQUEInterop(t *testing.T) {
	t.Setenv("STATE_DIRECTORY", t.TempDir())

	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = echo.Close() }()
	go func() {
		buffer := make([]byte, 1500)
		for {
			n, addr, err := echo.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			_, _ = echo.WriteToUDP(buffer[:n], addr)
		}
	}()

	reuse := true
	ctx := serverbase.Context{
		Bind:           netip.MustParseAddrPort("127.0.0.1:0"),
		Concurrent:     8,
		ConnectTimeout: 2,
		Connector:      connect.New(nil, nil, nil, 2, nil, &reuse, 0),
		UDP:            config.DefaultBootArgs().UDP,
	}
	server, err := NewServer(ctx, "", "")
	if err != nil {
		t.Fatal(err)
	}
	packetConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = packetConn.Close() }()
	server.ctx.Bind = packetConn.LocalAddr().(*net.UDPAddr).AddrPort()
	server.template = uritemplate.MustNew(templateURL(server.ctx.Bind))
	server.server.Addr = packetConn.LocalAddr().String()
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.server.Serve(packetConn) }()
	defer func() {
		_ = server.Close()
		select {
		case <-serveDone:
		case <-time.After(3 * time.Second):
			t.Error("MASQUE server did not stop")
		}
	}()

	proxyAddr := packetConn.LocalAddr().String()
	template := uritemplate.MustNew("https://" + proxyAddr + proxyPath + "{target_host}/{target_port}/")
	request, err := masquego.NewRequest(context.Background(), template, echo.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	transport := masquego.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3}}}
	conn, response, err := transport.Dial(request)
	if err != nil {
		if response != nil {
			t.Fatalf("MASQUE dial failed with HTTP %d: %v", response.StatusCode, err)
		}
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	payload := []byte("outway-masque")
	if _, err := conn.WriteTo(payload, nil); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, _, err := conn.ReadFrom(got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}
}

func TestMASQUEIdleTimeoutReleasesTunnelSlot(t *testing.T) {
	t.Setenv("STATE_DIRECTORY", t.TempDir())

	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = echo.Close() }()

	reuse := true
	udpConfig := config.DefaultBootArgs().UDP
	udpConfig.AssociationIdleTimeoutSecs = 1
	ctx := serverbase.Context{
		Bind:           netip.MustParseAddrPort("127.0.0.1:0"),
		Concurrent:     1,
		ConnectTimeout: 2,
		Connector:      connect.New(nil, nil, nil, 2, nil, &reuse, 0),
		UDP:            udpConfig,
	}
	server, err := NewServer(ctx, "", "")
	if err != nil {
		t.Fatal(err)
	}
	packetConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = packetConn.Close() }()
	server.ctx.Bind = packetConn.LocalAddr().(*net.UDPAddr).AddrPort()
	server.template = uritemplate.MustNew(templateURL(server.ctx.Bind))
	server.server.Addr = packetConn.LocalAddr().String()
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.server.Serve(packetConn) }()
	defer func() {
		_ = server.Close()
		select {
		case <-serveDone:
		case <-time.After(3 * time.Second):
			t.Error("MASQUE server did not stop")
		}
	}()

	proxyAddr := packetConn.LocalAddr().String()
	template := uritemplate.MustNew("https://" + proxyAddr + proxyPath + "{target_host}/{target_port}/")
	transport := masquego.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3}}}
	dial := func() net.PacketConn {
		request, err := masquego.NewRequest(context.Background(), template, echo.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		conn, response, err := transport.Dial(request)
		if err != nil {
			if response != nil {
				t.Fatalf("MASQUE dial failed with HTTP %d: %v", response.StatusCode, err)
			}
			t.Fatal(err)
		}
		return conn
	}

	first := dial()
	defer func() { _ = first.Close() }()
	if got := len(server.limit); got != 1 {
		t.Fatalf("active tunnel slots = %d, want 1", got)
	}

	deadline := time.Now().Add(4 * time.Second)
	for len(server.limit) != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := len(server.limit); got != 0 {
		t.Fatalf("idle tunnel slot was not released: active=%d", got)
	}

	second := dial()
	if err := second.Close(); err != nil {
		t.Fatalf("close replacement tunnel: %v", err)
	}
}
