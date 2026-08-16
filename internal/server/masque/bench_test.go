package masque

import (
	"context"
	"crypto/tls"
	"fmt"
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

// newBenchServer starts a MASQUE server and UDP echo target on loopback and
// returns the dialed client connection.
func newBenchServer(b *testing.B) *masquego.Conn {
	b.Helper()
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = echo.Close() })
	go func() {
		buffer := make([]byte, 2048)
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
		ConnectTimeout: 5,
		Connector:      connect.New(nil, nil, nil, 5, nil, &reuse, 0),
		UDP:            config.DefaultBootArgs().UDP,
	}
	server, err := NewServer(ctx, "", "")
	if err != nil {
		b.Fatal(err)
	}
	packetConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		_ = packetConn.Close()
		_ = server.Close()
	})
	server.ctx.Bind = packetConn.LocalAddr().(*net.UDPAddr).AddrPort()
	server.template = uritemplate.MustNew(templateURL(server.ctx.Bind))
	go func() { _ = server.server.Serve(packetConn) }()

	proxyAddr := packetConn.LocalAddr().String()
	template := uritemplate.MustNew("https://" + proxyAddr + proxyPath + "{target_host}/{target_port}/")
	request, err := masquego.NewRequest(context.Background(), template, echo.LocalAddr().String())
	if err != nil {
		b.Fatal(err)
	}
	transport := masquego.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3}}}
	conn, _, err := transport.Dial(request)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = conn.Close() })
	return conn
}

// BenchmarkMASQUEDatagramRoundTrip measures one client→proxy→echo→client
// datagram exchange, exercising both pump directions plus QUIC overhead.
func BenchmarkMASQUEDatagramRoundTrip(b *testing.B) {
	conn := newBenchServer(b)
	payload := []byte("outway-masque-benchmark-payload")
	receive := make([]byte, len(payload))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := conn.WriteTo(payload, nil); err != nil {
			b.Fatal(err)
		}
		if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
			b.Fatal(err)
		}
		if _, _, err := conn.ReadFrom(receive); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkMASQUESetupTeardown measures full tunnel establishment and teardown,
// the per-association churn path.
func BenchmarkMASQUESetupTeardown(b *testing.B) {
	// One shared server, one tunnel per iteration.
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = echo.Close() })

	reuse := true
	ctx := serverbase.Context{
		Bind:           netip.MustParseAddrPort("127.0.0.1:0"),
		Concurrent:     8,
		ConnectTimeout: 5,
		Connector:      connect.New(nil, nil, nil, 5, nil, &reuse, 0),
		UDP:            config.DefaultBootArgs().UDP,
	}
	server, err := NewServer(ctx, "", "")
	if err != nil {
		b.Fatal(err)
	}
	packetConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		_ = packetConn.Close()
		_ = server.Close()
	})
	server.ctx.Bind = packetConn.LocalAddr().(*net.UDPAddr).AddrPort()
	server.template = uritemplate.MustNew(templateURL(server.ctx.Bind))
	go func() { _ = server.server.Serve(packetConn) }()

	proxyAddr := packetConn.LocalAddr().String()
	template := uritemplate.MustNew("https://" + proxyAddr + proxyPath + "{target_host}/{target_port}/")
	transport := masquego.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3}}}
	target := echo.LocalAddr().String()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		request, err := masquego.NewRequest(context.Background(), template, target)
		if err != nil {
			b.Fatal(err)
		}
		conn, _, err := transport.Dial(request)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := conn.WriteTo([]byte(fmt.Sprintf("ping-%d", i)), nil); err != nil {
			b.Fatal(err)
		}
		_ = conn.Close()
	}
}
