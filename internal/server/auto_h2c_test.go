package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/xiaozhou26/outway/internal/config"
	"github.com/xiaozhou26/outway/internal/connect"
)

func newAutoH2CTestServer(t *testing.T) *AutoDetectServer {
	t.Helper()
	h2c := config.DefaultH2CConfig()
	h2c.Enabled = true
	proxy, err := NewAutoDetectServer(Context{
		Bind:           netip.MustParseAddrPort("127.0.0.1:0"),
		Concurrent:     16,
		ConnectTimeout: 5,
		Connector:      connect.New(nil, nil, nil, 5, nil, nil, 0),
		H2C:            h2c,
	}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = proxy.Start() }()
	t.Cleanup(func() { _ = proxy.Close() })
	return proxy
}

func startAutoEchoTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go acceptTCPEchoConnections(ln)
	return ln.Addr().String()
}

// The auto-detect port routes the HTTP/2 preface ("PRI", first byte 'P') to
// the h2c tunnel server when h2c is enabled.
func TestAutoDetectDispatchesH2C(t *testing.T) {
	proxy := newAutoH2CTestServer(t)
	target := startAutoEchoTarget(t)

	var protocols http.Protocols
	protocols.SetUnencryptedHTTP2(true)
	tr := &http.Transport{Protocols: &protocols}
	cc, err := tr.NewClientConn(context.Background(), "http", proxy.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cc.Close() }()

	for i := range 4 {
		pr, pw := io.Pipe()
		req := &http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Scheme: "http", Host: proxy.listener.Addr().String()},
			Host:   target,
			Header: http.Header{},
			Body:   pr,
		}
		msg := []byte(fmt.Sprintf("tunnel %d", i))
		go func() { _, _ = pw.Write(msg) }()
		resp, err := cc.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %s", resp.Status)
		}
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(resp.Body, got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("echoed %q, want %q", got, msg)
		}
		_ = pw.Close()
		_ = resp.Body.Close()
	}
}

// HTTP/1 requests whose method starts with 'P' must still reach the HTTP/1
// handler when h2c is enabled.
func TestAutoDetectH2CKeepsHTTP1Methods(t *testing.T) {
	proxy := newAutoH2CTestServer(t)
	conn, err := net.DialTimeout("tcp4", proxy.listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprint(conn, "POST http://127.0.0.1:1/ HTTP/1.1\r\nHost: 127.0.0.1:1\r\nContent-Length: 0\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("HTTP/1 POST got no HTTP/1 response: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d, want 502 for an unreachable target", resp.StatusCode)
	}
}

// Bytes sent right behind the CONNECT headers, in the same segment or later
// ones, reach the target in order through the auto-detect port too.
func TestAutoDetectOptimisticConnectPreservesEarlyBytes(t *testing.T) {
	proxy := newAutoTestServer(t)
	target := startAutoEchoTarget(t)
	conn, err := net.DialTimeout("tcp4", proxy.listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	payload := make([]byte, 128<<10)
	_, _ = rand.Read(payload)
	head := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	go func() {
		_, _ = conn.Write(append([]byte(head), payload[:300]...))
		for off := 300; off < len(payload); off += 4093 {
			time.Sleep(time.Millisecond)
			_, _ = conn.Write(payload[off:min(off+4093, len(payload))])
		}
	}()
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %s", resp.Status)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("echoed bytes differ from what was sent behind CONNECT")
	}
}
