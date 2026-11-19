package http

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/xiaozhou26/outway/internal/config"
	"github.com/xiaozhou26/outway/internal/connect"
	"github.com/xiaozhou26/outway/internal/serverbase"
)

func startEchoTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

func startProxy(t *testing.T, h2c config.H2CConfig, auth config.AuthMode) string {
	t.Helper()
	proxy, err := NewServer(serverbase.Context{
		Bind:           netip.MustParseAddrPort("127.0.0.1:0"),
		Concurrent:     64,
		ConnectTimeout: 5,
		Auth:           auth,
		Connector:      connect.New(nil, nil, nil, 5, nil, nil, 0),
		H2C:            h2c,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = proxy.Start() }()
	t.Cleanup(func() { _ = proxy.Close() })
	return proxy.listener.Addr().String()
}

func enabledH2C() config.H2CConfig {
	cfg := config.DefaultH2CConfig()
	cfg.Enabled = true
	return cfg
}

func basicAuth(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// newH2CClientConn opens one prior-knowledge HTTP/2 connection to the proxy
// with large receive windows, the way a multiplexing client holds it.
func newH2CClientConn(t *testing.T, proxyAddr string) *stdhttp.ClientConn {
	t.Helper()
	var protocols stdhttp.Protocols
	protocols.SetUnencryptedHTTP2(true)
	tr := &stdhttp.Transport{
		Protocols: &protocols,
		HTTP2: &stdhttp.HTTP2Config{
			MaxReceiveBufferPerConnection: 64 << 20,
			MaxReceiveBufferPerStream:     16 << 20,
		},
	}
	cc, err := tr.NewClientConn(context.Background(), "http", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return cc
}

// openH2CTunnel starts a CONNECT stream and writes early before the response
// arrives, mirroring a client that sends its TLS ClientHello right behind the
// HEADERS frame.
type roundTripper interface {
	RoundTrip(*stdhttp.Request) (*stdhttp.Response, error)
}

func openH2CTunnel(tr roundTripper, proxyAddr, target, auth string, early []byte) (*stdhttp.Response, *io.PipeWriter, error) {
	pr, pw := io.Pipe()
	req := &stdhttp.Request{
		Method: stdhttp.MethodConnect,
		URL:    &url.URL{Scheme: "http", Host: proxyAddr},
		Host:   target,
		Header: stdhttp.Header{},
		Body:   pr,
	}
	if auth != "" {
		req.Header.Set("Proxy-Authorization", auth)
	}
	writeErr := make(chan error, 1)
	go func() {
		_, err := pw.Write(early)
		writeErr <- err
	}()
	resp, err := tr.RoundTrip(req)
	if err != nil {
		_ = pw.Close()
		return nil, nil, err
	}
	if resp.StatusCode == stdhttp.StatusOK {
		if err := <-writeErr; err != nil {
			return nil, nil, err
		}
	}
	return resp, pw, nil
}

func TestH2CMultiplexesConnectTunnelsOnOneConnection(t *testing.T) {
	target := startEchoTarget(t)
	proxy := startProxy(t, enabledH2C(), config.AuthMode{Username: "u", Password: "p"})
	cc := newH2CClientConn(t, proxy)

	const tunnels = 32
	var wg sync.WaitGroup
	errs := make(chan error, tunnels)
	for i := range tunnels {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Every stream carries its own credentials, so one connection can
			// serve many accounts (user-session-<id> extensions).
			auth := basicAuth(fmt.Sprintf("u-session-%d", i), "p")
			msg := []byte(fmt.Sprintf("hello from tunnel %d", i))
			resp, pw, err := openH2CTunnel(cc, proxy, target, auth, msg)
			if err != nil {
				errs <- err
				return
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != stdhttp.StatusOK {
				errs <- fmt.Errorf("tunnel %d: status %s", i, resp.Status)
				return
			}
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(resp.Body, got); err != nil {
				errs <- fmt.Errorf("tunnel %d: %w", i, err)
				return
			}
			if !bytes.Equal(got, msg) {
				errs <- fmt.Errorf("tunnel %d echoed %q", i, got)
				return
			}
			// Ending the request stream half-closes the target; the echo
			// server then closes and the response stream must end.
			_ = pw.Close()
			if rest, err := io.ReadAll(resp.Body); err != nil || len(rest) != 0 {
				errs <- fmt.Errorf("tunnel %d: after close got %q, %v", i, rest, err)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if err := cc.Err(); err != nil {
		t.Fatalf("multiplexed connection failed: %v", err)
	}
	if n := cc.InFlight(); n != 0 {
		t.Fatalf("client connection still has %d streams in flight", n)
	}
}

func TestH2CTunnelCarriesLargeTransfersBothWays(t *testing.T) {
	target := startEchoTarget(t)
	proxy := startProxy(t, enabledH2C(), config.AuthMode{})
	tr := newH2CClientConn(t, proxy)

	payload := make([]byte, 8<<20)
	_, _ = rand.Read(payload)
	resp, pw, err := openH2CTunnel(tr, proxy, target, "", payload[:1])
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	go func() {
		_, _ = pw.Write(payload[1:])
		_ = pw.Close()
	}()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echoed %d bytes, want %d identical bytes", len(got), len(payload))
	}
}

func TestH2CTargetCloseEndsStreamPromptly(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 5)
		_, _ = io.ReadFull(conn, buf)
		_, _ = conn.Write([]byte("bye"))
		_ = conn.Close()
	}()
	proxy := startProxy(t, enabledH2C(), config.AuthMode{})
	tr := newH2CClientConn(t, proxy)

	resp, pw, err := openH2CTunnel(tr, proxy, ln.Addr().String(), "", []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pw.Close() }()
	done := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(resp.Body)
		done <- b
	}()
	select {
	case b := <-done:
		if string(b) != "bye" {
			t.Fatalf("got %q, want %q", b, "bye")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("response stream did not end after the target closed")
	}
}

func TestH2CRequiresProxyAuthorizationPerStream(t *testing.T) {
	target := startEchoTarget(t)
	proxy := startProxy(t, enabledH2C(), config.AuthMode{Username: "u", Password: "p"})
	tr := newH2CClientConn(t, proxy)

	for _, auth := range []string{"", basicAuth("u", "wrong")} {
		resp, _, err := openH2CTunnel(tr, proxy, target, auth, nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != stdhttp.StatusProxyAuthRequired && resp.StatusCode != stdhttp.StatusForbidden {
			t.Fatalf("auth %q: status %s, want 407 or 403", auth, resp.Status)
		}
		if auth == "" && resp.Header.Get("Proxy-Authenticate") == "" {
			t.Fatal("407 without Proxy-Authenticate")
		}
	}
}

// TestH2CEarlyDataAndFlowControlWindows drives the protocol by hand: preface,
// SETTINGS, HEADERS, and the first DATA frame go out in a single write before
// anything is read. outway must advertise the configured receive windows,
// answer 200, and forward the early DATA to the target.
func TestH2CEarlyDataAndFlowControlWindows(t *testing.T) {
	target := startEchoTarget(t)
	cfg := enabledH2C()
	cfg.ConnWindow = 8 << 20
	cfg.StreamWindow = 2 << 20
	proxy := startProxy(t, cfg, config.AuthMode{})

	conn, err := net.Dial("tcp4", proxy)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	var out bytes.Buffer
	out.WriteString(http2.ClientPreface)
	fr := http2.NewFramer(&out, nil)
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	_ = enc.WriteField(hpack.HeaderField{Name: ":method", Value: "CONNECT"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":authority", Value: target})
	if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: hb.Bytes(), EndHeaders: true}); err != nil {
		t.Fatal(err)
	}
	early := []byte("\x16\x03\x01 early ClientHello bytes")
	if err := fr.WriteData(1, false, early); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(out.Bytes()); err != nil {
		t.Fatal(err)
	}

	rd := http2.NewFramer(io.Discard, conn)
	rd.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	var streamWindow, connIncrement uint32
	var status string
	var echoed []byte
	for len(echoed) < len(early) {
		f, err := rd.ReadFrame()
		if err != nil {
			t.Fatalf("read frame: %v (status=%q echoed=%q)", err, status, echoed)
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if v, ok := f.Value(http2.SettingInitialWindowSize); ok {
				streamWindow = v
			}
		case *http2.WindowUpdateFrame:
			if f.StreamID == 0 && connIncrement == 0 {
				connIncrement = f.Increment
			}
		case *http2.MetaHeadersFrame:
			status = f.PseudoValue("status")
		case *http2.DataFrame:
			if f.StreamID == 1 {
				echoed = append(echoed, f.Data()...)
			}
		}
	}
	if status != "200" {
		t.Fatalf("status %q, want 200", status)
	}
	if !bytes.Equal(echoed, early) {
		t.Fatalf("echoed %q, want %q", echoed, early)
	}
	if streamWindow != uint32(cfg.StreamWindow) {
		t.Fatalf("advertised stream window %d, want %d", streamWindow, cfg.StreamWindow)
	}
	if want := uint32(cfg.ConnWindow) - 65535; connIncrement != want {
		t.Fatalf("connection window update %d, want %d", connIncrement, want)
	}
}

func TestH2CDisabledByDefault(t *testing.T) {
	proxy := startProxy(t, config.DefaultH2CConfig(), config.AuthMode{})
	conn, err := net.Dial("tcp4", proxy)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	reply, _ := io.ReadAll(bufio.NewReader(conn))
	if len(reply) > 0 && !strings.HasPrefix(string(reply), "HTTP/1.") {
		t.Fatalf("disabled h2c answered with non-HTTP/1 bytes %q", reply[:min(len(reply), 16)])
	}
}

// TestHTTP1OptimisticConnectPreservesEarlyBytes pins the ordering guarantee
// clients rely on when they send tunnel bytes right behind the CONNECT
// headers without waiting for 200: bytes that arrive in the same segment
// (buffered by the request parser) and bytes that arrive later must both
// reach the target exactly once and in order.
func TestHTTP1OptimisticConnectPreservesEarlyBytes(t *testing.T) {
	target := startEchoTarget(t)
	proxy := startProxy(t, config.DefaultH2CConfig(), config.AuthMode{})
	for _, tc := range []struct {
		name  string
		split bool
	}{{"same segment", false}, {"later segments", true}} {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := net.Dial("tcp4", proxy)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			_ = conn.(*net.TCPConn).SetNoDelay(true)

			payload := make([]byte, 256<<10)
			_, _ = rand.Read(payload)
			head := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
			go func() {
				if !tc.split {
					_, _ = conn.Write(append([]byte(head), payload...))
					return
				}
				_, _ = conn.Write(append([]byte(head), payload[:100]...))
				for off := 100; off < len(payload); off += 7919 {
					time.Sleep(time.Millisecond)
					_, _ = conn.Write(payload[off:min(off+7919, len(payload))])
				}
			}()
			br := bufio.NewReader(conn)
			resp, err := stdhttp.ReadResponse(br, &stdhttp.Request{Method: stdhttp.MethodConnect})
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != stdhttp.StatusOK {
				t.Fatalf("status %s", resp.Status)
			}
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(br, got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("echoed bytes differ from what was sent behind CONNECT")
			}
		})
	}
}
