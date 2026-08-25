package server

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xiaozhou26/outway/internal/config"
	"github.com/xiaozhou26/outway/internal/connect"
	"github.com/xiaozhou26/outway/internal/serverbase"
)

type autoScriptedAcceptListener struct {
	calls atomic.Int32
}

func (l *autoScriptedAcceptListener) Accept() (net.Conn, error) {
	if l.calls.Add(1) == 1 {
		return nil, errors.New("injected auto accept failure")
	}
	return nil, net.ErrClosed
}

func (*autoScriptedAcceptListener) Close() error   { return nil }
func (*autoScriptedAcceptListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestAutoAcceptLoopLogsUnexpectedAcceptError(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelError})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	server := &AutoDetectServer{
		gate:  serverbase.NewConnectionGate(1),
		conns: serverbase.NewConnectionSet(),
	}
	if err := server.acceptLoop(&autoScriptedAcceptListener{}); err != nil {
		t.Fatalf("acceptLoop returned error: %v", err)
	}
	output := logs.String()
	if !strings.Contains(output, "level=ERROR") || !strings.Contains(output, "injected auto accept failure") {
		t.Fatalf("unexpected accept error was not logged at error level: %q", output)
	}
}

func TestAutoHTTPConnectConcurrentTunnelsStress(t *testing.T) {
	countString := os.Getenv("OUTWAY_STRESS_AUTO_CONNECTIONS")
	if countString == "" {
		t.Skip("set OUTWAY_STRESS_AUTO_CONNECTIONS to run the Auto concurrency stress test")
	}
	count, err := strconv.Atoi(countString)
	if err != nil || count < 1 {
		t.Fatalf("invalid OUTWAY_STRESS_AUTO_CONNECTIONS value %q", countString)
	}
	rounds := autoStressRounds(t)

	echo, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = echo.Close() }()
	go acceptTCPEchoConnections(echo)

	concurrent := config.DefaultBootArgs().Concurrent
	if required := uint32(count + 128); required > concurrent {
		concurrent = required
	}
	proxy, err := NewAutoDetectServer(Context{
		Bind:           netip.MustParseAddrPort("127.0.0.1:0"),
		Concurrent:     concurrent,
		ConnectTimeout: 10,
		Connector:      connect.New(nil, nil, nil, 10, nil, nil, 0),
	}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proxy.Close() }()
	go func() { _ = proxy.Start() }()

	connections := make([]net.Conn, count)
	jobs := make(chan int)
	errorsCh := make(chan error, count)
	workers := 128
	if count < workers {
		workers = count
	}
	var openWG sync.WaitGroup
	for range workers {
		openWG.Add(1)
		go func() {
			defer openWG.Done()
			for index := range jobs {
				conn, err := openAutoHTTPConnectTunnel(proxy.listener.Addr().String(), echo.Addr().String())
				if err != nil {
					errorsCh <- err
					continue
				}
				connections[index] = conn
			}
		}()
	}
	for index := range count {
		jobs <- index
	}
	close(jobs)
	openWG.Wait()
	close(errorsCh)
	for err := range errorsCh {
		t.Errorf("open tunnel: %v", err)
	}
	if t.Failed() {
		closeConnections(connections)
		return
	}

	payload := []byte("outway-auto-stress")
	var roundTripWG sync.WaitGroup
	roundTripErrors := make(chan error, count)
	for _, conn := range connections {
		roundTripWG.Add(1)
		go func() {
			defer roundTripWG.Done()
			response := make([]byte, len(payload))
			for range rounds {
				if _, err := conn.Write(payload); err != nil {
					roundTripErrors <- err
					return
				}
				if _, err := io.ReadFull(conn, response); err != nil {
					roundTripErrors <- err
					return
				}
				if !bytes.Equal(response, payload) {
					roundTripErrors <- fmt.Errorf("unexpected response %q", response)
					return
				}
			}
		}()
	}
	roundTripWG.Wait()
	close(roundTripErrors)
	for err := range roundTripErrors {
		t.Errorf("tunnel round trip: %v", err)
	}
	closeConnections(connections)
}

func autoStressRounds(t *testing.T) int {
	t.Helper()
	rounds := 1
	if value := os.Getenv("OUTWAY_STRESS_ROUNDS"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 {
			t.Fatalf("invalid OUTWAY_STRESS_ROUNDS value %q", value)
		}
		rounds = parsed
	}
	return rounds
}

func acceptTCPEchoConnections(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = conn.Close() }()
			_, _ = io.Copy(conn, conn)
		}()
	}
}

func openAutoHTTPConnectTunnel(proxyAddress, targetAddress string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp4", proxyAddress, 5*time.Second)
	if err != nil {
		return nil, err
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddress, targetAddress); err != nil {
		_ = conn.Close()
		return nil, err
	}
	request := &http.Request{Method: http.MethodConnect}
	response, err := http.ReadResponse(bufio.NewReader(conn), request)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("CONNECT returned %s", response.Status)
	}
	return conn, nil
}

func closeConnections(connections []net.Conn) {
	for _, conn := range connections {
		if conn != nil {
			_ = conn.Close()
		}
	}
}

// newAutoTestServer starts an auto-detect server with no auth on a random
// loopback port.
func newAutoTestServer(t *testing.T) *AutoDetectServer {
	t.Helper()
	proxy, err := NewAutoDetectServer(Context{
		Bind:           netip.MustParseAddrPort("127.0.0.1:0"),
		Concurrent:     16,
		ConnectTimeout: 5,
		Connector:      connect.New(nil, nil, nil, 5, nil, nil, 0),
	}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = proxy.Start() }()
	t.Cleanup(func() { _ = proxy.Close() })
	return proxy
}

// TestAutoDetectDispatchesSOCKS5 pins the 0x05 branch: the SOCKS5 greeting
// survives the peek and the method negotiation reply comes back.
func TestAutoDetectDispatchesSOCKS5(t *testing.T) {
	proxy := newAutoTestServer(t)
	conn, err := net.DialTimeout("tcp4", proxy.listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("SOCKS5 method reply = %x, want 05 00", reply)
	}
}

// TestAutoDetectDispatchesHTTP pins the >= 0x41 branch: an ASCII request line
// reaches the HTTP proxy handler (a target-less CONNECT yields a 400).
func TestAutoDetectDispatchesHTTP(t *testing.T) {
	proxy := newAutoTestServer(t)
	conn, err := net.DialTimeout("tcp4", proxy.listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	request := "CONNECT x HTTP/1.1\r\nHost: x\r\n\r\n"
	if _, err := fmt.Fprint(conn, request); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed CONNECT status = %d, want 400", response.StatusCode)
	}
}

// TestAutoDetectDispatchesHTTPS pins the < 0x41 branch: a TLS ClientHello
// (first byte 0x16) is routed to the TLS path and an HTTP/1.1 request over the
// handshake reaches the proxy handler.
func TestAutoDetectDispatchesHTTPS(t *testing.T) {
	proxy := newAutoTestServer(t)
	raw, err := net.DialTimeout("tcp4", proxy.listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	tlsConn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	defer func() { _ = tlsConn.Close() }()
	_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}

	if _, err := fmt.Fprint(tlsConn, "CONNECT x HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(tlsConn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("TLS-routed malformed CONNECT status = %d, want 400", response.StatusCode)
	}
}

// TestBufferedConnPreservesPeekedBytes guards the dispatch wrapper: every byte
// the bufio.Reader buffered during the peek must come back in order from Read.
func TestBufferedConnPreservesPeekedBytes(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	payload := []byte{0x05, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	go func() {
		_, _ = client.Write(payload)
	}()

	br := bufio.NewReader(server)
	if _, err := br.Peek(1); err != nil {
		t.Fatal(err)
	}
	wrapped := &bufferedConn{Conn: server, br: br}
	got := make([]byte, len(payload))
	_ = wrapped.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(wrapped, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("read = %x, want %x — the peeked byte was lost", got, payload)
	}
}
