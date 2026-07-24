package http

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xiaozhou26/outway/internal/connect"
	"github.com/xiaozhou26/outway/internal/ext"
	"github.com/xiaozhou26/outway/internal/serverbase"
)

func TestRemoveHopHeadersRemovesConnectionTokens(t *testing.T) {
	header := stdhttp.Header{
		"Connection":       []string{"X-Internal, Keep-Alive"},
		"X-Internal":       []string{"secret"},
		"Keep-Alive":       []string{"timeout=5"},
		"Proxy-Connection": []string{"keep-alive"},
		"X-End-To-End":     []string{"preserve"},
	}

	removeHopHeaders(header)

	for _, key := range []string{"Connection", "X-Internal", "Keep-Alive", "Proxy-Connection"} {
		if header.Get(key) != "" {
			t.Errorf("expected %s to be removed", key)
		}
	}
	if got := header.Get("X-End-To-End"); got != "preserve" {
		t.Fatalf("end-to-end header changed: %q", got)
	}
}

func TestHTTPSConnectConcurrentTunnelsStress(t *testing.T) {
	countString := os.Getenv("OUTWAY_STRESS_HTTPS_CONNECTIONS")
	if countString == "" {
		t.Skip("set OUTWAY_STRESS_HTTPS_CONNECTIONS to run the HTTPS concurrency stress test")
	}
	count, err := strconv.Atoi(countString)
	if err != nil || count < 1 {
		t.Fatalf("invalid OUTWAY_STRESS_HTTPS_CONNECTIONS value %q", countString)
	}

	echo, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()

	proxy, err := NewServer(serverbase.Context{
		Bind:           netip.MustParseAddrPort("127.0.0.1:0"),
		Concurrent:     uint32(count + 128),
		ConnectTimeout: 10,
		Connector:      connect.New(nil, nil, nil, 10, nil, nil, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := proxy.WithHTTPS("", ""); err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	go func() { _ = proxy.Start() }()

	exerciseHTTPConnectLoad(
		t,
		count,
		httpStressRounds(t),
		func() (net.Conn, error) {
			return openHTTPSConnectTunnel(proxy.listener.Addr().String(), echo.Addr().String())
		},
	)
}

func exerciseHTTPConnectLoad(t *testing.T, count, rounds int, open func() (net.Conn, error)) {
	t.Helper()
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
				conn, err := open()
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
		for _, conn := range connections {
			if conn != nil {
				conn.Close()
			}
		}
		return
	}

	payload := []byte("outway-https-stress")
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
	for _, conn := range connections {
		_ = conn.Close()
	}
}

func openHTTPSConnectTunnel(proxyAddress, targetAddress string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp4", proxyAddress, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return nil, err
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddress, targetAddress); err != nil {
		conn.Close()
		return nil, err
	}
	request := &stdhttp.Request{Method: stdhttp.MethodConnect}
	response, err := stdhttp.ReadResponse(bufio.NewReader(conn), request)
	if err != nil {
		conn.Close()
		return nil, err
	}
	response.Body.Close()
	if response.StatusCode != stdhttp.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("CONNECT returned %s", response.Status)
	}
	return conn, nil
}

func TestHTTPConnectConcurrentTunnelsStress(t *testing.T) {
	countString := os.Getenv("OUTWAY_STRESS_CONNECTIONS")
	if countString == "" {
		t.Skip("set OUTWAY_STRESS_CONNECTIONS to run the high-concurrency stress test")
	}
	count, err := strconv.Atoi(countString)
	if err != nil || count < 1 {
		t.Fatalf("invalid OUTWAY_STRESS_CONNECTIONS value %q", countString)
	}
	rounds := httpStressRounds(t)

	echo, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()

	proxy, err := NewServer(serverbase.Context{
		Bind:           netip.MustParseAddrPort("127.0.0.1:0"),
		Concurrent:     uint32(count + 128),
		ConnectTimeout: 10,
		Connector:      connect.New(nil, nil, nil, 10, nil, nil, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
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
				conn, err := openHTTPConnectTunnel(proxy.listener.Addr().String(), echo.Addr().String())
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
		for _, conn := range connections {
			if conn != nil {
				conn.Close()
			}
		}
		return
	}

	payload := []byte("outway-http-stress")
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
	for _, conn := range connections {
		_ = conn.Close()
	}
}

func httpStressRounds(t *testing.T) int {
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

func openHTTPConnectTunnel(proxyAddress, targetAddress string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp4", proxyAddress, 5*time.Second)
	if err != nil {
		return nil, err
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddress, targetAddress); err != nil {
		conn.Close()
		return nil, err
	}
	request := &stdhttp.Request{Method: stdhttp.MethodConnect}
	response, err := stdhttp.ReadResponse(bufio.NewReader(conn), request)
	if err != nil {
		conn.Close()
		return nil, err
	}
	response.Body.Close()
	if response.StatusCode != stdhttp.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("CONNECT returned %s", response.Status)
	}
	return conn, nil
}

func TestForwardRequestReusesOutboundConnection(t *testing.T) {
	var connections atomic.Int32
	origin := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	origin.Config.ConnState = func(_ net.Conn, state stdhttp.ConnState) {
		if state == stdhttp.StateNew {
			connections.Add(1)
		}
	}
	origin.Start()
	defer origin.Close()

	handler := NewHandler(serverbase.Context{
		ConnectTimeout: 1,
		Connector:      connect.New(nil, nil, nil, 1, nil, nil, 0),
	})
	defer handler.CloseIdleConnections()

	for range 2 {
		req, err := stdhttp.NewRequest(stdhttp.MethodGet, origin.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		writer := bufio.NewWriter(io.Discard)
		if _, err := handler.forwardRequest(context.Background(), req, ext.None, writer); err != nil {
			t.Fatal(err)
		}
	}

	if got := connections.Load(); got != 1 {
		t.Fatalf("origin accepted %d connections, want 1", got)
	}
}

func TestServerCloseStopsAcceptLoop(t *testing.T) {
	ctx := serverbase.Context{
		Bind:           netip.MustParseAddrPort("127.0.0.1:0"),
		Concurrent:     1,
		ConnectTimeout: 1,
		Connector:      connect.New(nil, nil, nil, 1, nil, nil, 0),
	}
	srv, err := NewServer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Start() }()

	client, err := net.Dial("tcp", srv.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve loop returned an error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("serve loop did not stop after Close")
	}
}

func TestTLSConfigOnlyAdvertisesHTTP11(t *testing.T) {
	cert, key, err := generateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := NewTLSConfigFromPEM(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	protos := cfg.Config().NextProtos
	if len(protos) != 1 || protos[0] != "http/1.1" {
		t.Fatalf("unexpected ALPN protocols: %v", protos)
	}
}

// BenchmarkHTTPConnectSetupParallel measures the full per-connection CONNECT
// setup cost — TCP accept, request parse, auth, outbound dial, 200 response,
// and teardown.
func BenchmarkHTTPConnectSetupParallel(b *testing.B) {
	echo, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()

	proxy, err := NewServer(serverbase.Context{
		Bind:           netip.MustParseAddrPort("127.0.0.1:0"),
		Concurrent:     10000,
		ConnectTimeout: 5,
		Connector:      connect.New(nil, nil, nil, 5, nil, nil, 0),
	})
	if err != nil {
		b.Fatal(err)
	}
	defer proxy.Close()
	go func() { _ = proxy.Start() }()

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			conn, err := openHTTPConnectTunnel(proxy.listener.Addr().String(), echo.Addr().String())
			if err != nil {
				b.Error(err)
				return
			}
			_ = conn.Close()
		}
	})
}

// TestConnectEstablishedResponseIsValid200 ensures the prerendered CONNECT
// success bytes stay a parseable 200 response with no body.
func TestConnectEstablishedResponseIsValid200(t *testing.T) {
	reader := bufio.NewReader(bytes.NewReader(connectEstablishedResponse))
	response, err := stdhttp.ReadResponse(reader, &stdhttp.Request{Method: stdhttp.MethodConnect})
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != stdhttp.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(body) != 0 {
		t.Fatalf("unexpected body %q", body)
	}
	if reader.Buffered() != 0 {
		t.Fatalf("%d trailing bytes after response", reader.Buffered())
	}
}
