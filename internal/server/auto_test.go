package server

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/xiaozhou26/outway/internal/config"
	"github.com/xiaozhou26/outway/internal/connect"
)

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
	defer echo.Close()
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
			defer conn.Close()
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
		conn.Close()
		return nil, err
	}
	request := &http.Request{Method: http.MethodConnect}
	response, err := http.ReadResponse(bufio.NewReader(conn), request)
	if err != nil {
		conn.Close()
		return nil, err
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		conn.Close()
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
