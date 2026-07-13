package serverbase

import (
	"context"
	"net"
	"runtime"
	"testing"
	"time"
)

func TestConnectionGateLimitsConcurrency(t *testing.T) {
	gate := NewConnectionGate(1)
	gate.Acquire()

	started := make(chan struct{})
	acquired := make(chan struct{})
	go func() {
		close(started)
		gate.Acquire()
		close(acquired)
	}()
	<-started
	runtime.Gosched()

	select {
	case <-acquired:
		t.Fatal("second acquire succeeded before the first slot was released")
	case <-time.After(20 * time.Millisecond):
	}

	gate.Release()
	select {
	case <-acquired:
		gate.Release()
	case <-time.After(time.Second):
		t.Fatal("second acquire did not proceed after release")
	}
}

func TestConnectionGateAcquireUntilCancellation(t *testing.T) {
	gate := NewConnectionGate(1)
	gate.Acquire()
	done := make(chan struct{})
	result := make(chan bool, 1)
	go func() { result <- gate.AcquireUntil(done) }()
	close(done)
	select {
	case acquired := <-result:
		if acquired {
			t.Fatal("gate acquired a slot after cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("gate acquisition did not unblock on cancellation")
	}
	gate.Release()
}

func TestCopyBidirectionalContextCancellation(t *testing.T) {
	client, proxyClient := net.Pipe()
	proxyRemote, remote := net.Pipe()
	defer client.Close()
	defer remote.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_, _, _ = CopyBidirectionalContext(ctx, proxyClient, proxyRemote, time.Minute)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("bidirectional copy did not stop after cancellation")
	}
}

func TestCopyBidirectionalHalfCloseGrace(t *testing.T) {
	client, proxyClient := tcpConnPair(t)
	proxyRemote, remote := tcpConnPair(t)
	defer client.Close()
	defer proxyClient.Close()
	defer proxyRemote.Close()
	defer remote.Close()

	done := make(chan struct{})
	go func() {
		_, _, _ = CopyBidirectionalContext(context.Background(), proxyClient, proxyRemote, 50*time.Millisecond)
		close(done)
	}()
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("bidirectional copy exceeded half-close grace")
	}
}

func tcpConnPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan *net.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case server := <-accepted:
		return client, server
	case err := <-acceptErr:
		client.Close()
		t.Fatal(err)
	case <-time.After(time.Second):
		client.Close()
		t.Fatal("timed out accepting TCP pair")
	}
	return nil, nil
}

func TestTLSHandshakeGateDoesNotExceedConnectionLimit(t *testing.T) {
	gate := NewTLSHandshakeGate(17)
	if capacity := cap(gate.tokens); capacity != 17 {
		t.Fatalf("TLS gate capacity %d, want 17", capacity)
	}
}

func TestTLSHandshakeGateUnlimitedConnectionsIsNotSerialized(t *testing.T) {
	gate := NewTLSHandshakeGate(0)
	if capacity := cap(gate.tokens); capacity < 64 {
		t.Fatalf("TLS gate capacity %d, want at least 64", capacity)
	}
}
