package serverbase

import (
	"context"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAddrPortOfMatchesStringRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		addr net.Addr
	}{
		{"tcp4", &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 80}},
		{"tcp6", &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443}},
		{"tcp4-in-6", &net.TCPAddr{IP: net.ParseIP("::ffff:198.51.100.9"), Port: 8080}},
		{"udp4", &net.UDPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 53}},
		{"udp6", &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 5353}},
	}
	for _, tc := range cases {
		got := AddrPortOf(tc.addr)
		want, err := netip.ParseAddrPort(tc.addr.String())
		if err != nil {
			t.Fatalf("%s: ParseAddrPort(%q): %v", tc.name, tc.addr.String(), err)
		}
		if got != want {
			t.Errorf("%s: AddrPortOf=%v, want (string round-trip)=%v", tc.name, got, want)
		}
	}
	if ap := AddrPortOf(nil); ap.IsValid() {
		t.Errorf("AddrPortOf(nil) = %v, want invalid", ap)
	}
}

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

// recordConn is a net.Conn stub whose Close is observable.
type recordConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *recordConn) Close() error { c.closed.Store(true); return nil }

func TestConnectionSetShutdownClosesTrackedConns(t *testing.T) {
	set := NewConnectionSet()

	conns := make([]*recordConn, 200) // > shard count, so every shard is populated
	for i := range conns {
		conns[i] = &recordConn{}
		if !set.Add(conns[i]) {
			t.Fatalf("Add(%d) returned false before shutdown", i)
		}
	}

	// Removing one connection must not cause CloseAll to close it.
	removed := conns[0]
	set.Remove(removed)

	select {
	case <-set.Done():
		t.Fatal("Done() closed before CloseAll")
	default:
	}

	if err := set.CloseAll(); err != nil {
		t.Fatalf("CloseAll: %v", err)
	}

	select {
	case <-set.Done():
	default:
		t.Fatal("Done() not closed after CloseAll")
	}

	for i, c := range conns {
		want := i != 0 // conns[0] was removed before CloseAll
		if got := c.closed.Load(); got != want {
			t.Fatalf("conn %d closed=%v, want %v", i, got, want)
		}
	}

	// Add after shutdown must be refused; Remove after shutdown must not panic.
	if set.Add(&recordConn{}) {
		t.Fatal("Add succeeded after shutdown")
	}
	set.Remove(&recordConn{})
	set.Remove(removed)
}

func TestConnectionSetConcurrentChurnAndShutdown(t *testing.T) {
	set := NewConnectionSet()
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				c := &recordConn{}
				if set.Add(c) {
					set.Remove(c)
				}
			}
		}()
	}
	time.Sleep(20 * time.Millisecond)
	if err := set.CloseAll(); err != nil {
		t.Fatalf("CloseAll: %v", err)
	}
	// After CloseAll, all Adds must be refused so the churn goroutines wind down.
	close(stop)
	wg.Wait()
}
