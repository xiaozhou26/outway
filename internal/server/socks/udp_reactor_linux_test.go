//go:build linux

package socks

import (
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func rawUDPFd(t *testing.T, conn *net.UDPConn) int {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var fd int
	if err := raw.Control(func(f uintptr) { fd = int(f) }); err != nil {
		t.Fatal(err)
	}
	return fd
}

// TestUDPReactorDeliversReadiness registers a socket, sends to it, and confirms
// the reactor invokes the handler which drains the datagrams via raw recvfrom —
// i.e. the socket is serviced without a dedicated blocking read goroutine.
func TestUDPReactorDeliversReadiness(t *testing.T) {
	reactor, err := newUDPReactor(2)
	if err != nil {
		t.Fatal(err)
	}
	defer reactor.close()

	sock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()
	fd := rawUDPFd(t, sock)

	received := make(chan int, 64)
	var handler func()
	handler = func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := unix.Recvfrom(fd, buf, unix.MSG_DONTWAIT)
			if err != nil {
				break // EAGAIN: drained
			}
			received <- n
		}
		_ = reactor.rearm(fd)
	}
	if err := reactor.register(fd, handler); err != nil {
		t.Fatal(err)
	}

	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	target := sock.LocalAddr().(*net.UDPAddr)

	const rounds = 20
	for i := range rounds {
		if _, err := sender.WriteToUDP([]byte("datagram"), target); err != nil {
			t.Fatal(err)
		}
		select {
		case n := <-received:
			if n != len("datagram") {
				t.Fatalf("round %d: got %d bytes, want %d", i, n, len("datagram"))
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("round %d: reactor did not deliver readiness", i)
		}
	}
	reactor.deregister(fd)
}

// TestUDPReactorSharesGoroutines confirms the reactor's goroutine count is fixed
// by the worker pool, not the number of registered sockets — the whole point of
// the reactor.
func TestUDPReactorSharesGoroutines(t *testing.T) {
	const workers = 3
	runtime.GC()
	before := runtime.NumGoroutine()
	reactor, err := newUDPReactor(workers)
	if err != nil {
		t.Fatal(err)
	}
	defer reactor.close()

	const sockets = 200
	conns := make([]*net.UDPConn, 0, sockets)
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	var serviced atomic.Int64
	for range sockets {
		sock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, sock)
		fd := rawUDPFd(t, sock)
		var handler func()
		handler = func() {
			buf := make([]byte, 2048)
			for {
				if _, _, err := unix.Recvfrom(fd, buf, unix.MSG_DONTWAIT); err != nil {
					break
				}
				serviced.Add(1)
			}
			_ = reactor.rearm(fd)
		}
		if err := reactor.register(fd, handler); err != nil {
			t.Fatal(err)
		}
	}

	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	added := runtime.NumGoroutine() - before
	// 200 sockets must not have added ~200 goroutines; only the worker pool.
	if added > workers+2 {
		t.Fatalf("reactor added %d goroutines for %d sockets, want ~%d", added, sockets, workers)
	}
	var wg sync.WaitGroup
	for _, sock := range conns {
		wg.Add(1)
		go func(target *net.UDPAddr) {
			defer wg.Done()
			s, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			defer s.Close()
			_, _ = s.WriteToUDP([]byte("x"), target)
		}(sock.LocalAddr().(*net.UDPAddr))
	}
	wg.Wait()
	deadline := time.Now().Add(3 * time.Second)
	for serviced.Load() < sockets && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if serviced.Load() < sockets {
		t.Fatalf("reactor serviced %d of %d sockets", serviced.Load(), sockets)
	}
	t.Logf("%d sockets serviced by a %d-worker reactor; goroutines added=%d", sockets, workers, added)
}
