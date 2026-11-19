//go:build linux

package connect

import (
	"context"
	"net"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/xiaozhou26/outway/internal/ext"
)

// reno is built into every Linux kernel and always allowed, so it exercises
// TCP_CONGESTION without needing root or a module.
func TestOutboundTCPUsesConfiguredCongestion(t *testing.T) {
	if err := ProbeCongestion("reno"); err != nil {
		t.Fatalf("probe reno: %v", err)
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		if c, err := ln.Accept(); err == nil {
			_ = c.Close()
		}
	}()

	for _, want := range []string{"reno", ""} {
		connector := New(nil, nil, nil, 5, nil, nil, 0)
		connector.Congestion = want
		port := uint16(ln.Addr().(*net.TCPAddr).Port)
		conn, err := connector.TCP(ext.None).Connect(context.Background(), FromHost("127.0.0.1", port))
		if err != nil {
			t.Fatal(err)
		}
		got := congestionOf(t, conn)
		_ = conn.Close()
		if want == "" {
			def, _ := unix.GetsockoptString(mustSocket(t), unix.IPPROTO_TCP, unix.TCP_CONGESTION)
			want = def
		}
		if got != want {
			t.Fatalf("outbound congestion control = %q, want %q", got, want)
		}
		go func() {
			if c, err := ln.Accept(); err == nil {
				_ = c.Close()
			}
		}()
	}
}

func TestProbeCongestionRejectsUnknownAlgorithm(t *testing.T) {
	err := ProbeCongestion("nosuchcc")
	if err == nil || !strings.Contains(err.Error(), "nosuchcc") {
		t.Fatalf("ProbeCongestion(nosuchcc) = %v, want an error naming it", err)
	}
}

func congestionOf(t *testing.T, conn *net.TCPConn) string {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var name string
	var serr error
	if err := raw.Control(func(fd uintptr) {
		name, serr = unix.GetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION)
	}); err != nil {
		t.Fatal(err)
	}
	if serr != nil {
		t.Fatal(serr)
	}
	return name
}

func mustSocket(t *testing.T) int {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}
