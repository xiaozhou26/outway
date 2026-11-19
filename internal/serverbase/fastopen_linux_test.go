//go:build linux

package serverbase

import (
	"context"
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func TestListenTCPShardsEnablesFastOpen(t *testing.T) {
	listeners, err := ListenTCPShards(context.Background(), "tcp4", "127.0.0.1:0", 1, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = CloseListeners(listeners[0], listeners[1:]) }()
	if got := fastOpenQueue(t, listeners[0]); got != 64 {
		t.Fatalf("TCP_FASTOPEN = %d, want 64", got)
	}

	plain, err := ListenTCPShards(context.Background(), "tcp4", "127.0.0.1:0", 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = CloseListeners(plain[0], plain[1:]) }()
	if got := fastOpenQueue(t, plain[0]); got != 0 {
		t.Fatalf("TCP_FASTOPEN = %d on a default listener, want 0", got)
	}
}

func fastOpenQueue(t *testing.T, ln net.Listener) int {
	t.Helper()
	rc, err := ln.(*net.TCPListener).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var sockErr error
	if err := rc.Control(func(fd uintptr) {
		v, sockErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN)
	}); err != nil {
		t.Fatal(err)
	}
	if sockErr != nil {
		t.Fatal(sockErr)
	}
	return v
}
