//go:build unix && !linux

package connect

import "syscall"

// setReuseAddr enables SO_REUSEADDR on the socket.
func setReuseAddr(fd uintptr) error {
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
}

// setTCPUserTimeout is a no-op on non-Linux platforms.
func setTCPUserTimeout(fd, ms int) error { return nil }

// bindToDevice is a no-op on non-Linux platforms.
func bindToDevice(fd int, iface string) error { return nil }
