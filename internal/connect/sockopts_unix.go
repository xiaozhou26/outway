//go:build unix && !linux

package connect

import (
	"errors"
	"syscall"
)

// setReuseAddr enables SO_REUSEADDR on the socket.
func setReuseAddr(fd uintptr) error {
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
}

// setTCPUserTimeout is a no-op on non-Linux platforms.
func setTCPUserTimeout(fd, ms int) error { return nil }

// bindToDevice is a no-op on non-Linux platforms.
func bindToDevice(fd int, iface string) error { return nil }

// setCongestion is a no-op off Linux; ProbeCongestion fails there first.
func setCongestion(fd int, name string) error { return nil }

// ProbeCongestion reports that TCP congestion control selection is Linux only.
func ProbeCongestion(name string) error {
	return errors.New("upstream-congestion is only supported on Linux")
}
