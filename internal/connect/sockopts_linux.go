//go:build linux

package connect

import "syscall"

// setReuseAddr enables SO_REUSEADDR on the socket.
func setReuseAddr(fd uintptr) error {
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
}

// setTCPUserTimeout sets the TCP_USER_TIMEOUT socket option (Linux only).
func setTCPUserTimeout(fd, ms int) error {
	const TCP_USER_TIMEOUT = 18 // syscall.TCP_USER_TIMEOUT is not always exported
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, TCP_USER_TIMEOUT, ms)
}

// bindToDevice binds the socket to a specific network interface via
// SO_BINDTODEVICE (Linux only).
func bindToDevice(fd int, iface string) error {
	return syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
}
