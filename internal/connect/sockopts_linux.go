//go:build linux

package connect

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

// setReuseAddr enables SO_REUSEADDR on the socket.
func setReuseAddr(fd uintptr) error {
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
}

// setTCPUserTimeout sets the TCP_USER_TIMEOUT socket option (Linux only).
func setTCPUserTimeout(fd, ms int) error {
	const TCP_USER_TIMEOUT = 18 // syscall.TCP_USER_TIMEOUT is not always exported
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, TCP_USER_TIMEOUT, ms)
}

// setCongestion selects the TCP congestion control algorithm for the socket.
func setCongestion(fd int, name string) error {
	return syscall.SetsockoptString(fd, syscall.IPPROTO_TCP, syscall.TCP_CONGESTION, name)
}

// ProbeCongestion reports whether outbound TCP sockets can use the named
// congestion control algorithm, by setting it on a throwaway socket. The
// kernel loads a missing module (tcp_<name>) on demand when it can. An
// algorithm outside net.ipv4.tcp_allowed_congestion_control needs
// CAP_NET_ADMIN.
func ProbeCongestion(name string) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, syscall.IPPROTO_TCP)
	if err != nil {
		return err
	}
	defer func() { _ = syscall.Close(fd) }()
	if err := setCongestion(fd, name); err != nil {
		return congestionError(name, err)
	}
	return nil
}

func congestionError(name string, err error) error {
	available := readSysctl("/proc/sys/net/ipv4/tcp_available_congestion_control")
	allowed := readSysctl("/proc/sys/net/ipv4/tcp_allowed_congestion_control")
	switch err {
	case syscall.ENOENT:
		return fmt.Errorf("TCP congestion control %q is not available (available: %s); load it first, e.g. modprobe tcp_%s", name, available, name)
	case syscall.EPERM:
		return fmt.Errorf("TCP congestion control %q is not in net.ipv4.tcp_allowed_congestion_control (%s); run with CAP_NET_ADMIN or add it there", name, allowed)
	}
	return fmt.Errorf("set TCP congestion control %q: %w", name, err)
}

func readSysctl(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(b))
}

// bindToDevice binds the socket to a specific network interface via
// SO_BINDTODEVICE (Linux only).
func bindToDevice(fd int, iface string) error {
	return syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
}
