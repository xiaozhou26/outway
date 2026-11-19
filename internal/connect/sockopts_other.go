//go:build !unix && !windows

package connect

import "errors"

// setReuseAddr is a no-op on platforms without a socket-option API.
func setReuseAddr(fd uintptr) error { return nil }

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
