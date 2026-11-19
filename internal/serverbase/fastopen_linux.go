//go:build linux

package serverbase

import (
	"syscall"

	"golang.org/x/sys/unix"
)

const fastOpenSupported = true

// setFastOpen enables server-side TCP Fast Open with the given pending-request
// queue length. The kernel also needs net.ipv4.tcp_fastopen to include the
// server bit (0x2) unless the listener sets TFO itself, which this does.
func setFastOpen(c syscall.RawConn, qlen int) error {
	var sockErr error
	if err := c.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN, qlen)
	}); err != nil {
		return err
	}
	return sockErr
}
