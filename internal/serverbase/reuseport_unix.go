//go:build unix

package serverbase

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// reusePortSupported reports that SO_REUSEPORT accept sharding is available.
const reusePortSupported = true

// controlReusePort sets SO_REUSEPORT so several listeners can bind the same
// address and the kernel load-balances incoming connections across them.
func controlReusePort(_, _ string, c syscall.RawConn) error {
	var sockErr error
	if err := c.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	}); err != nil {
		return err
	}
	return sockErr
}
