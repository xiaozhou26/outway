//go:build !unix

package serverbase

import "syscall"

// reusePortSupported reports that SO_REUSEPORT accept sharding is unavailable on
// this platform, so callers fall back to a single listener.
const reusePortSupported = false

func controlReusePort(_, _ string, _ syscall.RawConn) error { return nil }
