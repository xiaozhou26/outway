//go:build !linux

package serverbase

import "syscall"

const fastOpenSupported = false

func setFastOpen(syscall.RawConn, int) error { return nil }
