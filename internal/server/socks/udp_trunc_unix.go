//go:build unix && !linux

package socks

import (
	"golang.org/x/sys/unix"
)

func udpMessageTruncated(flags int) bool { return flags&unix.MSG_TRUNC != 0 }
func udpReadErrorTruncated(error) bool   { return false }
