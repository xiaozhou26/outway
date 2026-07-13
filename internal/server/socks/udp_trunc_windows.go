//go:build windows

package socks

import (
	"errors"

	"golang.org/x/sys/windows"
)

func udpMessageTruncated(flags int) bool { return false }

func udpReadErrorTruncated(err error) bool {
	return errors.Is(err, windows.WSAEMSGSIZE)
}
