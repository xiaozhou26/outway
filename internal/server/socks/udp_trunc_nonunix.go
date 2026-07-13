//go:build !unix && !windows

package socks

// Windows does not expose MSG_TRUNC through x/sys. With the default 65535-byte
// buffer no valid UDP payload can be truncated; equality conservatively marks
// a user-configured smaller full buffer as potentially truncated.
func udpMessageTruncated(flags int) bool { return false }
func udpReadErrorTruncated(error) bool   { return false }
