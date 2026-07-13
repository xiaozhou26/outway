//go:build linux

package serverbase

import (
	"io"
	"net"
)

func copyStream(dst, src net.Conn) (int64, error) {
	// Preserve net.TCPConn.ReadFrom so Go can use splice(2) for TCP-to-TCP
	// transfers without allocating a userspace copy buffer.
	return io.Copy(dst, src)
}
