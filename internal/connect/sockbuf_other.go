//go:build !linux

package connect

import "net"

// TuneUDPBuffers sets the socket receive and send buffers to the requested
// size in bytes, subject to the operating system's limits. Buffer tuning is
// best-effort; a size of zero keeps the system defaults.
func TuneUDPBuffers(conn *net.UDPConn, bytes int) {
	if conn == nil || bytes <= 0 {
		return
	}
	_ = conn.SetReadBuffer(bytes)
	_ = conn.SetWriteBuffer(bytes)
}
