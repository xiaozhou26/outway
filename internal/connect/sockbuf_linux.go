//go:build linux

package connect

import (
	"net"

	"golang.org/x/sys/unix"
)

// TuneUDPBuffers sets the socket receive and send buffers to the requested
// size in bytes. It first attempts SO_RCVBUFFORCE/SO_SNDBUFFORCE, which
// ignores the rmem_max/wmem_max sysctl ceilings but requires CAP_NET_ADMIN,
// and falls back to the regular (clamped) socket options without it. Buffer
// tuning is best-effort; a size of zero keeps the system defaults.
func TuneUDPBuffers(conn *net.UDPConn, bytes int) {
	if conn == nil || bytes <= 0 {
		return
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return
	}
	var rcvErr, sndErr error
	if err := raw.Control(func(fd uintptr) {
		rcvErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, bytes)
		sndErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, bytes)
	}); err != nil {
		return
	}
	if rcvErr != nil {
		if err := conn.SetReadBuffer(bytes); err == nil {
			logger().Debug("UDP receive buffer set without CAP_NET_ADMIN; size is capped by net.core.rmem_max", "requested", bytes)
		}
	}
	if sndErr != nil {
		if err := conn.SetWriteBuffer(bytes); err == nil {
			logger().Debug("UDP send buffer set without CAP_NET_ADMIN; size is capped by net.core.wmem_max", "requested", bytes)
		}
	}
}
