//go:build !linux

package socks

import (
	"errors"
	"net"
)

// udpGSOSupported reports that UDP_SEGMENT batching is unavailable off Linux.
func udpGSOSupported() bool { return false }

// sendUDPGSO is never called off Linux (guarded by udpGSOSupported); it exists
// so the shared send path compiles on every platform.
func sendUDPGSO(_ *net.UDPConn, _ []udpWritePacket, _ int) (int, error) {
	return 0, errors.New("UDP GSO is only supported on Linux")
}
