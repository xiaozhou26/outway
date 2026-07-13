//go:build linux

package socks

import (
	"encoding/binary"
	"net"
	"sync"

	"golang.org/x/sys/unix"
)

// groMaxSegments bounds how many datagrams one coalesced UDP_GRO read is split
// into, so a burst of tiny same-size datagrams cannot force an unbounded number
// of buffer allocations. Anything beyond is dropped and counted.
const groMaxSegments = 64

// gsoSupported/groSupported are probed once: the kernel accepts the socket
// option only on new-enough versions (UDP_GRO since Linux 5.0).
var groSupported = sync.OnceValue(func() bool {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return false
	}
	defer conn.Close()
	return enableUDPGRO(conn) == nil
})

func udpGROSupported() bool { return groSupported() }

// enableUDPGRO turns on UDP_GRO so the kernel coalesces same-flow, same-size
// datagrams and reports the segment size in a control message on receive.
func enableUDPGRO(conn *net.UDPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO, 1)
	}); err != nil {
		return err
	}
	return sockErr
}

// parseGROSize returns the UDP_GRO segment size from a received control buffer,
// or zero when the read was not coalesced.
func parseGROSize(oob []byte) int {
	if len(oob) == 0 {
		return 0
	}
	messages, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return 0
	}
	for i := range messages {
		if messages[i].Header.Level != unix.IPPROTO_UDP || messages[i].Header.Type != unix.UDP_GRO {
			continue
		}
		data := messages[i].Data
		switch {
		case len(data) >= 4:
			return int(binary.NativeEndian.Uint32(data))
		case len(data) >= 2:
			return int(binary.NativeEndian.Uint16(data))
		}
	}
	return 0
}
