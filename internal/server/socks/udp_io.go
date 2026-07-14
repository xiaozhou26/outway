package socks

import (
	"net"
	"net/netip"
)

type udpReadPacket struct {
	buffer    []byte
	n         int
	addr      netip.AddrPort
	truncated bool
	batchSlot bool
}

type udpWritePacket struct {
	buffer    []byte
	owner     []byte
	addr      netip.AddrPort
	batchSlot bool
}

type udpBatchReader interface {
	Read() ([]udpReadPacket, error)
}

type udpBatchWriter interface {
	Write([]udpWritePacket) (int, error)
}

func udpAddrPort(addr net.Addr) (netip.AddrPort, bool) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}, false
	}
	return udpAddr.AddrPort(), true
}

// newReusableUDPAddr returns a *net.UDPAddr whose IP slice has 16 bytes of
// capacity so setUDPAddr can rewrite it in place for either address family
// without reallocating.
func newReusableUDPAddr() *net.UDPAddr {
	return &net.UDPAddr{IP: make(net.IP, 16)}
}

// udpConnFd returns the raw file descriptor backing a UDP socket, so it can be
// registered with the epoll reactor. ok is false if the descriptor cannot be
// obtained.
func udpConnFd(conn *net.UDPConn) (int, bool) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, false
	}
	var fd int
	if err := raw.Control(func(handle uintptr) { fd = int(handle) }); err != nil {
		return 0, false
	}
	return fd, true
}

// setUDPAddr rewrites dst to match ap in place, reusing dst.IP's backing array.
// It lets the batch writers avoid a *net.UDPAddr (and IP slice) allocation per
// packet that net.UDPAddrFromAddrPort would incur.
func setUDPAddr(dst *net.UDPAddr, ap netip.AddrPort) {
	addr := ap.Addr()
	if addr.Is4() {
		v4 := addr.As4()
		dst.IP = dst.IP[:4]
		copy(dst.IP, v4[:])
	} else {
		v16 := addr.As16()
		dst.IP = dst.IP[:16]
		copy(dst.IP, v16[:])
	}
	dst.Port = int(ap.Port())
	dst.Zone = ""
}
