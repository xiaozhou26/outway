//go:build linux

package socks

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// gsoMaxSegments bounds one UDP_SEGMENT send. The Linux kernel caps a GSO
// datagram at 64 segments; gsoScratchBytes additionally bounds the coalesced
// buffer so a single send never exceeds one 64 KiB super-datagram.
const (
	gsoMaxSegments  = 64
	gsoScratchBytes = 64 * 1024
)

var gsoScratchPool = sync.Pool{New: func() any {
	buffer := make([]byte, gsoScratchBytes)
	return &buffer
}}

// gsoSupported reports whether the running kernel accepts the UDP_SEGMENT
// socket option. It is probed once and cached.
var gsoSupported = sync.OnceValue(func() bool {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return false
	}
	defer conn.Close()
	raw, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	ok := false
	_ = raw.Control(func(fd uintptr) {
		ok = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT, 0) == nil
	})
	return ok
})

func udpGSOSupported() bool { return gsoSupported() }

// sendUDPGSO transmits a batch of same-destination datagrams as one or more
// UDP_SEGMENT (GSO) sends. All datagrams but the last must be exactly gsoSize
// bytes; the last may be shorter. It returns the number of datagrams handed to
// the kernel. The caller guarantees every packet in the batch targets the same
// address (batch[0].addr).
func sendUDPGSO(conn *net.UDPConn, batch []udpWritePacket, gsoSize int) (int, error) {
	if len(batch) == 0 {
		return 0, nil
	}
	sa, ok := sockaddrFromAddrPort(batch[0].addr)
	if !ok {
		return 0, unix.EAFNOSUPPORT
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}

	// UDP_SEGMENT control message carrying the segment size (uint16).
	var oobArray [64]byte
	oob := oobArray[:unix.CmsgSpace(2)]
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	hdr.Level = unix.IPPROTO_UDP
	hdr.Type = unix.UDP_SEGMENT
	hdr.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(oob[unix.CmsgLen(0):], uint16(gsoSize))

	scratchPtr := gsoScratchPool.Get().(*[]byte)
	scratch := *scratchPtr
	defer gsoScratchPool.Put(scratchPtr)

	sent := 0
	for sent < len(batch) {
		// Pack as many segments as fit into one GSO super-datagram.
		total := 0
		segments := 0
		for sent+segments < len(batch) && segments < gsoMaxSegments {
			payload := batch[sent+segments].buffer
			if total+len(payload) > len(scratch) {
				break
			}
			copy(scratch[total:], payload)
			total += len(payload)
			segments++
		}
		if segments == 0 {
			return sent, unix.EMSGSIZE
		}
		var sendErr error
		controlErr := raw.Write(func(fd uintptr) bool {
			_, sendErr = unix.SendmsgN(int(fd), scratch[:total], oob, sa, 0)
			return sendErr != unix.EAGAIN && sendErr != unix.EWOULDBLOCK
		})
		if controlErr != nil {
			return sent, controlErr
		}
		if sendErr != nil {
			return sent, sendErr
		}
		sent += segments
	}
	return sent, nil
}

// sockaddrFromAddrPort converts a netip.AddrPort to a unix.Sockaddr for
// sendmsg. The address is assumed already unmapped to its native family.
func sockaddrFromAddrPort(ap netip.AddrPort) (unix.Sockaddr, bool) {
	addr := ap.Addr()
	if addr.Is4() {
		return &unix.SockaddrInet4{Port: int(ap.Port()), Addr: addr.As4()}, true
	}
	if addr.Is6() {
		return &unix.SockaddrInet6{Port: int(ap.Port()), Addr: addr.As16()}, true
	}
	return nil, false
}
