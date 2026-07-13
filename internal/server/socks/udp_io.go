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
