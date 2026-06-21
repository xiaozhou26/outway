package proto

import (
	"encoding/binary"
	"io"
)

// UdpHeader is the SOCKS5 UDP relay header.
//
// +-----+------+------+----------+----------+----------+
// | RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
// +-----+------+------+----------+----------+----------+
type UdpHeader struct {
	Frag    uint8
	Address Address
}

// MaxSerializedLen is the maximum length of a serialized UDP header.
const UdpHeaderMaxLen = 3 + MaxSerializedLen

// Len returns the serialized length of the header.
func (h UdpHeader) Len() int {
	return 3 + h.Address.Len()
}

// MarshalTo writes the UDP header to w.
func (h UdpHeader) MarshalTo(w io.Writer) error {
	b := make([]byte, 0, h.Len())
	b = append(b, 0x00, 0x00, h.Frag)
	if _, err := w.Write(b); err != nil {
		return err
	}
	return h.Address.MarshalTo(w)
}

// ReadUdpHeader reads a SOCKS5 UDP header from r and returns the header and the
// number of header bytes consumed.
func ReadUdpHeader(r io.Reader) (UdpHeader, int, error) {
	var buf [3]byte
	if err := readFull(r, buf[:]); err != nil {
		return UdpHeader{}, 0, err
	}
	addr, err := ReadAddress(r)
	if err != nil {
		return UdpHeader{}, 0, err
	}
	h := UdpHeader{Frag: buf[2], Address: addr}
	return h, h.Len(), nil
}

// BuildUdpPacket assembles a SOCKS5 UDP relay packet (header + payload).
func BuildUdpPacket(frag uint8, from Address, payload []byte) []byte {
	h := UdpHeader{Frag: frag, Address: from}
	buf := make([]byte, 0, h.Len()+len(payload))
	buf = append(buf, 0x00, 0x00, frag)
	// inline address encoding to avoid extra allocations
	addr := from
	if addr.Socket != nil {
		ap := *addr.Socket
		if ap.Addr().Is4() {
			buf = append(buf, byte(AddrIPv4))
			v4 := ap.Addr().As4()
			buf = append(buf, v4[:]...)
		} else {
			buf = append(buf, byte(AddrIPv6))
			v6 := ap.Addr().As16()
			buf = append(buf, v6[:]...)
		}
		var p [2]byte
		binary.BigEndian.PutUint16(p[:], ap.Port())
		buf = append(buf, p[:]...)
	} else {
		buf = append(buf, byte(AddrDomain), byte(len(addr.Domain)))
		buf = append(buf, addr.Domain...)
		var p [2]byte
		binary.BigEndian.PutUint16(p[:], addr.Port)
		buf = append(buf, p[:]...)
	}
	buf = append(buf, payload...)
	return buf
}
