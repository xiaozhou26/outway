package proto

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
)

// AddressType is the SOCKS5 address type code.
type AddressType uint8

const (
	AddrIPv4   AddressType = 0x01
	AddrDomain AddressType = 0x03
	AddrIPv6   AddressType = 0x04
)

// Address is a SOCKS5 destination address: either a socket address or a
// domain:port pair.
type Address struct {
	// Socket is non-nil for IPv4/IPv6 socket addresses.
	Socket *netip.AddrPort
	// Domain holds the hostname (when Socket is nil).
	Domain string
	// Port is the destination port (used with Domain).
	Port uint16
}

// SocketAddress builds an Address from a socket address.
func SocketAddress(addr netip.AddrPort) Address {
	a := addr
	return Address{Socket: &a}
}

// DomainAddress builds an Address from a domain and port.
func DomainAddress(domain string, port uint16) Address {
	return Address{Domain: domain, Port: port}
}

// unspecifiedAddrPort backs Unspecified. Address holds a read-only pointer, so
// every reply can share one immutable value instead of allocating its own.
var unspecifiedAddrPort = netip.AddrPortFrom(netip.IPv4Unspecified(), 0)

// Unspecified returns the unspecified IPv4 address (used in replies).
func Unspecified() Address {
	return Address{Socket: &unspecifiedAddrPort}
}

// MaxSerializedLen is the maximum length of a serialized address (1 + 1 + 255 + 2).
const MaxSerializedLen = 1 + 1 + 255 + 2

// Len returns the serialized length of the address.
func (a Address) Len() int {
	if a.Socket != nil {
		if a.Socket.Addr().Is4() {
			return 1 + 4 + 2
		}
		return 1 + 16 + 2
	}
	return 1 + 1 + len(a.Domain) + 2
}

// AppendTo appends the address in SOCKS5 wire format to b.
func (a Address) AppendTo(b []byte) ([]byte, error) {
	if a.Socket != nil {
		ap := *a.Socket
		if ap.Addr().Is4() {
			b = append(b, byte(AddrIPv4))
			v4 := ap.Addr().As4()
			b = append(b, v4[:]...)
			return binary.BigEndian.AppendUint16(b, ap.Port()), nil
		}
		b = append(b, byte(AddrIPv6))
		v6 := ap.Addr().As16()
		b = append(b, v6[:]...)
		return binary.BigEndian.AppendUint16(b, ap.Port()), nil
	}
	if len(a.Domain) > 255 {
		return nil, fmt.Errorf("domain too long: %d", len(a.Domain))
	}
	b = append(b, byte(AddrDomain), byte(len(a.Domain)))
	b = append(b, a.Domain...)
	return binary.BigEndian.AppendUint16(b, a.Port), nil
}

// MarshalTo writes the address to w in SOCKS5 wire format.
func (a Address) MarshalTo(w io.Writer) error {
	b, err := a.AppendTo(make([]byte, 0, a.Len()))
	if err != nil {
		return err
	}
	return writeAll(w, b)
}

// ParseAddress parses a SOCKS5 address from the front of buf, returning the
// address and the number of bytes consumed. It is the allocation-light,
// io.Reader-free counterpart to ReadAddress used on the packet hot path.
func ParseAddress(buf []byte) (Address, int, error) {
	if len(buf) < 1 {
		return Address{}, 0, io.ErrUnexpectedEOF
	}
	switch AddressType(buf[0]) {
	case AddrIPv4:
		if len(buf) < 1+4+2 {
			return Address{}, 0, io.ErrUnexpectedEOF
		}
		addr := netip.AddrFrom4([4]byte{buf[1], buf[2], buf[3], buf[4]})
		ap := netip.AddrPortFrom(addr, binary.BigEndian.Uint16(buf[5:7]))
		return Address{Socket: &ap}, 1 + 4 + 2, nil
	case AddrIPv6:
		if len(buf) < 1+16+2 {
			return Address{}, 0, io.ErrUnexpectedEOF
		}
		var addr16 [16]byte
		copy(addr16[:], buf[1:17])
		ap := netip.AddrPortFrom(netip.AddrFrom16(addr16), binary.BigEndian.Uint16(buf[17:19]))
		return Address{Socket: &ap}, 1 + 16 + 2, nil
	case AddrDomain:
		if len(buf) < 2 {
			return Address{}, 0, io.ErrUnexpectedEOF
		}
		length := int(buf[1])
		if len(buf) < 2+length+2 {
			return Address{}, 0, io.ErrUnexpectedEOF
		}
		domain := string(buf[2 : 2+length])
		port := binary.BigEndian.Uint16(buf[2+length : 2+length+2])
		return Address{Domain: domain, Port: port}, 2 + length + 2, nil
	default:
		return Address{}, 0, fmt.Errorf("unsupported address type %#x", buf[0])
	}
}

// ReadAddress reads a SOCKS5 address from r.
func ReadAddress(r io.Reader) (Address, error) {
	atyp, err := readU8(r)
	if err != nil {
		return Address{}, err
	}
	switch AddressType(atyp) {
	case AddrIPv4:
		var buf [6]byte
		if err := readFull(r, buf[:]); err != nil {
			return Address{}, err
		}
		addr := netip.AddrFrom4([4]byte{buf[0], buf[1], buf[2], buf[3]})
		port := binary.BigEndian.Uint16(buf[4:])
		ap := netip.AddrPortFrom(addr, port)
		return Address{Socket: &ap}, nil
	case AddrDomain:
		ln, err := readU8(r)
		if err != nil {
			return Address{}, err
		}
		buf := make([]byte, int(ln)+2)
		if err := readFull(r, buf); err != nil {
			return Address{}, err
		}
		port := binary.BigEndian.Uint16(buf[ln:])
		return Address{Domain: string(buf[:ln]), Port: port}, nil
	case AddrIPv6:
		var buf [18]byte
		if err := readFull(r, buf[:]); err != nil {
			return Address{}, err
		}
		var addr16 [16]byte
		copy(addr16[:], buf[:16])
		addr := netip.AddrFrom16(addr16)
		port := binary.BigEndian.Uint16(buf[16:])
		ap := netip.AddrPortFrom(addr, port)
		return Address{Socket: &ap}, nil
	default:
		return Address{}, fmt.Errorf("unsupported address type %#x", atyp)
	}
}

// String returns a human-readable representation.
func (a Address) String() string {
	if a.Socket != nil {
		return a.Socket.String()
	}
	return fmt.Sprintf("%s:%d", a.Domain, a.Port)
}
