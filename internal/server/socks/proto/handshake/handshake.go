// Package handshake implements the SOCKS5 method-selection handshake.
package handshake

import (
	"io"
	"github.com/xiaozhou26/outway/internal/server/socks/proto"
)

// SubnegotiationVersion is the username/password sub-negotiation version.
const SubnegotiationVersion uint8 = 0x01

// ReadByte reads a single byte from r.
func ReadByte(r io.Reader) (uint8, error) {
	return proto.ReadU8Exported(r)
}

// ReadBytes reads exactly len(buf) bytes from r.
func ReadBytes(r io.Reader, buf []byte) error {
	return proto.ReadFullExported(r, buf)
}
