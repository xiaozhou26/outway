// Package proto implements the SOCKS5 wire protocol primitives.
package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Version is the SOCKS protocol version.
const Version5 uint8 = 5

// readFull reads exactly len(buf) bytes, returning io.ErrUnexpectedEOF on short reads.
func readFull(r io.Reader, buf []byte) error {
	_, err := io.ReadFull(r, buf)
	return err
}

// ReadFullExported is the exported form of readFull.
func ReadFullExported(r io.Reader, buf []byte) error { return readFull(r, buf) }

// readU8 reads a single byte.
func readU8(r io.Reader) (uint8, error) {
	var b [1]byte
	if err := readFull(r, b[:]); err != nil {
		return 0, err
	}
	return b[0], nil
}

// ReadU8Exported is the exported form of readU8.
func ReadU8Exported(r io.Reader) (uint8, error) { return readU8(r) }

// readU16 reads a big-endian uint16.
func readU16(r io.Reader) (uint16, error) {
	var b [2]byte
	if err := readFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}

// writeAll writes all bytes.
func writeAll(w io.Writer, b []byte) error {
	_, err := w.Write(b)
	return err
}

// checkVersion validates the SOCKS version byte.
func checkVersion(v uint8) error {
	if v != Version5 {
		return fmt.Errorf("unsupported SOCKS version %#x", v)
	}
	return nil
}

// CheckVersion is the exported form of checkVersion.
func CheckVersion(v uint8) error { return checkVersion(v) }

// errShort signals an unexpected end of stream.
var errShort = errors.New("short read")
