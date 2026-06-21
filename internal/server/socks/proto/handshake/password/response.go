package password

import (
	"fmt"
	"io"

	"github.com/xiaozhou26/outway/internal/server/socks/proto/handshake"
)

// Status is the username/password sub-negotiation status.
type Status uint8

const (
	StatusSucceeded Status = 0x00
	StatusFailed    Status = 0xff
)

// Response is the SOCKS5 username/password sub-negotiation response.
//
// +-----+--------+
// | VER | STATUS |
// +-----+--------+
type Response struct {
	Status Status
}

// NewResponse builds a password response.
func NewResponse(s Status) Response {
	return Response{Status: s}
}

// MarshalTo writes the response to w.
func (resp Response) MarshalTo(w io.Writer) error {
	_, err := w.Write([]byte{handshake.SubnegotiationVersion, byte(resp.Status)})
	return err
}

// ParseStatus parses a status byte.
func ParseStatus(b uint8) (Status, error) {
	switch b {
	case 0x00:
		return StatusSucceeded, nil
	case 0xff:
		return StatusFailed, nil
	default:
		return 0, fmt.Errorf("invalid sub-negotiation status %#x", b)
	}
}
