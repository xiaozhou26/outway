package handshake

import (
	"io"
	"github.com/xiaozhou26/outway/internal/server/socks/proto"
)

// Response is the SOCKS5 method-selection response.
//
// +-----+--------+
// | VER | METHOD |
// +-----+--------+
// |  1  |   1    |
// +-----+--------+
type Response struct {
	Method Method
}

// NewResponse builds a method-selection response.
func NewResponse(m Method) Response {
	return Response{Method: m}
}

// MarshalTo writes the response to w.
func (resp Response) MarshalTo(w io.Writer) error {
	_, err := w.Write([]byte{proto.Version5, resp.Method.Byte()})
	return err
}
