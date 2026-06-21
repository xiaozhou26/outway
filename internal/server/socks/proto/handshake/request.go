package handshake

import (
	"io"
	"github.com/xiaozhou26/outway/internal/server/socks/proto"
)

// Request is the SOCKS5 method-selection request.
//
// +-----+----------+----------+
// | VER | NMETHODS | METHODS  |
// +-----+----------+----------+
// |  1  |    1     | 1 to 255 |
// +-----+----------+----------|
type Request struct {
	Methods []Method
}

// EvaluateMethod reports whether the client offered the given method.
func (r Request) EvaluateMethod(m Method) bool {
	for _, offered := range r.Methods {
		if offered == m {
			return true
		}
	}
	return false
}

// ReadRequest reads a method-selection request from r.
func ReadRequest(r io.Reader) (Request, error) {
	ver, err := proto.ReadU8Exported(r)
	if err != nil {
		return Request{}, err
	}
	if err := proto.CheckVersion(ver); err != nil {
		return Request{}, err
	}
	nmethods, err := proto.ReadU8Exported(r)
	if err != nil {
		return Request{}, err
	}
	buf := make([]byte, int(nmethods))
	if err := proto.ReadFullExported(r, buf); err != nil {
		return Request{}, err
	}
	methods := make([]Method, len(buf))
	for i, b := range buf {
		methods[i] = MethodFromByte(b)
	}
	return Request{Methods: methods}, nil
}
