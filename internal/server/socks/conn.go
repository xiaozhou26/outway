package socks

import (
	"io"
	"net"

	"github.com/xiaozhou26/outway/internal/ext"
	"github.com/xiaozhou26/outway/internal/server/socks/proto"
	"github.com/xiaozhou26/outway/internal/server/socks/proto/handshake"
)

// IncomingConnection is a freshly accepted connection that has not yet
// completed the SOCKS5 handshake. Handshake bytes are read through reader (a
// buffered reader over stream) so the multi-field negotiation costs one recv
// per client flight instead of one per field; replies are written straight to
// the raw stream.
type IncomingConnection struct {
	stream net.Conn
	reader io.Reader
	auth   AuthAdaptor
}

// NewIncomingConnection wraps a stream and the buffered reader used to read its
// handshake bytes with an auth adaptor.
func NewIncomingConnection(stream net.Conn, reader io.Reader, auth AuthAdaptor) IncomingConnection {
	return IncomingConnection{stream: stream, reader: reader, auth: auth}
}

// Authenticate performs the SOCKS5 method-selection handshake and the
// configured authentication sub-negotiation. On success it returns the stream
// ready for request reading and the parsed extension.
func (ic IncomingConnection) Authenticate() (net.Conn, ext.Extension, error) {
	req, err := handshake.ReadRequest(ic.reader)
	if err != nil {
		return nil, ext.None, err
	}

	method := ic.auth.Method()
	if req.EvaluateMethod(method) {
		if err := handshake.NewResponse(method).MarshalTo(ic.stream); err != nil {
			return nil, ext.None, err
		}
		extension, err := ic.auth.Execute(readWriter{r: ic.reader, w: ic.stream})
		if err != nil {
			return ic.stream, ext.None, err
		}
		return ic.stream, extension, nil
	}

	// No acceptable methods.
	_ = handshake.NewResponse(handshake.MethodNoAcceptableMethods).MarshalTo(ic.stream)
	return nil, ext.None, errNoAcceptableMethods
}

// readWriter reads from r (the buffered handshake reader) and writes to w (the
// raw stream), so auth sub-negotiation reads stay buffered while replies go
// directly to the connection.
type readWriter struct {
	r io.Reader
	w io.Writer
}

func (rw readWriter) Read(p []byte) (int, error)  { return rw.r.Read(p) }
func (rw readWriter) Write(p []byte) (int, error) { return rw.w.Write(p) }

// writeReply writes a SOCKS5 reply on the stream.
func writeReply(w io.Writer, reply proto.Reply, addr proto.Address) error {
	return proto.NewResponse(reply, addr).MarshalTo(w)
}

var errNoAcceptableMethods = errStr("no available handshake method provided by client")

type errStr string

func (e errStr) Error() string { return string(e) }
