package proto

import "io"

// Response is a SOCKS5 response.
//
// +-----+-----+-------+------+----------+----------+
// | VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
// +-----+-----+-------+------+----------+----------+
type Response struct {
	Reply   Reply
	Address Address
}

// NewResponse builds a response.
func NewResponse(reply Reply, addr Address) Response {
	return Response{Reply: reply, Address: addr}
}

// MarshalTo writes the response to w.
func (resp Response) MarshalTo(w io.Writer) error {
	b := make([]byte, 0, 3+resp.Address.Len())
	b = append(b, Version5, resp.Reply.Byte(), 0x00)
	if _, err := w.Write(b); err != nil {
		return err
	}
	return resp.Address.MarshalTo(w)
}
