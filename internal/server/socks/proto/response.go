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

// MarshalTo writes the response to w as a single write, so a reply costs one
// syscall instead of one for the header and another for the address.
func (resp Response) MarshalTo(w io.Writer) error {
	b := make([]byte, 0, 3+resp.Address.Len())
	b = append(b, Version5, resp.Reply.Byte(), 0x00)
	b, err := resp.Address.AppendTo(b)
	if err != nil {
		return err
	}
	return writeAll(w, b)
}
