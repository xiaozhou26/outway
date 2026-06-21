package proto

import "io"

// Request is a SOCKS5 request.
//
// +-----+-----+-------+------+----------+----------+
// | VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
// +-----+-----+-------+------+----------+----------+
type Request struct {
	Command Command
	Address Address
}

// ReadRequest reads a SOCKS5 request from r.
func ReadRequest(r io.Reader) (Request, error) {
	ver, err := readU8(r)
	if err != nil {
		return Request{}, err
	}
	if err := checkVersion(ver); err != nil {
		return Request{}, err
	}
	var buf [2]byte
	if err := readFull(r, buf[:]); err != nil {
		return Request{}, err
	}
	cmd, err := ParseCommand(buf[0])
	if err != nil {
		return Request{}, err
	}
	// buf[1] is RSV (reserved)
	addr, err := ReadAddress(r)
	if err != nil {
		return Request{}, err
	}
	return Request{Command: cmd, Address: addr}, nil
}

// MarshalTo writes the request to w.
func (req Request) MarshalTo(w io.Writer) error {
	b := make([]byte, 0, 3+req.Address.Len())
	b = append(b, Version5, req.Command.Byte(), 0x00)
	if _, err := w.Write(b); err != nil {
		return err
	}
	return req.Address.MarshalTo(w)
}
