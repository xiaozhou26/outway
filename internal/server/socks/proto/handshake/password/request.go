package password

import (
	"fmt"
	"io"

	"github.com/xiaozhou26/outway/internal/server/socks/proto/handshake"
)

// Request is the SOCKS5 username/password sub-negotiation request.
//
// +-----+------+----------+------+----------+
// | VER | ULEN |  UNAME   | PLEN |  PASSWD  |
// +-----+------+----------+------+----------+
type Request struct {
	UserPass UsernamePassword
}

// ReadRequest reads a username/password request from r.
func ReadRequest(r io.Reader) (Request, error) {
	ver, err := handshake.ReadByte(r)
	if err != nil {
		return Request{}, err
	}
	if ver != handshake.SubnegotiationVersion {
		return Request{}, fmt.Errorf("unsupported sub-negotiation version %#x", ver)
	}
	ulen, err := handshake.ReadByte(r)
	if err != nil {
		return Request{}, err
	}
	buf := make([]byte, int(ulen)+1)
	if err := handshake.ReadBytes(r, buf); err != nil {
		return Request{}, err
	}
	plen := buf[ulen]
	username := string(buf[:ulen])
	pwd := make([]byte, int(plen))
	if err := handshake.ReadBytes(r, pwd); err != nil {
		return Request{}, err
	}
	return Request{UserPass: New(username, string(pwd))}, nil
}

// MarshalTo writes the request to w.
func (req Request) MarshalTo(w io.Writer) error {
	uname := []byte(req.UserPass.Username)
	passwd := []byte(req.UserPass.Password)
	b := make([]byte, 0, 3+len(uname)+len(passwd))
	b = append(b, handshake.SubnegotiationVersion, byte(len(uname)))
	b = append(b, uname...)
	b = append(b, byte(len(passwd)))
	b = append(b, passwd...)
	_, err := w.Write(b)
	return err
}
