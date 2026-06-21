package socks

import (
	"errors"
	"io"
	"net"
	"strings"

	"github.com/xiaozhou26/outway/internal/ext"
	"github.com/xiaozhou26/outway/internal/server/socks/proto/handshake"
	"github.com/xiaozhou26/outway/internal/server/socks/proto/handshake/password"
)

// authMode identifies the configured authentication method.
type authMode int

const (
	authNone authMode = iota
	authPassword
)

// AuthAdaptor unifies the available SOCKS5 authentication methods.
type AuthAdaptor struct {
	mode     authMode
	username string
	password string
}

// NoAuthConfig builds a no-authentication adaptor.
func NoAuthConfig() AuthAdaptor { return AuthAdaptor{mode: authNone} }

// PasswordConfig builds a username/password adaptor.
func PasswordConfig(username, password string) AuthAdaptor {
	return AuthAdaptor{mode: authPassword, username: username, password: password}
}

// Method returns the SOCKS5 method offered by this adaptor.
func (a AuthAdaptor) Method() handshake.Method {
	switch a.mode {
	case authPassword:
		return handshake.MethodPassword
	default:
		return handshake.MethodNoAuth
	}
}

// Execute runs the authentication sub-negotiation on the stream and returns the
// parsed extension (if any).
func (a AuthAdaptor) Execute(stream io.ReadWriter) (ext.Extension, error) {
	switch a.mode {
	case authPassword:
		return a.executePassword(stream)
	default:
		return ext.None, nil
	}
}

func (a AuthAdaptor) executePassword(stream io.ReadWriter) (ext.Extension, error) {
	req, err := password.ReadRequest(stream)
	if err != nil {
		return ext.None, err
	}

	equal := strings.HasPrefix(req.UserPass.Username, a.username) &&
		req.UserPass.Password == a.password

	status := password.StatusFailed
	if equal {
		status = password.StatusSucceeded
	}
	if err := password.NewResponse(status).MarshalTo(stream); err != nil {
		return ext.None, err
	}
	if !equal {
		return ext.None, errors.New("username or password is incorrect")
	}

	return ext.TryFrom(a.username, req.UserPass.Username), nil
}

// connAddr returns the peer or local address safely.
func connAddr(c *net.TCPConn, peer bool) string {
	if c == nil {
		return "?"
	}
	if peer {
		if a := c.RemoteAddr(); a != nil {
			return a.String()
		}
	} else {
		if a := c.LocalAddr(); a != nil {
			return a.String()
		}
	}
	return "?"
}
