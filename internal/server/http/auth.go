// Package http implements the HTTP/HTTPS proxy server, including Basic auth,
// self-signed certificate generation, TLS configuration, CONNECT tunneling,
// and HTTP request forwarding.
package http

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/xiaozhou26/outway/internal/ext"
	"github.com/xiaozhou26/outway/internal/serverbase"
)

// Authenticator unifies the available HTTP proxy authentication methods.
type Authenticator struct {
	mode          serverbase.AuthMode
	// expectedToken is the full "Basic <credentials>" header for the plain
	// username:password pair, prerendered so the common no-extension request
	// authenticates with a single constant-time comparison and no base64 work.
	username      string
	password      string
	usernameBytes []byte
	passwordBytes []byte
	expectedToken string
}

// NoAuth builds a no-authentication authenticator.
func NoAuth() Authenticator { return Authenticator{mode: serverbase.AuthNone} }

// PasswordAuth builds a username/password authenticator.
func PasswordAuth(username, password string) Authenticator {
	credentials := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	return Authenticator{
		mode:          serverbase.AuthPassword,
		username:      username,
		password:      password,
		usernameBytes: []byte(username),
		passwordBytes: []byte(password),
		expectedToken: "Basic " + credentials,
	}
}

// Authenticate inspects the request headers and returns the parsed extension
// (if any) or an error indicating the failure kind.
func (a Authenticator) Authenticate(hdr http.Header) (ext.Extension, error) {
	switch a.mode {
	case serverbase.AuthPassword:
		return a.authenticatePassword(hdr)
	default:
		return ext.None, nil
	}
}

// constantTimeStringEq compares two strings without leaking where the first
// difference appears. subtle.ConstantTimeCompare only accepts []byte, and the
// conversions of the compared strings stay stack-allocated (verified by
// benchmark), so the fast path below uses it directly instead.
func constantTimeStringEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (a Authenticator) authenticatePassword(hdr http.Header) (ext.Extension, error) {
	proxyAuth := hdr.Get("Proxy-Authorization")
	if proxyAuth == "" {
		return ext.None, errProxyAuthRequired
	}
	// Fast path: the plain username:password pair matches the prerendered
	// token. This covers requests without a username extension and costs no
	// decoding or allocation.
	if constantTimeStringEq(proxyAuth, a.expectedToken) {
		return ext.TryFrom(a.username, a.username), nil
	}
	const prefix = "Basic "
	if !strings.HasPrefix(proxyAuth, prefix) {
		return ext.None, errProxyAuthRequired
	}
	encoded := proxyAuth[len(prefix):]
	// Decode into a stack buffer; oversized credentials fall back to the heap.
	var stack [256]byte
	decoded := base64.StdEncoding.DecodedLen(len(encoded))
	buffer := stack[:min(decoded, len(stack))]
	if decoded > len(stack) {
		buffer = make([]byte, decoded)
	}
	n, err := base64.StdEncoding.Decode(buffer, []byte(encoded))
	if err != nil {
		return ext.None, errProxyAuthRequired
	}
	credentials := buffer[:n]

	idx := -1
	for i := len(credentials) - 1; i >= 0; i-- {
		if credentials[i] == ':' {
			idx = i
			break
		}
	}
	if idx < 0 {
		return ext.None, errProxyAuthRequired
	}
	authUsername := credentials[:idx]
	authPassword := credentials[idx+1:]

	if bytes.HasPrefix(authUsername, a.usernameBytes) && subtle.ConstantTimeCompare(authPassword, a.passwordBytes) == 1 {
		return ext.TryFrom(a.username, string(authUsername)), nil
	}
	return ext.None, errForbidden
}

// Sentinel authentication errors.
var (
	errProxyAuthRequired = authErr("proxy authentication required")
	errForbidden         = authErr("forbidden")
)

type authErr string

func (e authErr) Error() string { return string(e) }

// IsProxyAuthRequired reports whether the error indicates missing/invalid
// Proxy-Authorization credentials.
func IsProxyAuthRequired(err error) bool { return err == errProxyAuthRequired }

// IsForbidden reports whether the error indicates invalid credentials.
func IsForbidden(err error) bool { return err == errForbidden }
