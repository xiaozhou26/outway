// Package http implements the HTTP/HTTPS proxy server, including Basic auth,
// self-signed certificate generation, TLS configuration, CONNECT tunneling,
// and HTTP request forwarding.
package http

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/xiaozhou26/outway/internal/ext"
)

// AuthMode identifies the configured authentication method.
type authMode int

const (
	authNone authMode = iota
	authPassword
)

// Authenticator unifies the available HTTP proxy authentication methods.
type Authenticator struct {
	mode     authMode
	username string
	password string
}

// NoAuth builds a no-authentication authenticator.
func NoAuth() Authenticator { return Authenticator{mode: authNone} }

// PasswordAuth builds a username/password authenticator.
func PasswordAuth(username, password string) Authenticator {
	return Authenticator{mode: authPassword, username: username, password: password}
}

// Authenticate inspects the request headers and returns the parsed extension
// (if any) or an error indicating the failure kind.
func (a Authenticator) Authenticate(hdr http.Header) (ext.Extension, error) {
	switch a.mode {
	case authPassword:
		return a.authenticatePassword(hdr)
	default:
		return ext.None, nil
	}
}

func (a Authenticator) authenticatePassword(hdr http.Header) (ext.Extension, error) {
	proxyAuth := hdr.Get("Proxy-Authorization")
	if proxyAuth == "" {
		return ext.None, errProxyAuthRequired
	}
	const prefix = "Basic "
	if !strings.HasPrefix(proxyAuth, prefix) {
		return ext.None, errProxyAuthRequired
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(proxyAuth, prefix))
	if err != nil {
		return ext.None, errProxyAuthRequired
	}
	authStr := string(decoded)

	idx := strings.LastIndex(authStr, ":")
	if idx < 0 {
		return ext.None, errProxyAuthRequired
	}
	authUsername := authStr[:idx]
	authPassword := authStr[idx+1:]

	if strings.HasPrefix(authUsername, a.username) && authPassword == a.password {
		return ext.TryFrom(a.username, authUsername), nil
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
