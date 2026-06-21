// Package password implements the SOCKS5 username/password sub-negotiation
// (RFC 1929).
package password

// UsernamePassword holds credentials for SOCKS5 username/password auth.
type UsernamePassword struct {
	Username string
	Password string
}

// New builds a UsernamePassword.
func New(username, password string) UsernamePassword {
	return UsernamePassword{Username: username, Password: password}
}
