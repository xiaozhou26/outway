package http

import (
	"crypto/tls"
	"os"
)

// TLSConfig holds the parsed TLS server configuration.
type TLSConfig struct {
	cfg *tls.Config
}

// NewTLSConfigFromPEM builds a TLSConfig from PEM-encoded cert and key bytes.
func NewTLSConfigFromPEM(certPEM, keyPEM []byte) (*TLSConfig, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &TLSConfig{cfg: &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}}, nil
}

// NewTLSConfigFromFiles builds a TLSConfig from cert and key file paths.
func NewTLSConfigFromFiles(certPath, keyPath string) (*TLSConfig, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	return NewTLSConfigFromPEM(certPEM, keyPEM)
}

// NewSelfSignedTLSConfig builds a TLSConfig from a freshly generated (or
// cached) self-signed certificate.
func NewSelfSignedTLSConfig() (*TLSConfig, error) {
	cert, key, err := getSelfSignedCert()
	if err != nil {
		return nil, err
	}
	return NewTLSConfigFromPEM(cert, key)
}

// Config returns a clone of the underlying *tls.Config.
func (t *TLSConfig) Config() *tls.Config { return t.cfg.Clone() }
