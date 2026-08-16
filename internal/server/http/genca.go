package http

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/xiaozhou26/outway/internal/state"
)

var selfSignedCertMu sync.Mutex

// GetSelfSignedCert returns the PEM-encoded certificate and private key,
// generating and caching them in the platform state directory if needed.
// Under systemd, STATE_DIRECTORY points at the unit's private StateDirectory.
func GetSelfSignedCert() (cert, key []byte, err error) {
	selfSignedCertMu.Lock()
	defer selfSignedCertMu.Unlock()

	stateDir, err := state.Directory()
	if err != nil {
		return nil, nil, err
	}
	if err := state.PreparePrivateDirectory(stateDir); err != nil {
		return nil, nil, err
	}

	certPath := filepath.Join(stateDir, "cert.pem")
	keyPath := filepath.Join(stateDir, "key.pem")

	if certData, certErr := os.ReadFile(certPath); certErr == nil {
		if keyData, keyErr := os.ReadFile(keyPath); keyErr == nil {
			if _, pairErr := tls.X509KeyPair(certData, keyData); pairErr == nil {
				return certData, keyData, nil
			}
		}
	}

	cert, key, err = generateSelfSigned()
	if err != nil {
		return nil, nil, err
	}
	// Each file replacement is atomic. If the process stops between the two
	// replacements, the validation above detects the mismatched pair and
	// regenerates it on the next call.
	if werr := writeFileAtomic(keyPath, key, 0o600); werr != nil {
		return nil, nil, werr
	}
	if werr := writeFileAtomic(certPath, cert, 0o644); werr != nil {
		return nil, nil, werr
	}
	return cert, key, nil
}

// generateSelfSigned creates a self-signed CA certificate and ECDSA private key
// in PEM format.
func generateSelfSigned() (certPEM, keyPEM []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         "outway",
			Organization:       []string{"outway"},
			OrganizationalUnit: []string{"outway"},
		},
		NotBefore: time.Unix(0, 0),
		NotAfter:  time.Date(4096, time.January, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign |
			x509.KeyUsageKeyEncipherment,
		IsCA:                  true,
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}
