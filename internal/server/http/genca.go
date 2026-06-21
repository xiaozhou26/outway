package http

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// getSelfSignedCert returns the PEM-encoded certificate and private key,
// generating and caching them in the OS temp directory if needed.
func getSelfSignedCert() (cert, key []byte, err error) {
	tempDir := filepath.Join(os.TempDir(), "outway")
	if _, statErr := os.Stat(tempDir); os.IsNotExist(statErr) {
		if mkErr := os.MkdirAll(tempDir, 0o755); mkErr != nil {
			return nil, nil, mkErr
		}
	}

	certPath := filepath.Join(tempDir, "cert.pem")
	keyPath := filepath.Join(tempDir, "key.pem")

	if certData, cerr := os.ReadFile(certPath); cerr == nil {
		if keyData, kerr := os.ReadFile(keyPath); kerr == nil {
			return certData, keyData, nil
		}
	}

	cert, key, err = generateSelfSigned()
	if err != nil {
		return nil, nil, err
	}
	if werr := os.WriteFile(certPath, cert, 0o644); werr != nil {
		return nil, nil, werr
	}
	if werr := os.WriteFile(keyPath, key, 0o600); werr != nil {
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
