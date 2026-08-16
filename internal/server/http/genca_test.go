package http

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
)

func TestSelfSignedCertificatePersistsInStateDirectory(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "outway-state")
	t.Setenv("STATE_DIRECTORY", stateDir)

	cert, key, err := GetSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	if len(cert) == 0 || len(key) == 0 {
		t.Fatal("generated certificate or key is empty")
	}

	for _, name := range []string{"cert.pem", "key.pem"} {
		if _, err := os.Stat(filepath.Join(stateDir, name)); err != nil {
			t.Fatalf("state file %s: %v", name, err)
		}
	}

	cachedCert, cachedKey, err := GetSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	if string(cachedCert) != string(cert) || string(cachedKey) != string(key) {
		t.Fatal("cached certificate pair differs from the persisted pair")
	}
}

func TestSelfSignedCertificateRepairsMismatchedPair(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "outway-state")
	t.Setenv("STATE_DIRECTORY", stateDir)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}

	certA, _, err := generateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	_, keyB, err := generateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "cert.pem"), certA, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "key.pem"), keyB, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := tls.X509KeyPair(certA, keyB); err == nil {
		t.Fatal("test fixture unexpectedly contains a matching certificate pair")
	}

	cert, key, err := GetSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.X509KeyPair(cert, key); err != nil {
		t.Fatalf("repaired certificate pair is invalid: %v", err)
	}
	persistedCert, err := os.ReadFile(filepath.Join(stateDir, "cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	persistedKey, err := os.ReadFile(filepath.Join(stateDir, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.X509KeyPair(persistedCert, persistedKey); err != nil {
		t.Fatalf("persisted repaired certificate pair is invalid: %v", err)
	}
}
