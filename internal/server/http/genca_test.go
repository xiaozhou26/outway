package http

import (
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
