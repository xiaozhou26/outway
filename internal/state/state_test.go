package state

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDirectoryPrefersSystemdStateDirectory(t *testing.T) {
	t.Setenv("STATE_DIRECTORY", filepath.Join(t.TempDir(), "systemd-state"))
	got, err := Directory()
	if err != nil {
		t.Fatal(err)
	}
	if got != os.Getenv("STATE_DIRECTORY") {
		t.Fatalf("Directory() = %q, want %q", got, os.Getenv("STATE_DIRECTORY"))
	}
}

func TestPreparePrivateDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	if err := PreparePrivateDirectory(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		t.Fatalf("state directory mode = %o, want 700", info.Mode().Perm())
	}
}
