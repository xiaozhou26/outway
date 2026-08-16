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

func TestDirectoryUsesXDGStateHome(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("darwin uses Library/Application Support before XDG_STATE_HOME")
	}
	t.Setenv("STATE_DIRECTORY", "")
	t.Setenv("LOCALAPPDATA", "")
	xdg := t.TempDir()
	t.Setenv("XDG_STATE_HOME", xdg)

	got, err := Directory()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(xdg, directoryName)
	if got != want {
		t.Fatalf("Directory() = %q, want %q", got, want)
	}
}

func TestPreparePrivateDirectoryRejectsFilePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state-file")
	if err := os.WriteFile(path, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PreparePrivateDirectory(path); err == nil {
		t.Fatal("expected a file path to be rejected")
	}
}

func TestPreparePrivateDirectoryTightensPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose POSIX directory mode semantics")
	}
	path := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := PreparePrivateDirectory(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("state directory mode = %o, want 700", got)
	}
}
