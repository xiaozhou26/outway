// Package state resolves and prepares persistent application state paths.
package state

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

const directoryName = "outway"

// systemStateDirectory is the root-owned Linux state directory used when no
// home or state environment is available, e.g. a bare systemd unit without
// StateDirectory=.
const systemStateDirectory = "/var/lib/outway"

// Swappable for tests.
var (
	goos        = runtime.GOOS
	geteuid     = os.Geteuid
	userHomeDir = os.UserHomeDir
)

// Directory returns systemd's StateDirectory when available, otherwise the
// platform's persistent per-user application state directory. On Linux, root
// without a home directory falls back to /var/lib/outway.
func Directory() (string, error) {
	if directory := os.Getenv("STATE_DIRECTORY"); directory != "" {
		return directory, nil
	}

	if goos == "windows" {
		if base := os.Getenv("LOCALAPPDATA"); base != "" {
			return filepath.Join(base, directoryName), nil
		}
	}
	if goos == "darwin" {
		home, err := userHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home directory: %w", err)
		}
		return filepath.Join(home, "Library", "Application Support", directoryName), nil
	}
	if base := os.Getenv("XDG_STATE_HOME"); base != "" {
		return filepath.Join(base, directoryName), nil
	}
	home, err := userHomeDir()
	if err != nil {
		if goos == "linux" && geteuid() == 0 {
			return systemStateDirectory, nil
		}
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, ".local", "state", directoryName), nil
}

// PreparePrivateDirectory creates a private directory for certificates and
// other sensitive persistent state.
func PreparePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o700); err != nil {
			return err
		}
	}
	return nil
}
