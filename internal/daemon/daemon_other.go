//go:build !unix

package daemon

import (
	"errors"
)

// requireRoot is a no-op on non-Unix platforms.
func requireRoot() error { return nil }

// startDetached is not supported on non-Unix platforms.
func startDetached(runArgs []string, stdout, stderr interface{}) (int, error) {
	return 0, errors.New("daemon mode is only supported on Unix platforms")
}

// stopProcess is a no-op on non-Unix platforms.
func stopProcess(pid int) {}

// processAlive always returns false on non-Unix platforms.
func processAlive(pid int) bool { return false }

// sleep100ms sleeps for 100 milliseconds.
func sleep100ms() {}

func (d *Daemon) waitForStartup(pid int) error {
	return errors.New("daemon mode is only supported on Unix platforms")
}

// PID returns 0 on non-Unix platforms.
func (d *Daemon) PID() (int, error) { return 0, nil }

// printProcessStatus is a no-op on non-Unix platforms.
func printProcessStatus(pid int) error { return nil }
