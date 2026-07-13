// Package daemon implements Unix daemon management for outway: start, stop,
// restart, status (ps), and log commands. It mirrors the Rust daemon module.
package daemon

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	binName           = "outway"
	defaultPIDPath    = "/var/run/outway.pid"
	defaultStdoutPath = "/var/run/outway.out"
	defaultStderrPath = "/var/run/outway.err"
)

// Daemon manages the outway daemon process via pid/stdout/stderr files.
type Daemon struct {
	pidFile    string
	stdoutFile string
	stderrFile string
}

// Default returns a Daemon with the default file paths.
func Default() *Daemon {
	return &Daemon{
		pidFile:    defaultPIDPath,
		stdoutFile: defaultStdoutPath,
		stderrFile: defaultStderrPath,
	}
}

// Start starts the daemon by re-executing the current binary with the "run"
// subcommand in a detached process.
func (d *Daemon) Start(runArgs []string) error {
	if pid, _ := d.PID(); pid != 0 {
		fmt.Printf("%s is already running with pid: %d\n", binName, pid)
		return nil
	}

	if err := requireRoot(); err != nil {
		return err
	}

	// Create stdout/stderr files.
	stdout, err := os.OpenFile(d.stdoutFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("create stdout file: %w", err)
	}
	defer stdout.Close()

	stderr, err := os.OpenFile(d.stderrFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("create stderr file: %w", err)
	}
	defer stderr.Close()

	pid, err := startDetached(runArgs, stdout, stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(-1)
	}

	if err := os.WriteFile(d.pidFile, []byte(fmt.Sprintf("%d", pid)), 0o755); err != nil {
		return fmt.Errorf("write pid file: %w", err)
	}
	if err := d.waitForStartup(pid); err != nil {
		_ = os.Remove(d.pidFile)
		return err
	}

	fmt.Printf("%s started with pid: %d\n", binName, pid)
	return nil
}

// Stop sends SIGINT to the running daemon (up to 360 times, once per second)
// and removes the pid file.
func (d *Daemon) Stop() error {
	if err := requireRoot(); err != nil {
		return err
	}

	if pid, _ := d.PID(); pid != 0 {
		stopProcess(pid)
	}

	if err := os.Remove(d.pidFile); err != nil && !os.IsNotExist(err) {
		fmt.Printf("failed to remove pid file: %v\n", err)
	}
	return nil
}

// Restart stops the daemon, waits briefly, then starts it again.
func (d *Daemon) Restart(runArgs []string) error {
	if err := d.Stop(); err != nil {
		return err
	}

	spinners := []rune{'|', '/', '-', '\\'}
	for i := 0; i < 30; i++ {
		fmt.Printf("\r%c", spinners[i%4])
		sleep100ms()
	}
	fmt.Printf("\r \r")
	return d.Start(runArgs)
}

// Status prints the daemon process status (PID, CPU%, memory).
func (d *Daemon) Status() error {
	pid, err := d.PID()
	if err != nil {
		return err
	}
	if pid == 0 {
		fmt.Printf("%s is not running\n", binName)
		return nil
	}
	return printProcessStatus(pid)
}

// Log prints the daemon's stdout and stderr log files.
func (d *Daemon) Log() error {
	if err := readAndPrintFile(d.stdoutFile, "STDOUT>"); err != nil {
		return err
	}
	return readAndPrintFile(d.stderrFile, "STDERR>")
}

// readAndPrintFile reads a file line by line and prints its contents with a
// placeholder header.
func readAndPrintFile(path, placeholder string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Size() == 0 {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	start := true
	for _, line := range splitLines(string(data)) {
		if start {
			start = false
			fmt.Println(placeholder)
		}
		fmt.Println(line)
	}
	return nil
}

// splitLines splits a string into lines without a trailing empty string.
func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// pidFilePath returns the pid file path (for testing).
func (d *Daemon) pidFilePath() string { return filepath.Clean(d.pidFile) }
