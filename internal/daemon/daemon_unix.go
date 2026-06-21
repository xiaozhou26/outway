//go:build unix

package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// requireRoot checks that the process is running as root.
func requireRoot() error {
	if os.Geteuid() != 0 {
		fmt.Println("You must run this executable with root permissions")
		os.Exit(-1)
	}
	return nil
}

// startDetached re-executes the current binary with the given args in a new
// session (detached from the terminal). stdout and stderr are redirected to
// the provided files. Returns the child PID.
func startDetached(runArgs []string, stdout, stderr *os.File) (int, error) {
	exe, err := os.Executable()
	if err != nil {
		return 0, fmt.Errorf("get executable path: %w", err)
	}

	cmd := exec.Command(exe, runArgs...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Stdin = nil

	// Detach from the terminal: create a new session.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("start daemon: %w", err)
	}

	pid := cmd.Process.Pid

	// Release the process so it doesn't become a zombie when this parent exits.
	if cmd.Process != nil {
		_ = cmd.Process.Release()
	}

	return pid, nil
}

// stopProcess sends SIGINT to the process up to 360 times (once per second)
// until it exits.
func stopProcess(pid int) {
	for i := 0; i < 360; i++ {
		if err := syscall.Kill(pid, syscall.SIGINT); err != nil {
			break
		}
		if !processAlive(pid) {
			break
		}
		time.Sleep(time.Second)
	}
}

// processAlive reports whether a process with the given PID is running.
func processAlive(pid int) bool {
	if err := syscall.Kill(pid, 0); err != nil {
		if err == syscall.ESRCH {
			return false
		}
	}
	return true
}

// sleep100ms sleeps for 100 milliseconds (used by the restart spinner).
func sleep100ms() {
	time.Sleep(100 * time.Millisecond)
}

// PID reads the pid file and returns the PID if the process is alive and
// matches the outway binary name. Returns 0 if not running.
func (d *Daemon) PID() (int, error) {
	data, err := os.ReadFile(d.pidFile)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, err
	}

	if !processAlive(pid) {
		_ = os.Remove(d.pidFile)
		return 0, nil
	}

	// On Linux, verify the process name matches.
	if runtime.GOOS == "linux" {
		name, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err == nil {
			n := strings.TrimSpace(string(name))
			if n != binName && !strings.HasPrefix(n, binName) {
				fmt.Printf("PID %d exists but belongs to different process: %s\n", pid, n)
				_ = os.Remove(d.pidFile)
				return 0, nil
			}
		}
	}

	return pid, nil
}

// printProcessStatus prints the PID, CPU usage, and memory usage for the
// daemon process.
func printProcessStatus(pid int) error {
	if runtime.GOOS == "linux" {
		return printLinuxProcessStatus(pid)
	}

	// Fallback for non-Linux Unix: just print the PID.
	fmt.Printf("%-6s\n", "PID")
	fmt.Printf("%-6d\n", pid)
	return nil
}

// printLinuxProcessStatus reads /proc/[pid]/stat and /proc/[pid]/status to
// print CPU and memory usage.
func printLinuxProcessStatus(pid int) error {
	// Read /proc/[pid]/stat for CPU usage.
	statData, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return fmt.Errorf("read stat for pid %d: %w", pid, err)
	}

	statFields := strings.Fields(string(statData))
	if len(statFields) < 20 {
		return fmt.Errorf("unexpected stat format for pid %d", pid)
	}

	// Fields (0-indexed): utime=13, stime=14, starttime=21 in /proc/[pid]/stat
	// But the comm field (index 1) may contain spaces in parentheses, so we
	// need to handle that. The standard approach: find the last ')' and split
	// after it.
	statStr := string(statData)
	lastParen := strings.LastIndex(statStr, ")")
	if lastParen < 0 {
		return fmt.Errorf("malformed stat for pid %d", pid)
	}
	rest := strings.Fields(statStr[lastParen+1:])
	// rest[0] is state, rest[1] is ppid, etc.
	// utime = rest[11], stime = rest[12], starttime = rest[19] (0-indexed from state)
	if len(rest) < 20 {
		return fmt.Errorf("unexpected stat fields for pid %d", pid)
	}

	utime, _ := strconv.ParseUint(rest[11], 10, 64)
	stime, _ := strconv.ParseUint(rest[12], 10, 64)
	starttime, _ := strconv.ParseUint(rest[19], 10, 64)

	// Read /proc/uptime for total system uptime.
	uptimeData, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return fmt.Errorf("read uptime: %w", err)
	}
	uptimeFields := strings.Fields(string(uptimeData))
	if len(uptimeFields) == 0 {
		return fmt.Errorf("malformed uptime")
	}
	uptimeSecs, _ := strconv.ParseFloat(uptimeFields[0], 64)

	// Read /proc/[pid]/status for memory.
	statusData, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return fmt.Errorf("read status for pid %d: %w", pid, err)
	}

	var memKB uint64
	for _, line := range strings.Split(string(statusData), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				memKB, _ = strconv.ParseUint(fields[1], 10, 64)
			}
			break
		}
	}

	// Read CLK_TCK (usually 100 on Linux).
	clkTck := uint64(100)

	// CPU usage percentage: (utime + stime) / (uptime - starttime/clkTck) * 100
	totalTime := utime + stime
	elapsedTicks := uptimeSecs*float64(clkTck) - float64(starttime)
	cpuUsage := 0.0
	if elapsedTicks > 0 {
		cpuUsage = float64(totalTime) / elapsedTicks * 100.0
	}

	memMB := float64(memKB) / 1024.0

	fmt.Printf("%-6s %-8s  %-8s\n", "PID", "CPU(%)", "MEM(MB)")
	fmt.Printf("%-6d   %-8.1f  %-8.1f\n", pid, cpuUsage, memMB)
	return nil
}
