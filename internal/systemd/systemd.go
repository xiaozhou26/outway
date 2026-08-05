//go:build linux

// Package systemd installs and controls the outway system service on Linux.
package systemd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/xiaozhou26/outway/internal/config"
)

const (
	serviceName     = "outway.service"
	defaultUnitPath = "/etc/systemd/system/outway.service"
)

// Manager installs and controls one systemd unit.
type Manager struct {
	unitPath    string
	executable  func() (string, error)
	workingDir  func() (string, error)
	lookPath    func(string) (string, error)
	run         func(string, ...string) error
	euid        func() int
	stderrIsTTY func() bool
	lookupEnv   func(string) (string, bool)
	readFile    func(string) ([]byte, error)
	writeFile   func(string, []byte, os.FileMode) error
}

// Default returns the Linux system service manager.
func Default() *Manager {
	return &Manager{
		unitPath:    defaultUnitPath,
		executable:  os.Executable,
		workingDir:  os.Getwd,
		lookPath:    exec.LookPath,
		run:         runCommand,
		euid:        os.Geteuid,
		stderrIsTTY: stderrIsTerminal,
		lookupEnv:   os.LookupEnv,
		readFile:    os.ReadFile,
		writeFile:   os.WriteFile,
	}
}

// Install writes or updates the unit file and reloads systemd.
func (m *Manager) Install(args config.BootArgs, runArgs []string) error {
	changed, err := m.install(args, runArgs)
	if err != nil {
		return err
	}
	if changed {
		fmt.Printf("systemd unit updated: %s\n", m.unitPath)
	} else {
		fmt.Printf("systemd unit unchanged: %s\n", m.unitPath)
	}
	return nil
}

// Enable installs the unit and enables it at boot without starting it.
func (m *Manager) Enable(args config.BootArgs, runArgs []string) error {
	if _, err := m.install(args, runArgs); err != nil {
		return err
	}
	if err := m.systemctl("enable", serviceName); err != nil {
		return err
	}
	fmt.Printf("%s enabled\n", serviceName)
	return nil
}

// Start installs, enables, and starts the service.
func (m *Manager) Start(args config.BootArgs, runArgs []string) error {
	if _, err := m.install(args, runArgs); err != nil {
		return err
	}
	if err := m.systemctl("enable", serviceName); err != nil {
		return err
	}
	if err := m.systemctl("start", serviceName); err != nil {
		return err
	}
	fmt.Printf("%s started\n", serviceName)
	return nil
}

// Restart updates the unit, enables it, and restarts the service.
func (m *Manager) Restart(args config.BootArgs, runArgs []string) error {
	if _, err := m.install(args, runArgs); err != nil {
		return err
	}
	if err := m.systemctl("enable", serviceName); err != nil {
		return err
	}
	if err := m.systemctl("restart", serviceName); err != nil {
		return err
	}
	fmt.Printf("%s restarted\n", serviceName)
	return nil
}

// Stop stops the service without disabling boot startup.
func (m *Manager) Stop() error {
	if err := m.requireRoot(); err != nil {
		return err
	}
	return m.systemctl("stop", serviceName)
}

// Status shows the service and process state.
func (m *Manager) Status() error {
	return m.systemctl("status", "--no-pager", serviceName)
}

// Logs shows recent journal entries and follows new ones.
func (m *Manager) Logs() error {
	return m.journalctl("-u", serviceName, "-n", "100", "-f", "--no-pager")
}

func (m *Manager) install(args config.BootArgs, runArgs []string) (bool, error) {
	if err := m.requireRoot(); err != nil {
		return false, err
	}
	unit, err := m.unit(args, runArgs)
	if err != nil {
		return false, err
	}
	current, err := m.readFile(m.unitPath)
	if err != nil && !os.IsNotExist(err) {
		return false, fmt.Errorf("read systemd unit: %w", err)
	}
	changed := !bytes.Equal(current, unit)
	if !changed {
		return false, nil
	}
	if err := m.writeFile(m.unitPath, unit, 0o644); err != nil {
		return false, fmt.Errorf("write systemd unit: %w", err)
	}
	if err := m.systemctl("daemon-reload"); err != nil {
		return false, err
	}
	return true, nil
}

func (m *Manager) unit(args config.BootArgs, runArgs []string) ([]byte, error) {
	executable, err := m.executable()
	if err != nil {
		return nil, fmt.Errorf("get executable path: %w", err)
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return nil, fmt.Errorf("make executable path absolute: %w", err)
	}
	workingDir, err := m.workingDir()
	if err != nil {
		return nil, fmt.Errorf("get working directory: %w", err)
	}
	workingDir, err = filepath.Abs(workingDir)
	if err != nil {
		return nil, fmt.Errorf("make working directory absolute: %w", err)
	}

	command := make([]string, 0, len(runArgs)+1)
	command = append(command, executable)
	command = append(command, runArgs...)

	var b strings.Builder
	b.WriteString("[Unit]\n")
	b.WriteString("Description=Outway HTTP, HTTPS, and SOCKS5 proxy server\n")
	b.WriteString("Documentation=https://github.com/xiaozhou26/outway\n")
	b.WriteString("After=network-online.target\n")
	b.WriteString("Wants=network-online.target\n\n")
	b.WriteString("[Service]\n")
	b.WriteString("Type=exec\n")
	fmt.Fprintf(&b, "WorkingDirectory=%s\n", escapeDirective(workingDir))
	fmt.Fprintf(&b, "ExecStart=%s\n", joinExec(command))
	b.WriteString("Restart=on-failure\n")
	b.WriteString("RestartSec=3s\n")
	b.WriteString("TimeoutStopSec=10s\n")
	b.WriteString("StandardOutput=journal\n")
	b.WriteString("StandardError=journal\n")
	b.WriteString("StateDirectory=outway\n")
	b.WriteString("StateDirectoryMode=0700\n")
	b.WriteString("UMask=0077\n")

	if !m.stderrIsTTY() {
		b.WriteString("Environment=NO_COLOR=1\n")
		b.WriteString("Environment=TERM=dumb\n")
		writeHardening(&b, args)
	}

	if uid, gid, ok := m.invokingUser(); ok {
		fmt.Fprintf(&b, "User=%d\n", uid)
		fmt.Fprintf(&b, "Group=%d\n", gid)
	}

	capabilities := requiredCapabilities(args)
	if len(capabilities) != 0 {
		joined := strings.Join(capabilities, " ")
		fmt.Fprintf(&b, "AmbientCapabilities=%s\n", joined)
		fmt.Fprintf(&b, "CapabilityBoundingSet=%s\n", joined)
	}

	b.WriteString("\n[Install]\n")
	b.WriteString("WantedBy=multi-user.target\n")
	return []byte(b.String()), nil
}

func writeHardening(b *strings.Builder, args config.BootArgs) {
	b.WriteString("NoNewPrivileges=yes\n")
	b.WriteString("PrivateTmp=yes\n")
	b.WriteString("PrivateDevices=yes\n")
	b.WriteString("ProtectSystem=strict\n")
	b.WriteString("ProtectHome=read-only\n")
	b.WriteString("ProtectControlGroups=yes\n")
	b.WriteString("ProtectKernelLogs=yes\n")
	b.WriteString("ProtectKernelModules=yes\n")
	if args.CIDR == nil {
		b.WriteString("ProtectKernelTunables=yes\n")
	}
	b.WriteString("ProtectClock=yes\n")
	b.WriteString("LockPersonality=yes\n")
	b.WriteString("MemoryDenyWriteExecute=yes\n")
	b.WriteString("RestrictSUIDSGID=yes\n")
	b.WriteString("RestrictRealtime=yes\n")
	b.WriteString("RestrictNamespaces=yes\n")
	b.WriteString("SystemCallArchitectures=native\n")
	b.WriteString("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\n")
}

func requiredCapabilities(args config.BootArgs) []string {
	var capabilities []string
	if args.Bind.Port() < 1024 {
		capabilities = append(capabilities, "CAP_NET_BIND_SERVICE")
	}
	if args.CIDR != nil || args.UDP.SocketBufferBytes > 0 {
		capabilities = append(capabilities, "CAP_NET_ADMIN")
	}
	if args.Fallback != nil && args.Fallback.IsInterface() {
		capabilities = append(capabilities, "CAP_NET_RAW")
	}
	return capabilities
}

func (m *Manager) invokingUser() (int, int, bool) {
	uidText, uidOK := m.lookupEnv("SUDO_UID")
	gidText, gidOK := m.lookupEnv("SUDO_GID")
	if !uidOK || !gidOK {
		return 0, 0, false
	}
	uid, uidErr := strconv.Atoi(uidText)
	gid, gidErr := strconv.Atoi(gidText)
	if uidErr != nil || gidErr != nil || uid == 0 || gid < 0 {
		return 0, 0, false
	}
	return uid, gid, true
}

func (m *Manager) requireRoot() error {
	if m.euid() != 0 {
		return errors.New("systemd service installation and control require root permissions")
	}
	return nil
}

func (m *Manager) systemctl(args ...string) error {
	path, err := m.lookPath("systemctl")
	if err != nil {
		return errors.New("systemctl was not found; systemd service management is unavailable")
	}
	return m.run(path, args...)
}

func (m *Manager) journalctl(args ...string) error {
	path, err := m.lookPath("journalctl")
	if err != nil {
		return errors.New("journalctl was not found; systemd journal access is unavailable")
	}
	return m.run(path, args...)
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run %s %s: %w", filepath.Base(name), strings.Join(args, " "), err)
	}
	return nil
}

func joinExec(args []string) string {
	quoted := make([]string, len(args))
	for i, arg := range args {
		quoted[i] = quoteExecArg(escapeExecMarkers(arg))
	}
	return strings.Join(quoted, " ")
}

func escapeExecMarkers(value string) string {
	value = strings.ReplaceAll(value, "%", "%%")
	return strings.ReplaceAll(value, "$", "$$")
}

func escapeDirective(value string) string {
	return strings.ReplaceAll(value, "%", "%%")
}

func quoteExecArg(value string) string {
	if value != "" && !strings.ContainsAny(value, " \t\n\r\"\\") {
		return value
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\n':
			b.WriteString("\\n")
		case '\r':
			b.WriteString("\\r")
		case '\t':
			b.WriteString("\\t")
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func stderrIsTerminal() bool {
	info, err := os.Stderr.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	term := os.Getenv("TERM")
	return term != "" && term != "dumb"
}
