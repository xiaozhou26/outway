//go:build linux

package systemd

import (
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/xiaozhou26/outway/internal/config"
)

func testManager(t *testing.T, stderrTTY bool) *Manager {
	t.Helper()
	return &Manager{
		unitPath:   filepath.Join(t.TempDir(), serviceName),
		executable: func() (string, error) { return "/opt/out way/outway", nil },
		workingDir: func() (string, error) { return "/srv/out%way", nil },
		lookPath:   func(name string) (string, error) { return "/usr/bin/" + name, nil },
		run:        func(string, ...string) error { return nil },
		euid:       func() int { return 0 },
		stderrIsTTY: func() bool {
			return stderrTTY
		},
		lookupEnv: func(string) (string, bool) { return "", false },
		readFile:  os.ReadFile,
		writeFile: os.WriteFile,
	}
}

func TestUnitUsesStateDirectoryAndNonTerminalHardening(t *testing.T) {
	manager := testManager(t, false)
	args := config.DefaultBootArgs()
	unit, err := manager.unit(args, []string{"run", "auto", "--username", "100%-$TOKEN"})
	if err != nil {
		t.Fatal(err)
	}
	text := string(unit)
	for _, expected := range []string{
		"StateDirectory=outway",
		"StateDirectoryMode=0700",
		"Environment=NO_COLOR=1",
		"Environment=TERM=dumb",
		"NoNewPrivileges=yes",
		"ProtectSystem=strict",
		"WorkingDirectory=/srv/out%%way",
		`ExecStart="/opt/out way/outway" run auto --username 100%%-$$TOKEN`,
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("unit does not contain %q:\n%s", expected, text)
		}
	}
}

func TestUnitLeavesInteractiveInstallUnhardened(t *testing.T) {
	manager := testManager(t, true)
	unit, err := manager.unit(config.DefaultBootArgs(), []string{"run", "http"})
	if err != nil {
		t.Fatal(err)
	}
	text := string(unit)
	if strings.Contains(text, "NO_COLOR") || strings.Contains(text, "NoNewPrivileges") {
		t.Fatalf("interactive unit unexpectedly contains non-terminal hardening:\n%s", text)
	}
	if !strings.Contains(text, "StateDirectory=outway") {
		t.Fatal("StateDirectory must be present regardless of terminal state")
	}
}

func TestRequiredCapabilities(t *testing.T) {
	args := config.DefaultBootArgs()
	args.Bind = netip.MustParseAddrPort("0.0.0.0:443")
	cidr := netip.MustParsePrefix("2001:db8::/64")
	args.CIDR = &cidr
	args.Fallback = &config.Fallback{Interface: "eth0"}
	args.UDP.SocketBufferBytes = 1 << 20
	want := []string{"CAP_NET_BIND_SERVICE", "CAP_NET_ADMIN", "CAP_NET_RAW"}
	if got := requiredCapabilities(args); !reflect.DeepEqual(got, want) {
		t.Fatalf("capabilities = %v, want %v", got, want)
	}
}

func TestInstallReloadsOnlyAfterWritingUnit(t *testing.T) {
	manager := testManager(t, false)
	var calls [][]string
	manager.run = func(name string, args ...string) error {
		calls = append(calls, append([]string{name}, args...))
		return nil
	}
	changed, err := manager.install(config.DefaultBootArgs(), []string{"run", "http"})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("first install should write the unit")
	}
	if len(calls) != 1 || calls[0][1] != "daemon-reload" {
		t.Fatalf("unexpected command calls: %v", calls)
	}
	changed, err = manager.install(config.DefaultBootArgs(), []string{"run", "http"})
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("identical second install should be unchanged")
	}
	if len(calls) != 1 {
		t.Fatalf("unchanged install should not reload systemd, calls: %v", calls)
	}
}

func TestRequiredCapabilitiesUpstreamCongestion(t *testing.T) {
	args := config.DefaultBootArgs()
	args.Bind = netip.MustParseAddrPort("127.0.0.1:1080")
	if got := requiredCapabilities(args); len(got) != 0 {
		t.Fatalf("default capabilities = %v, want none", got)
	}
	args.UpstreamCongestion = "bbr"
	if got, want := requiredCapabilities(args), []string{"CAP_NET_ADMIN"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("capabilities = %v, want %v", got, want)
	}
}
