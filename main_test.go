package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/xiaozhou26/outway/internal/config"
	"github.com/xiaozhou26/outway/internal/oneself"
)

func TestConfigPathFromArgs(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
		ok   bool
	}{
		{"space form", []string{"auto", "--config", "/etc/outway.yaml"}, "/etc/outway.yaml", true},
		{"equals form", []string{"--config=/etc/outway.yaml", "auto"}, "/etc/outway.yaml", true},
		{"before subcommand", []string{"--config", "a.yaml", "auto"}, "a.yaml", true},
		{"missing", []string{"auto"}, "", false},
		{"after separator", []string{"auto", "--", "--config", "a.yaml"}, "", false},
		{"dangling value left to cobra", []string{"auto", "--config"}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := configPathFromArgs(tc.args)
			if got != tc.want || ok != tc.ok {
				t.Errorf("configPathFromArgs(%q) = %q,%v; want %q,%v", tc.args, got, ok, tc.want, tc.ok)
			}
		})
	}
}

// resetFlagVars restores every flag variable to its registered default by
// re-running the flag registration against a throwaway command tree.
func resetFlagVars() {
	cmd := newRootCmd(func(*cobra.Command, []string) error { return nil })
	resetDefaults(cmd.PersistentFlags())
	resetDefaults(cmd.Flags())
	for _, sub := range cmd.Commands() {
		resetDefaults(sub.PersistentFlags())
		resetDefaults(sub.Flags())
		for _, leaf := range sub.Commands() {
			resetDefaults(leaf.Flags())
		}
	}
}

func resetDefaults(fs *pflag.FlagSet) {
	fs.VisitAll(func(f *pflag.Flag) {
		_ = f.Value.Set(f.DefValue)
	})
}

func TestRunConfigFileFlagOverridesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outway.yaml")
	content := `
bind: 0.0.0.0:9999
concurrent: 65536
reuse-port: true
username: fileuser
password: filepass
udp:
  socket-buffer: 8388608
  gso: true
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	resetFlagVars()

	// Drive the real pipeline: preload from --config, then cobra parses the
	// command line where only -b is explicit. The captured BootArgs must show
	// the flag winning for bind and the file winning everywhere else.
	var got config.BootArgs
	exec := func(cmd *cobra.Command, _ []string) error {
		a, err := buildBootArgs(proxyNameFromArgs(cmd))
		if err != nil {
			return err
		}
		got = a
		return nil
	}
	if err := run([]string{"outway", "run", "auto", "-b", "127.0.0.1:7777", "--config", path}, exec); err != nil {
		t.Fatalf("run: %v", err)
	}

	if got.Bind.String() != "127.0.0.1:7777" {
		t.Errorf("bind = %s, want the explicit flag value", got.Bind)
	}
	if got.Concurrent != 65536 {
		t.Errorf("concurrent = %d, want the file value", got.Concurrent)
	}
	if !got.ReusePort {
		t.Error("reuse-port = false, want the file value true")
	}
	if got.Proxy.Auth.Username != "fileuser" || got.Proxy.Auth.Password != "filepass" {
		t.Errorf("auth = %q/%q, want the file values", got.Proxy.Auth.Username, got.Proxy.Auth.Password)
	}
	if got.UDP.SocketBufferBytes != 8388608 || !got.UDP.GSO {
		t.Errorf("udp = %d,%v; want file values 8388608,true", got.UDP.SocketBufferBytes, got.UDP.GSO)
	}
}

func TestRunFileWithoutExplicitFlags(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outway.yaml")
	if err := os.WriteFile(path, []byte("bind: 0.0.0.0:9999\nconcurrent: 4096\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	resetFlagVars()

	var got config.BootArgs
	exec := func(cmd *cobra.Command, _ []string) error {
		a, err := buildBootArgs(proxyNameFromArgs(cmd))
		if err != nil {
			return err
		}
		got = a
		return nil
	}
	if err := run([]string{"outway", "run", "http", "--config", path}, exec); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got.Bind.String() != "0.0.0.0:9999" || got.Concurrent != 4096 {
		t.Errorf("bind/concurrent = %s/%d, want file values", got.Bind, got.Concurrent)
	}
}

func TestRunBadConfigFailsStartup(t *testing.T) {
	resetFlagVars()
	err := run([]string{"outway", "run", "auto", "--config", filepath.Join(t.TempDir(), "absent.yaml")},
		func(*cobra.Command, []string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "read config file") {
		t.Errorf("run = %v, want a config read error", err)
	}
}

func TestPreloadConfigFileIgnoresNonRunCommands(t *testing.T) {
	// A bad config path must not break commands that never seed flags.
	err := preloadConfigFile([]string{"outway", "self", "update", "--config", filepath.Join(t.TempDir(), "absent.yaml")})
	if err != nil {
		t.Errorf("preloadConfigFile(self update) = %v, want nil", err)
	}
}

func TestRunSourcePolicyFromFileAndFlags(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outway.yaml")
	content := "cidr: 2001:db8::/64\nsession-spread: true\nndp-proxy: eno1\nndp-proxy-max: 4096\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	resetFlagVars()
	var got config.BootArgs
	exec := func(cmd *cobra.Command, _ []string) error {
		a, err := buildBootArgs(proxyNameFromArgs(cmd))
		got = a
		return err
	}
	if err := run([]string{"outway", "run", "auto", "--strict-source", "--config", path}, exec); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !got.SessionSpread || !got.StrictSource || got.NDPProxy != "eno1" || got.NDPProxyMax != 4096 {
		t.Fatalf("got spread=%v strict=%v ndp=%q max=%d", got.SessionSpread, got.StrictSource, got.NDPProxy, got.NDPProxyMax)
	}

	resetFlagVars()
	if err := run([]string{"outway", "run", "auto"}, exec); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got.SessionSpread || got.StrictSource || got.NDPProxy != "" || got.NDPProxyMax != config.DefaultNDPProxyMax {
		t.Fatalf("defaults changed: spread=%v strict=%v ndp=%q max=%d", got.SessionSpread, got.StrictSource, got.NDPProxy, got.NDPProxyMax)
	}
}

func TestVersionOutput(t *testing.T) {
	for _, args := range [][]string{{"--version"}, {"version"}} {
		cmd := newRootCmd(func(*cobra.Command, []string) error { return nil })
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if got, want := out.String(), "outway "+oneself.Version()+"\n"; got != want {
			t.Fatalf("%v printed %q, want %q", args, got, want)
		}
	}
}
