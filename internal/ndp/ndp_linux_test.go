//go:build linux

package ndp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeProcSys(t *testing.T, iface, forwarding string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "net", "ipv6", "conf", iface)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "forwarding"), []byte(forwarding+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	saved := procSys
	procSys = root
	t.Cleanup(func() { procSys = saved })
	return dir
}

func TestOpenRejectsNonForwardingInterface(t *testing.T) {
	fakeProcSys(t, "lo", "0")
	_, err := Open("lo", 16)
	if err == nil || !strings.Contains(err.Error(), "forwarding") {
		t.Fatalf("Open = %v, want a forwarding error", err)
	}
}

func TestOpenEnablesProxyNDP(t *testing.T) {
	dir := fakeProcSys(t, "lo", "1")
	cache, err := Open("lo", 16)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cache.Close() }()
	got, err := os.ReadFile(filepath.Join(dir, "proxy_ndp"))
	if err != nil || string(got) != "1" {
		t.Fatalf("proxy_ndp = %q, %v; want 1", got, err)
	}
}

func TestOpenRejectsUnknownInterface(t *testing.T) {
	if _, err := Open("outway-no-such-if0", 16); err == nil {
		t.Fatal("expected an unknown interface to be rejected")
	}
}
