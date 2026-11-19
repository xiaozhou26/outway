package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFileAppliesPresentKeysOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outway.yaml")
	content := `
bind: 0.0.0.0:1080
concurrent: 65536
cidr: 2001:db8::/56
cidr-range: 64
reuse-port: false
username: user
password: pass
udp:
  socket-buffer: 8388608
  gso: true
  associations: 32768
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	fc, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if fc == nil {
		t.Fatal("LoadFile returned nil for a non-empty file")
	}
	if fc.Bind == nil || *fc.Bind != "0.0.0.0:1080" {
		t.Errorf("bind = %v, want 0.0.0.0:1080", fc.Bind)
	}
	if fc.Concurrent == nil || *fc.Concurrent != 65536 {
		t.Errorf("concurrent = %v, want 65536", fc.Concurrent)
	}
	if fc.CIDRRange == nil || *fc.CIDRRange != 64 {
		t.Errorf("cidr-range = %v, want 64", fc.CIDRRange)
	}
	if fc.Log != nil {
		t.Errorf("absent key log parsed as %v, want nil", *fc.Log)
	}
	if fc.ReusePort == nil || *fc.ReusePort {
		t.Error("explicit reuse-port: false must parse as present-and-false, not absent")
	}
	if fc.UDP == nil {
		t.Fatal("udp section missing")
	}
	if fc.UDP.SocketBufferBytes == nil || *fc.UDP.SocketBufferBytes != 8388608 {
		t.Errorf("udp.socket-buffer = %v, want 8388608", fc.UDP.SocketBufferBytes)
	}
	if fc.UDP.GSO == nil || !*fc.UDP.GSO {
		t.Errorf("udp.gso = %v, want true", fc.UDP.GSO)
	}
	if fc.UDP.BatchSize != nil {
		t.Errorf("absent udp.batch-size parsed as %v, want nil", *fc.UDP.BatchSize)
	}
}

func TestLoadFileRejectsUnknownKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outway.yaml")
	if err := os.WriteFile(path, []byte("bnd: 0.0.0.0:1080\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err == nil {
		t.Fatal("LoadFile accepted an unknown key; typoed settings must fail at startup")
	}
}

func TestLoadFileEmptyYieldsNil(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outway.yaml")
	if err := os.WriteFile(path, []byte("   \n# comment only\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fc, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if fc != nil {
		t.Errorf("empty file returned %+v, want nil", fc)
	}
}

func TestLoadFileMissingErrors(t *testing.T) {
	if _, err := LoadFile(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Fatal("LoadFile succeeded on a missing file")
	}
}

func TestLoadFileSourcePolicyKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outway.yaml")
	content := `
cidr: 2001:db8::/64
session-spread: true
strict-source: true
ndp-proxy: eno1
ndp-proxy-max: 1024
h2c: true
h2c-max-streams: 500
h2c-conn-window: 33554432
h2c-stream-window: 8388608
tcp-fastopen: 256
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	fc, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if fc.SessionSpread == nil || !*fc.SessionSpread {
		t.Errorf("session-spread = %v, want true", fc.SessionSpread)
	}
	if fc.StrictSource == nil || !*fc.StrictSource {
		t.Errorf("strict-source = %v, want true", fc.StrictSource)
	}
	if fc.NDPProxy == nil || *fc.NDPProxy != "eno1" {
		t.Errorf("ndp-proxy = %v, want eno1", fc.NDPProxy)
	}
	if fc.H2C == nil || !*fc.H2C || fc.H2CMaxStreams == nil || *fc.H2CMaxStreams != 500 ||
		fc.H2CConnWindow == nil || *fc.H2CConnWindow != 32<<20 || fc.H2CStreamWindow == nil || *fc.H2CStreamWindow != 8<<20 {
		t.Errorf("h2c keys = %v %v %v %v", fc.H2C, fc.H2CMaxStreams, fc.H2CConnWindow, fc.H2CStreamWindow)
	}
	if fc.TCPFastOpen == nil || *fc.TCPFastOpen != 256 {
		t.Errorf("tcp-fastopen = %v, want 256", fc.TCPFastOpen)
	}
	if fc.NDPProxyMax == nil || *fc.NDPProxyMax != 1024 {
		t.Errorf("ndp-proxy-max = %v, want 1024", fc.NDPProxyMax)
	}
}
