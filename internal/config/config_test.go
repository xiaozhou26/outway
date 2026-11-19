package config

import (
	"net/netip"
	"testing"
)

func TestBootArgsValidateRejectsPartialCredentials(t *testing.T) {
	args := DefaultBootArgs()
	args.Proxy.Auth.Username = "user"
	if err := args.Validate(); err == nil {
		t.Fatal("expected partial credentials to be rejected")
	}
}

func TestBootArgsValidateRejectsUnlimitedConcurrency(t *testing.T) {
	args := DefaultBootArgs()
	args.Concurrent = 0
	if err := args.Validate(); err == nil {
		t.Fatal("expected zero concurrency limit to be rejected")
	}
}

func TestDefaultBootArgsSupportsThousandsOfConnections(t *testing.T) {
	args := DefaultBootArgs()
	if args.Concurrent < 5000 {
		t.Fatalf("default concurrency %d is below the high-concurrency target", args.Concurrent)
	}
}

func TestDefaultBootArgsUDPResources(t *testing.T) {
	args := DefaultBootArgs()
	if args.UDP.MaxPacketSize != DefaultUDPMaxPacketSize ||
		args.UDP.BatchSize != DefaultUDPBatchSize ||
		args.UDP.BatchBufferBudget != DefaultUDPBatchBufferBudget ||
		args.UDP.SendQueueSize != DefaultUDPSendQueueSize {
		t.Fatalf("unexpected UDP defaults: %+v", args.UDP)
	}
	if err := args.Validate(); err != nil {
		t.Fatalf("default UDP resources should validate: %v", err)
	}
	args.UDP.SocketBufferBytes = 4 << 20
	if err := args.Validate(); err != nil {
		t.Fatalf("explicit UDP socket buffer should validate: %v", err)
	}
}

func TestBootArgsValidateRejectsInvalidUDPResources(t *testing.T) {
	tests := []struct {
		name string
		edit func(*BootArgs)
	}{
		{name: "small packet", edit: func(args *BootArgs) { args.UDP.MaxPacketSize = 511 }},
		{name: "large batch", edit: func(args *BootArgs) { args.UDP.BatchSize = 1025 }},
		{name: "negative batch budget", edit: func(args *BootArgs) { args.UDP.BatchBufferBudget = -1 }},
		{name: "empty queue", edit: func(args *BootArgs) { args.UDP.SendQueueSize = 0 }},
		{name: "negative workers", edit: func(args *BootArgs) { args.UDP.SendWorkers = -1 }},
		{name: "small socket buffer", edit: func(args *BootArgs) { args.UDP.SocketBufferBytes = 4095 }},
		{name: "negative socket buffer", edit: func(args *BootArgs) { args.UDP.SocketBufferBytes = -1 }},
		{name: "huge socket buffer", edit: func(args *BootArgs) { args.UDP.SocketBufferBytes = 1<<30 + 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			args := DefaultBootArgs()
			test.edit(&args)
			if err := args.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestBootArgsValidateRejectsPartialTLSConfig(t *testing.T) {
	args := DefaultBootArgs()
	args.Proxy.TLSCert = "cert.pem"
	if err := args.Validate(); err == nil {
		t.Fatal("expected partial TLS config to be rejected")
	}
}

func TestBootArgsValidateCIDRRange(t *testing.T) {
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	invalid := uint8(33)
	args := DefaultBootArgs()
	args.CIDR = &prefix
	args.CIDRRange = &invalid
	if err := args.Validate(); err == nil {
		t.Fatal("expected an IPv4 CIDR range above 32 to be rejected")
	}

	valid := uint8(28)
	args.CIDRRange = &valid
	if err := args.Validate(); err != nil {
		t.Fatalf("expected valid CIDR range: %v", err)
	}
}

func TestDiagnosticsDisabledByDefault(t *testing.T) {
	args := DefaultBootArgs()
	if args.Diagnostics != nil {
		t.Fatalf("diagnostics should be disabled by default: %v", args.Diagnostics)
	}
}

func TestBootArgsValidateRejectsWildcardDiagnostics(t *testing.T) {
	for _, endpoint := range []string{"0.0.0.0:6060", "[::]:6060"} {
		t.Run(endpoint, func(t *testing.T) {
			bind := netip.MustParseAddrPort(endpoint)
			args := DefaultBootArgs()
			args.Diagnostics = &bind
			if err := args.Validate(); err == nil {
				t.Fatal("expected wildcard diagnostics address to be rejected")
			}
		})
	}
}

func TestBootArgsValidateAcceptsLoopbackDiagnostics(t *testing.T) {
	bind := netip.MustParseAddrPort("127.0.0.1:6060")
	args := DefaultBootArgs()
	args.Diagnostics = &bind
	if err := args.Validate(); err != nil {
		t.Fatalf("expected loopback diagnostics address to validate: %v", err)
	}
}

func TestDefaultBootArgsSourcePolicyIsOff(t *testing.T) {
	args := DefaultBootArgs()
	if args.SessionSpread || args.StrictSource || args.NDPProxy != "" {
		t.Fatalf("source policy defaults changed: spread=%v strict=%v ndp=%q", args.SessionSpread, args.StrictSource, args.NDPProxy)
	}
	if args.NDPProxyMax != DefaultNDPProxyMax || DefaultNDPProxyMax != 65536 {
		t.Fatalf("NDPProxyMax = %d, want 65536", args.NDPProxyMax)
	}
}

func TestBootArgsValidateNDPProxy(t *testing.T) {
	v6 := netip.MustParsePrefix("2001:db8::/64")
	v4 := netip.MustParsePrefix("192.0.2.0/24")

	args := DefaultBootArgs()
	args.NDPProxy = "eno1"
	if err := args.Validate(); err == nil {
		t.Error("ndp-proxy without a CIDR was accepted")
	}
	args.CIDR = &v4
	if err := args.Validate(); err == nil {
		t.Error("ndp-proxy with an IPv4 CIDR was accepted")
	}
	args.CIDR = &v6
	if err := args.Validate(); err != nil {
		t.Errorf("valid ndp-proxy rejected: %v", err)
	}
	args.NDPProxyMax = 0
	if err := args.Validate(); err == nil {
		t.Error("ndp-proxy-max 0 was accepted")
	}
}

func TestH2CAndFastOpenOffByDefault(t *testing.T) {
	args := DefaultBootArgs()
	if args.H2C.Enabled || args.TCPFastOpen != 0 {
		t.Fatalf("h2c=%v tcp-fastopen=%d, want both off by default", args.H2C.Enabled, args.TCPFastOpen)
	}
	if args.H2C.ConnWindow < 16<<20 || args.H2C.StreamWindow < 4<<20 {
		t.Fatalf("default h2c windows conn=%d stream=%d are too small for long fat links", args.H2C.ConnWindow, args.H2C.StreamWindow)
	}
}

func TestBootArgsValidateH2C(t *testing.T) {
	valid := DefaultBootArgs()
	valid.Proxy.Kind = ProxyAuto
	valid.H2C.Enabled = true
	if err := valid.Validate(); err != nil {
		t.Fatalf("h2c on auto: %v", err)
	}
	for name, mutate := range map[string]func(*BootArgs){
		"socks5 proxy":       func(a *BootArgs) { a.Proxy.Kind = ProxySocks5 },
		"https proxy":        func(a *BootArgs) { a.Proxy.Kind = ProxyHTTPS },
		"zero streams":       func(a *BootArgs) { a.H2C.MaxStreams = 0 },
		"tiny conn window":   func(a *BootArgs) { a.H2C.ConnWindow = 1024 },
		"zero stream window": func(a *BootArgs) { a.H2C.StreamWindow = 0 },
		"negative fastopen":  func(a *BootArgs) { a.TCPFastOpen = -1 },
	} {
		args := valid
		mutate(&args)
		if err := args.Validate(); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}
