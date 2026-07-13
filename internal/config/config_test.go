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
