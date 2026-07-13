// Package config defines the configuration types for the outway server.
package config

import (
	"fmt"
	"net/netip"
	"strings"
)

// AuthMode holds optional basic authentication credentials.
type AuthMode struct {
	Username string
	Password string
}

// HasAuth reports whether authentication is configured.
func (a AuthMode) HasAuth() bool {
	return a.Username != "" && a.Password != ""
}

// ProxyKind identifies the proxy protocol to run.
type ProxyKind int

const (
	ProxyHTTP ProxyKind = iota
	ProxyHTTPS
	ProxySocks5
	ProxyAuto
)

// ProxyConfig holds the selected proxy protocol and its options.
type ProxyConfig struct {
	Kind    ProxyKind
	Auth    AuthMode
	TLSCert string
	TLSKey  string
}

// Fallback describes a fallback outbound source: either a local IP address or
// (on Unix) a network interface name.
type Fallback struct {
	Address   netip.Addr
	Interface string
}

const (
	DefaultUDPMaxPacketSize       = 65507
	DefaultUDPBatchSize           = 32
	DefaultUDPBatchBufferBudget   = 1024
	DefaultUDPSendQueueSize       = 4096
	DefaultUDPMetricsIntervalSecs = 30
)

// UDPConfig controls SOCKS5 UDP relay resource usage. SendWorkers set to zero
// selects an automatic value derived from GOMAXPROCS. MetricsIntervalSecs and
// AssociationIdleTimeoutSecs set to zero disable the corresponding timer.
// SocketBufferBytes set to zero keeps the operating system default socket
// buffer sizes. GSO enables Linux UDP_SEGMENT batching for same-destination
// uniform-size sends; GRO enables Linux UDP_GRO coalescing on the receive path.
type UDPConfig struct {
	MaxPacketSize              int
	BatchSize                  int
	BatchBufferBudget          int
	SendQueueSize              int
	SendWorkers                int
	SocketBufferBytes          int
	MaxAssociations            uint32
	MetricsIntervalSecs        uint64
	AssociationIdleTimeoutSecs uint64
	GSO                        bool
	GRO                        bool
}

// IsInterface reports whether the fallback references a network interface.
func (f Fallback) IsInterface() bool {
	return f.Interface != ""
}

// ParseFallback parses a fallback string. It accepts an IP address, or (on all
// platforms) an interface name when the value is not a valid IP.
func ParseFallback(s string) (Fallback, error) {
	if addr, err := netip.ParseAddr(s); err == nil {
		return Fallback{Address: addr}, nil
	}
	return Fallback{Interface: s}, nil
}

// BootArgs holds all server boot configuration.
type BootArgs struct {
	LogLevel       string
	Bind           netip.AddrPort
	Concurrent     uint32
	Workers        int
	CIDR           *netip.Prefix
	CIDRRange      *uint8
	Fallback       *Fallback
	ConnectTimeout uint64
	TCPUserTimeout *uint64 // Linux only
	ReuseAddr      *bool
	UDP            UDPConfig
	Proxy          ProxyConfig
}

// Validate checks cross-field constraints that cannot be expressed by the CLI
// flag types alone.
func (a BootArgs) Validate() error {
	if a.Concurrent == 0 {
		return fmt.Errorf("concurrent connection limit must be greater than zero")
	}
	if a.ConnectTimeout == 0 {
		return fmt.Errorf("connect timeout must be greater than zero")
	}
	if a.Workers < 0 {
		return fmt.Errorf("workers must not be negative")
	}
	if a.UDP.MaxPacketSize < 512 || a.UDP.MaxPacketSize > 65535 {
		return fmt.Errorf("UDP maximum packet size must be between 512 and 65535")
	}
	if a.UDP.BatchSize < 1 || a.UDP.BatchSize > 1024 {
		return fmt.Errorf("UDP batch size must be between 1 and 1024")
	}
	if a.UDP.BatchBufferBudget < 0 {
		return fmt.Errorf("UDP batch buffer budget must not be negative")
	}
	if a.UDP.SendQueueSize < 1 {
		return fmt.Errorf("UDP send queue size must be greater than zero")
	}
	if a.UDP.SendWorkers < 0 || a.UDP.SendWorkers > 4096 {
		return fmt.Errorf("UDP send workers must be between 0 and 4096")
	}
	if a.UDP.SocketBufferBytes != 0 && (a.UDP.SocketBufferBytes < 4096 || a.UDP.SocketBufferBytes > 1<<30) {
		return fmt.Errorf("UDP socket buffer must be 0 (system default) or between 4096 and %d bytes", 1<<30)
	}
	if a.UDP.MaxAssociations > a.Concurrent {
		return fmt.Errorf("UDP association limit must not exceed concurrent connection limit")
	}
	if (a.Proxy.Auth.Username == "") != (a.Proxy.Auth.Password == "") {
		return fmt.Errorf("username and password must be configured together")
	}
	if (a.Proxy.TLSCert == "") != (a.Proxy.TLSKey == "") {
		return fmt.Errorf("TLS certificate and key must be configured together")
	}
	if a.CIDRRange != nil {
		if a.CIDR == nil {
			return fmt.Errorf("CIDR range requires a CIDR")
		}
		rangeBits := int(*a.CIDRRange)
		if rangeBits < a.CIDR.Bits() || rangeBits > a.CIDR.Addr().BitLen() {
			return fmt.Errorf("CIDR range must be between %d and %d for %s", a.CIDR.Bits(), a.CIDR.Addr().BitLen(), a.CIDR)
		}
	}
	return nil
}

// DefaultBootArgs returns boot arguments with the same defaults as the CLI.
func DefaultBootArgs() BootArgs {
	reuse := true
	return BootArgs{
		LogLevel:       "info",
		Bind:           netip.MustParseAddrPort("127.0.0.1:1080"),
		Concurrent:     8192,
		ConnectTimeout: 10,
		ReuseAddr:      &reuse,
		UDP: UDPConfig{
			MaxPacketSize:       DefaultUDPMaxPacketSize,
			BatchSize:           DefaultUDPBatchSize,
			BatchBufferBudget:   DefaultUDPBatchBufferBudget,
			SendQueueSize:       DefaultUDPSendQueueSize,
			MetricsIntervalSecs: DefaultUDPMetricsIntervalSecs,
		},
	}
}

// ParseLogLevel converts a string log level to a slog level string.
func ParseLogLevel(s string) string {
	switch strings.ToLower(s) {
	case "trace":
		return "DEBUG"
	case "debug":
		return "DEBUG"
	case "info":
		return "INFO"
	case "warn":
		return "WARN"
	case "error":
		return "ERROR"
	default:
		return "INFO"
	}
}
