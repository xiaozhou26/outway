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
	ProxyMASQUE
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

// DefaultMaxPendingDials bounds concurrent outbound TCP dials by default. It
// keeps a burst of new connections from opening an unbounded number of sockets
// at once; raise it for CONNECT-heavy pools whose targets dial slowly, or set
// zero to leave dialing unbounded.
const DefaultMaxPendingDials = 512

// DefaultNDPProxyMax bounds the proxy-neighbor entries --ndp-proxy keeps
// installed at once.
const DefaultNDPProxyMax = 65536

// HTTP/2 cleartext (h2c) CONNECT defaults. The receive windows bound the
// upload direction. HTTP/2's 64 KiB default would cap a 70 ms RTT connection
// at under 1 MB/s. A window much larger than the path's bandwidth-delay
// product does not add throughput. It lets the client queue megabytes of DATA
// ahead of a new tunnel's HEADERS, which then waits seconds for its 200 while
// other streams upload. 2 MiB covers about 28 MB/s per connection at 70 ms.
const (
	DefaultH2CMaxStreams   = 1000
	DefaultH2CConnWindow   = 2 << 20
	DefaultH2CStreamWindow = 2 << 20
)

// H2CConfig controls HTTP/2 cleartext CONNECT multiplexing (RFC 9113 §8.5) on
// the HTTP and auto-detect listeners. ConnWindow and StreamWindow are the
// receive windows outway advertises for client-to-target data.
type H2CConfig struct {
	Enabled      bool
	MaxStreams   uint32
	ConnWindow   int32
	StreamWindow int32
}

// DefaultH2CConfig returns the disabled h2c configuration with default limits.
func DefaultH2CConfig() H2CConfig {
	return H2CConfig{
		MaxStreams:   DefaultH2CMaxStreams,
		ConnWindow:   DefaultH2CConnWindow,
		StreamWindow: DefaultH2CStreamWindow,
	}
}

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
	LogLevel        string
	Bind            netip.AddrPort
	Concurrent      uint32
	Workers         int
	CIDR            *netip.Prefix
	CIDRRange       *uint8
	Fallback        *Fallback
	ConnectTimeout  uint64
	TCPUserTimeout  *uint64 // Linux only
	ReuseAddr       *bool
	MaxPendingDials int
	ReusePort       bool
	// SessionSpread selects the well-mixed session/TTL → address mapping
	// (default false keeps the Rust-compatible mapping and existing
	// addresses).
	SessionSpread bool
	// StrictSource keeps targets with a CIDR-family address on the CIDR
	// source; the fallback serves only targets without one.
	StrictSource bool
	// NDPProxy names the interface to answer neighbor solicitations on for
	// chosen IPv6 source addresses (Linux only; empty disables).
	NDPProxy string
	// NDPProxyMax bounds the installed proxy-neighbor entries.
	NDPProxyMax int
	// H2C enables HTTP/2 cleartext CONNECT multiplexing on HTTP listeners.
	H2C H2CConfig
	// TCPFastOpen sets the TCP_FASTOPEN queue length on TCP listeners
	// (Linux only; zero disables).
	TCPFastOpen int
	// UpstreamCongestion names the TCP congestion control algorithm (for
	// example "bbr") set with TCP_CONGESTION on every outbound TCP socket.
	// Empty keeps the system default. Linux only.
	UpstreamCongestion string
	Diagnostics        *netip.AddrPort
	UDP                UDPConfig
	Proxy              ProxyConfig
}

// Validate checks cross-field constraints that cannot be expressed by the CLI
// flag types alone.
func (a BootArgs) Validate() error {
	if a.Diagnostics != nil && (!a.Diagnostics.IsValid() || a.Diagnostics.Addr().IsUnspecified()) {
		return fmt.Errorf("diagnostics address must be a valid, non-wildcard IP endpoint")
	}
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
	if a.NDPProxy != "" {
		if a.CIDR == nil || !a.CIDR.Addr().Is6() {
			return fmt.Errorf("ndp-proxy requires an IPv6 CIDR")
		}
		if a.NDPProxyMax < 1 {
			return fmt.Errorf("ndp-proxy-max must be at least 1")
		}
	}
	if a.H2C.Enabled {
		if a.Proxy.Kind != ProxyHTTP && a.Proxy.Kind != ProxyAuto {
			return fmt.Errorf("h2c is only supported by the http and auto proxies")
		}
		if a.H2C.MaxStreams < 1 {
			return fmt.Errorf("h2c-max-streams must be at least 1")
		}
		if a.H2C.ConnWindow < 65535 {
			return fmt.Errorf("h2c-conn-window must be at least 65535 bytes")
		}
		if a.H2C.StreamWindow < 1 {
			return fmt.Errorf("h2c-stream-window must be positive")
		}
	}
	if a.TCPFastOpen < 0 {
		return fmt.Errorf("tcp-fastopen queue length must not be negative")
	}
	if err := validCongestionName(a.UpstreamCongestion); err != nil {
		return err
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
		LogLevel:        "info",
		Bind:            netip.MustParseAddrPort("127.0.0.1:1080"),
		Concurrent:      8192,
		ConnectTimeout:  10,
		ReuseAddr:       &reuse,
		MaxPendingDials: DefaultMaxPendingDials,
		NDPProxyMax:     DefaultNDPProxyMax,
		H2C:             DefaultH2CConfig(),
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

// validCongestionName checks the shape of a TCP congestion control name. The
// kernel limits names to 15 bytes (TCP_CA_NAME_MAX includes the NUL), and
// every in-tree algorithm uses lowercase letters, digits, and underscores.
// Whether the algorithm is available is checked at startup.
func validCongestionName(name string) error {
	if name == "" {
		return nil
	}
	if len(name) > 15 {
		return fmt.Errorf("upstream-congestion %q is longer than 15 bytes", name)
	}
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' && r != '-' {
			return fmt.Errorf("upstream-congestion %q contains %q; expected a kernel algorithm name such as bbr or cubic", name, r)
		}
	}
	return nil
}
