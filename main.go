// Package main is the outway command-line entry point. It wires up the CLI
// commands (run, systemd, self) to the server and self-update modules.
package main

import (
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/xiaozhou26/outway/internal/config"
	"github.com/xiaozhou26/outway/internal/oneself"
	"github.com/xiaozhou26/outway/internal/server"
)

// Flag variables shared across run/start/restart commands.
var (
	flagLogLevel               string
	flagBind                   string
	flagConcurrent             uint32
	flagWorkers                int
	flagCIDR                   string
	flagCIDRRange              uint8
	flagFallback               string
	flagConnectTimeout         uint64
	flagTCPUserTimeout         uint64
	flagReuseAddr              bool
	flagMaxPendingDials        int
	flagReusePort              bool
	flagSessionSpread          bool
	flagStrictSource           bool
	flagNDPProxy               string
	flagNDPProxyMax            int
	flagDiagnostics            string
	flagUDPMaxPacketSize       int
	flagUDPBatchSize           int
	flagUDPBatchBufferBudget   int
	flagUDPSendQueueSize       int
	flagUDPSendWorkers         int
	flagUDPSocketBuffer        int
	flagUDPGSO                 bool
	flagUDPGRO                 bool
	flagUDPMaxAssociations     uint32
	flagUDPMetricsInterval     uint64
	flagUDPAssociationIdleTime uint64

	// Auth flags (per proxy subcommand).
	flagUsername string
	flagPassword string

	// TLS flags (https/auto subcommands).
	flagTLSCert string
	flagTLSKey  string

	// Config file providing defaults for unset flags.
	flagConfigFile string
)

func main() {
	if err := run(os.Args, execRun); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// run wires the CLI: it seeds flag variables from --config before cobra parses
// the command line (file values act as defaults, explicit flags win), builds
// the command tree, and executes. exec is the entry point for run subcommands,
// swappable in tests.
func run(args []string, exec func(cmd *cobra.Command, a []string) error) error {
	rootCmd := newRootCmd(exec)
	if err := preloadConfigFile(args); err != nil {
		return err
	}
	rootCmd.SetArgs(args[1:])
	return rootCmd.Execute()
}

func newRootCmd(exec func(cmd *cobra.Command, args []string) error) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:           "outway",
		Short:         "A high-performance HTTP/HTTPS/SOCKS5 proxy server",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       oneself.Version(),
	}
	rootCmd.SetVersionTemplate("outway {{.Version}}\n")
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "outway %s\n", oneself.Version())
			return err
		},
	})

	// run command and its proxy subcommands.
	runCmd := newProxyCommand("run", "Run server", exec)
	rootCmd.AddCommand(runCmd)

	// Linux-only systemd service commands.
	if runtime.GOOS == "linux" {
		systemdCmd := &cobra.Command{Use: "systemd", Short: "Manage the systemd service"}
		systemdCmd.AddCommand(
			newProxyCommand("install", "Install the systemd service", execSystemdInstall),
			newProxyCommand("enable", "Install and enable the systemd service", execSystemdEnable),
			newProxyCommand("start", "Install, enable, and start the systemd service", execSystemdStart),
			newProxyCommand("restart", "Update and restart the systemd service", execSystemdRestart),
			&cobra.Command{Use: "stop", Short: "Stop the systemd service", Args: cobra.NoArgs, RunE: execSystemdStop},
			&cobra.Command{Use: "status", Short: "Show the systemd service status", Args: cobra.NoArgs, RunE: execSystemdStatus},
			&cobra.Command{Use: "logs", Short: "Show recent logs and follow new entries", Args: cobra.NoArgs, RunE: execSystemdLogs},
		)
		rootCmd.AddCommand(systemdCmd)
	}

	// self command.
	selfCmd := &cobra.Command{Use: "self", Short: "Modify server installation"}
	selfCmd.AddCommand(
		&cobra.Command{Use: "update", Short: "Download and install updates", RunE: execSelfUpdate},
		&cobra.Command{Use: "uninstall", Short: "Uninstall proxy server", RunE: execSelfUninstall},
	)
	rootCmd.AddCommand(selfCmd)

	return rootCmd
}

// preloadConfigFile applies --config values to the flag variables before cobra
// parses the command line. pflag only overwrites variables for flags present
// in the arguments, so file values act as defaults and an explicitly given
// flag always wins. Only run/systemd invocations are seeded; self-update and
// friends never touch server flags.
func preloadConfigFile(args []string) error {
	if len(args) < 2 || (args[1] != "run" && args[1] != "systemd") {
		return nil
	}
	path, ok := configPathFromArgs(args[2:])
	if !ok {
		return nil
	}
	fc, err := config.LoadFile(path)
	if err != nil {
		return err
	}
	applyFileConfig(fc)
	return nil
}

// configPathFromArgs extracts the value of a --config / --config= occurrence,
// stopping at the "--" separator that ends flag parsing. ok is false when no
// --config appears; a dangling --config is left for cobra to reject.
func configPathFromArgs(args []string) (path string, ok bool) {
	for i := 0; i < len(args); i++ {
		switch arg := args[i]; {
		case arg == "--":
			return "", false
		case arg == "--config":
			if i+1 < len(args) {
				return args[i+1], true
			}
			return "", false
		case strings.HasPrefix(arg, "--config="):
			return strings.TrimPrefix(arg, "--config="), true
		}
	}
	return "", false
}

// applyFileConfig seeds the flag variables from a parsed config file. Nil
// fields were absent from the file and leave the flag defaults untouched.
func applyFileConfig(fc *config.FileConfig) {
	if fc == nil {
		return
	}
	if fc.Log != nil {
		flagLogLevel = *fc.Log
	}
	if fc.Bind != nil {
		flagBind = *fc.Bind
	}
	if fc.Concurrent != nil {
		flagConcurrent = *fc.Concurrent
	}
	if fc.Workers != nil {
		flagWorkers = *fc.Workers
	}
	if fc.CIDR != nil {
		flagCIDR = *fc.CIDR
	}
	if fc.CIDRRange != nil {
		flagCIDRRange = *fc.CIDRRange
	}
	if fc.Fallback != nil {
		flagFallback = *fc.Fallback
	}
	if fc.ConnectTimeout != nil {
		flagConnectTimeout = *fc.ConnectTimeout
	}
	if fc.TCPUserTimeout != nil {
		flagTCPUserTimeout = *fc.TCPUserTimeout
	}
	if fc.ReuseAddr != nil {
		flagReuseAddr = *fc.ReuseAddr
	}
	if fc.MaxPendingDials != nil {
		flagMaxPendingDials = *fc.MaxPendingDials
	}
	if fc.ReusePort != nil {
		flagReusePort = *fc.ReusePort
	}
	if fc.SessionSpread != nil {
		flagSessionSpread = *fc.SessionSpread
	}
	if fc.StrictSource != nil {
		flagStrictSource = *fc.StrictSource
	}
	if fc.NDPProxy != nil {
		flagNDPProxy = *fc.NDPProxy
	}
	if fc.NDPProxyMax != nil {
		flagNDPProxyMax = *fc.NDPProxyMax
	}
	if fc.Diagnostics != nil {
		flagDiagnostics = *fc.Diagnostics
	}
	if fc.Username != nil {
		flagUsername = *fc.Username
	}
	if fc.Password != nil {
		flagPassword = *fc.Password
	}
	if fc.TLSCert != nil {
		flagTLSCert = *fc.TLSCert
	}
	if fc.TLSKey != nil {
		flagTLSKey = *fc.TLSKey
	}
	if u := fc.UDP; u != nil {
		if u.MaxPacketSize != nil {
			flagUDPMaxPacketSize = *u.MaxPacketSize
		}
		if u.BatchSize != nil {
			flagUDPBatchSize = *u.BatchSize
		}
		if u.BatchBufferBudget != nil {
			flagUDPBatchBufferBudget = *u.BatchBufferBudget
		}
		if u.SendQueueSize != nil {
			flagUDPSendQueueSize = *u.SendQueueSize
		}
		if u.SendWorkers != nil {
			flagUDPSendWorkers = *u.SendWorkers
		}
		if u.SocketBufferBytes != nil {
			flagUDPSocketBuffer = *u.SocketBufferBytes
		}
		if u.GSO != nil {
			flagUDPGSO = *u.GSO
		}
		if u.GRO != nil {
			flagUDPGRO = *u.GRO
		}
		if u.MaxAssociations != nil {
			flagUDPMaxAssociations = *u.MaxAssociations
		}
		if u.MetricsIntervalSecs != nil {
			flagUDPMetricsInterval = *u.MetricsIntervalSecs
		}
		if u.AssociationIdleTimeoutSecs != nil {
			flagUDPAssociationIdleTime = *u.AssociationIdleTimeoutSecs
		}
	}
}

// newProxyCommand creates a run or systemd configuration command with BootArgs flags
// and proxy subcommands (http/https/socks5/auto).
func newProxyCommand(use, short string, exec func(cmd *cobra.Command, args []string) error) *cobra.Command {
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
	}
	addBootArgsFlags(cmd)

	// http subcommand.
	httpCmd := &cobra.Command{
		Use:   "http",
		Short: "HTTP server",
		RunE:  exec,
	}
	addAuthFlags(httpCmd)
	cmd.AddCommand(httpCmd)

	// https subcommand.
	httpsCmd := &cobra.Command{
		Use:   "https",
		Short: "HTTPS server",
		RunE:  exec,
	}
	addAuthFlags(httpsCmd)
	addTLSFlags(httpsCmd)
	cmd.AddCommand(httpsCmd)

	// socks5 subcommand.
	socks5Cmd := &cobra.Command{
		Use:   "socks5",
		Short: "SOCKS5 server",
		RunE:  exec,
	}
	addAuthFlags(socks5Cmd)
	cmd.AddCommand(socks5Cmd)

	// masque subcommand.
	masqueCmd := &cobra.Command{
		Use:     "masque",
		Aliases: []string{"quic"},
		Short:   "HTTP/3 CONNECT-UDP (MASQUE) server",
		RunE:    exec,
	}
	addAuthFlags(masqueCmd)
	addTLSFlags(masqueCmd)
	cmd.AddCommand(masqueCmd)

	// auto subcommand.
	autoCmd := &cobra.Command{
		Use:   "auto",
		Short: "Auto detect server (SOCKS5, HTTP, HTTPS)",
		RunE:  exec,
	}
	addAuthFlags(autoCmd)
	addTLSFlags(autoCmd)
	cmd.AddCommand(autoCmd)

	return cmd
}

// addBootArgsFlags adds the shared BootArgs flags to a command as persistent
// flags.
func addBootArgsFlags(cmd *cobra.Command) {
	pf := cmd.PersistentFlags()
	pf.StringVarP(&flagLogLevel, "log", "L", "info", "Log level (trace / debug / info / warn / error)")
	pf.StringVarP(&flagBind, "bind", "b", "127.0.0.1:1080", "Bind address (listen endpoint)")
	pf.Uint32VarP(&flagConcurrent, "concurrent", "c", 8192, "Maximum concurrent active connections")
	pf.IntVarP(&flagWorkers, "workers", "w", 0, "Worker thread count (default: number of logical CPU cores)")
	pf.StringVarP(&flagCIDR, "cidr", "i", "", "Base CIDR block for outbound source address selection")
	pf.Uint8VarP(&flagCIDRRange, "cidr-range", "r", 0, "Sub-range bit width (CIDR range extension)")
	pf.StringVarP(&flagFallback, "fallback", "f", "", "Fallback local source address or interface name")
	pf.Uint64VarP(&flagConnectTimeout, "connect-timeout", "t", 10, "Outbound connection timeout (seconds)")
	pf.BoolVar(&flagReuseAddr, "reuseaddr", true, "Outbound SO_REUSEADDR for TCP sockets")
	pf.IntVar(&flagMaxPendingDials, "max-pending-dials", config.DefaultMaxPendingDials, "Maximum concurrent outbound TCP dials (0: unlimited)")
	pf.BoolVar(&flagReusePort, "reuse-port", false, "Shard the listener with SO_REUSEPORT across accept loops (Linux/BSD)")
	pf.BoolVar(&flagSessionSpread, "session-spread", false, "Spread session/TTL extensions over every host bit of the CIDR with a strong mixer (remaps existing sessions)")
	pf.BoolVar(&flagStrictSource, "strict-source", false, "Never race or fall back away from the CIDR source for targets that have an address in its family")
	pf.StringVar(&flagNDPProxy, "ndp-proxy", "", "Install proxy-NDP entries on this interface for chosen IPv6 source addresses (Linux only)")
	pf.IntVar(&flagNDPProxyMax, "ndp-proxy-max", config.DefaultNDPProxyMax, "Maximum proxy-NDP entries kept installed (least recently used are removed)")
	pf.StringVar(&flagDiagnostics, "diagnostics", "", "Diagnostic HTTP bind address for metrics and pprof (empty: disabled)")
	pf.StringVar(&flagConfigFile, "config", "", "YAML config file providing defaults for unset flags")
	pf.IntVar(&flagUDPMaxPacketSize, "udp-max-packet-size", config.DefaultUDPMaxPacketSize, "Maximum SOCKS5 UDP relay datagram size")
	pf.IntVar(&flagUDPBatchSize, "udp-batch-size", config.DefaultUDPBatchSize, "UDP packets per receive/send batch (Linux uses recvmmsg/sendmmsg)")
	pf.IntVar(&flagUDPBatchBufferBudget, "udp-batch-buffer-budget", config.DefaultUDPBatchBufferBudget, "Maximum extra pooled buffers held by concurrent Linux UDP batches (0: scalar reads)")
	pf.IntVar(&flagUDPSendQueueSize, "udp-send-queue", config.DefaultUDPSendQueueSize, "Global queued UDP packets awaiting outbound send")
	pf.IntVar(&flagUDPSendWorkers, "udp-send-workers", 0, "UDP outbound send workers (0: automatic)")
	pf.IntVar(&flagUDPSocketBuffer, "udp-socket-buffer", 0, "SO_RCVBUF/SO_SNDBUF for UDP relay sockets in bytes (0: system default)")
	pf.BoolVar(&flagUDPGSO, "udp-gso", false, "Enable Linux UDP_SEGMENT (GSO) batching for same-target uniform-size sends")
	pf.BoolVar(&flagUDPGRO, "udp-gro", false, "Enable Linux UDP_GRO coalescing of received datagrams on the relay sockets")
	pf.Uint32Var(&flagUDPMaxAssociations, "udp-associations", 0, "Maximum active UDP associations (0: inherit --concurrent)")
	pf.Uint64Var(&flagUDPMetricsInterval, "udp-metrics-interval", config.DefaultUDPMetricsIntervalSecs, "UDP metrics log interval in seconds (0: disabled)")
	pf.Uint64Var(&flagUDPAssociationIdleTime, "udp-association-idle-timeout", 0, "Close idle UDP associations after this many seconds (0: disabled)")
	if runtime.GOOS == "linux" {
		pf.Uint64Var(&flagTCPUserTimeout, "tcp-user-timeout", 30, "Outbound TCP sockets user timeout (seconds, Linux only)")
	}
}

// addAuthFlags adds the authentication flags to a proxy subcommand.
func addAuthFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&flagUsername, "username", "u", "", "Authentication username")
	cmd.Flags().StringVarP(&flagPassword, "password", "p", "", "Authentication password")
}

// addTLSFlags adds the TLS certificate/key flags to a proxy subcommand.
func addTLSFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&flagTLSCert, "tls-cert", "", "TLS certificate file")
	cmd.Flags().StringVar(&flagTLSKey, "tls-key", "", "TLS private key file")
}

// buildBootArgs constructs a config.BootArgs from the parsed flags and the
// proxy subcommand name.
func buildBootArgs(proxyName string) (config.BootArgs, error) {
	bind, err := netip.ParseAddrPort(flagBind)
	if err != nil {
		return config.BootArgs{}, fmt.Errorf("invalid bind address %q: %w", flagBind, err)
	}

	args := config.BootArgs{
		LogLevel:        config.ParseLogLevel(flagLogLevel),
		Bind:            bind,
		Concurrent:      flagConcurrent,
		Workers:         flagWorkers,
		ConnectTimeout:  flagConnectTimeout,
		ReuseAddr:       &flagReuseAddr,
		MaxPendingDials: flagMaxPendingDials,
		ReusePort:       flagReusePort,
		SessionSpread:   flagSessionSpread,
		StrictSource:    flagStrictSource,
		NDPProxy:        flagNDPProxy,
		NDPProxyMax:     flagNDPProxyMax,
		UDP: config.UDPConfig{
			MaxPacketSize:              flagUDPMaxPacketSize,
			BatchSize:                  flagUDPBatchSize,
			BatchBufferBudget:          flagUDPBatchBufferBudget,
			SendQueueSize:              flagUDPSendQueueSize,
			SendWorkers:                flagUDPSendWorkers,
			SocketBufferBytes:          flagUDPSocketBuffer,
			MaxAssociations:            flagUDPMaxAssociations,
			MetricsIntervalSecs:        flagUDPMetricsInterval,
			AssociationIdleTimeoutSecs: flagUDPAssociationIdleTime,
			GSO:                        flagUDPGSO,
			GRO:                        flagUDPGRO,
		},
		Proxy: config.ProxyConfig{
			Auth: config.AuthMode{
				Username: flagUsername,
				Password: flagPassword,
			},
		},
	}

	if flagDiagnostics != "" {
		diagnostics, err := netip.ParseAddrPort(flagDiagnostics)
		if err != nil {
			return config.BootArgs{}, fmt.Errorf("invalid diagnostics address %q: %w", flagDiagnostics, err)
		}
		args.Diagnostics = &diagnostics
	}

	if flagCIDR != "" {
		cidr, err := netip.ParsePrefix(flagCIDR)
		if err != nil {
			return config.BootArgs{}, fmt.Errorf("invalid CIDR %q: %w", flagCIDR, err)
		}
		args.CIDR = &cidr
		if flagCIDRRange > 0 {
			r := flagCIDRRange
			args.CIDRRange = &r
		}
	}

	if flagFallback != "" {
		fb, err := config.ParseFallback(flagFallback)
		if err != nil {
			return config.BootArgs{}, fmt.Errorf("invalid fallback %q: %w", flagFallback, err)
		}
		args.Fallback = &fb
	}

	if runtime.GOOS == "linux" {
		t := flagTCPUserTimeout
		args.TCPUserTimeout = &t
	}

	switch proxyName {
	case "http":
		args.Proxy.Kind = config.ProxyHTTP
	case "https":
		args.Proxy.Kind = config.ProxyHTTPS
		args.Proxy.TLSCert = flagTLSCert
		args.Proxy.TLSKey = flagTLSKey
	case "socks5":
		args.Proxy.Kind = config.ProxySocks5
	case "masque", "quic":
		args.Proxy.Kind = config.ProxyMASQUE
		args.Proxy.TLSCert = flagTLSCert
		args.Proxy.TLSKey = flagTLSKey
	case "auto":
		args.Proxy.Kind = config.ProxyAuto
		args.Proxy.TLSCert = flagTLSCert
		args.Proxy.TLSKey = flagTLSKey
	default:
		return config.BootArgs{}, fmt.Errorf("unknown proxy type %q", proxyName)
	}

	if err := args.Validate(); err != nil {
		return config.BootArgs{}, err
	}
	return args, nil
}

// proxyNameFromArgs extracts the proxy subcommand name from the command path.
func proxyNameFromArgs(cmd *cobra.Command) string {
	// The proxy name is the last command in the path: "run http" -> "http".
	parts := strings.Fields(cmd.CommandPath())
	if len(parts) >= 2 {
		return parts[len(parts)-1]
	}
	return ""
}

// execRun executes the "run" command: build BootArgs and call server.Run.
func execRun(cmd *cobra.Command, _ []string) error {
	proxyName := proxyNameFromArgs(cmd)
	args, err := buildBootArgs(proxyName)
	if err != nil {
		return err
	}
	return server.Run(args)
}

// systemdServiceArgs validates the server settings and returns the arguments
// that should follow "outway run" in ExecStart.
func systemdServiceArgs(cmd *cobra.Command) (config.BootArgs, []string, error) {
	args, err := buildBootArgs(proxyNameFromArgs(cmd))
	if err != nil {
		return config.BootArgs{}, nil, err
	}
	return args, buildRunArgsFromOSArgs(), nil
}

func execSystemdInstall(cmd *cobra.Command, _ []string) error {
	args, runArgs, err := systemdServiceArgs(cmd)
	if err != nil {
		return err
	}
	return systemdInstall(args, runArgs)
}

func execSystemdEnable(cmd *cobra.Command, _ []string) error {
	args, runArgs, err := systemdServiceArgs(cmd)
	if err != nil {
		return err
	}
	return systemdEnable(args, runArgs)
}

func execSystemdStart(cmd *cobra.Command, _ []string) error {
	args, runArgs, err := systemdServiceArgs(cmd)
	if err != nil {
		return err
	}
	return systemdStart(args, runArgs)
}

func execSystemdRestart(cmd *cobra.Command, _ []string) error {
	args, runArgs, err := systemdServiceArgs(cmd)
	if err != nil {
		return err
	}
	return systemdRestart(args, runArgs)
}

func execSystemdStop(*cobra.Command, []string) error   { return systemdStop() }
func execSystemdStatus(*cobra.Command, []string) error { return systemdStatus() }
func execSystemdLogs(*cobra.Command, []string) error   { return systemdLogs() }

// execSelfUpdate executes the "self update" command.
func execSelfUpdate(cmd *cobra.Command, _ []string) error {
	return oneself.Update()
}

// execSelfUninstall executes the "self uninstall" command.
func execSelfUninstall(cmd *cobra.Command, _ []string) error {
	return oneself.Uninstall()
}

// buildRunArgsFromOSArgs builds the ExecStart arguments from
// "outway systemd <action> ..." by replacing the management prefix with "run".
func buildRunArgsFromOSArgs() []string {
	args := make([]string, 0, len(os.Args)-2)
	args = append(args, "run")
	if len(os.Args) > 3 {
		args = append(args, os.Args[3:]...)
	}
	return args
}
