// Package main is the outway command-line entry point. It wires up the CLI
// commands (run, start, restart, stop, ps, log, self) to the server, daemon,
// and self-update modules.
package main

import (
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/xiaozhou26/outway/internal/config"
	"github.com/xiaozhou26/outway/internal/daemon"
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
)

func main() {
	rootCmd := &cobra.Command{
		Use:           "outway",
		Short:         "A high-performance HTTP/HTTPS/SOCKS5 proxy server",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// run command and its proxy subcommands.
	runCmd := newProxyCommand("run", "Run server", execRun)
	rootCmd.AddCommand(runCmd)

	// Unix-only daemon commands.
	if runtime.GOOS != "windows" {
		startCmd := newProxyCommand("start", "Start server daemon", execStart)
		restartCmd := newProxyCommand("restart", "Restart server daemon", execRestart)
		rootCmd.AddCommand(startCmd, restartCmd)

		rootCmd.AddCommand(
			&cobra.Command{Use: "stop", Short: "Stop server daemon", RunE: execStop},
			&cobra.Command{Use: "ps", Short: "Show server daemon process", RunE: execPS},
			&cobra.Command{Use: "log", Short: "Show server daemon log", RunE: execLog},
		)
	}

	// self command.
	selfCmd := &cobra.Command{Use: "self", Short: "Modify server installation"}
	selfCmd.AddCommand(
		&cobra.Command{Use: "update", Short: "Download and install updates", RunE: execSelfUpdate},
		&cobra.Command{Use: "uninstall", Short: "Uninstall proxy server", RunE: execSelfUninstall},
	)
	rootCmd.AddCommand(selfCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// newProxyCommand creates a command (run/start/restart) with BootArgs flags
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
		LogLevel:       config.ParseLogLevel(flagLogLevel),
		Bind:           bind,
		Concurrent:     flagConcurrent,
		Workers:        flagWorkers,
		ConnectTimeout: flagConnectTimeout,
		ReuseAddr:      &flagReuseAddr,
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

// execStart executes the "start" command: re-exec with "run" in daemon mode.
func execStart(cmd *cobra.Command, _ []string) error {
	if _, err := buildBootArgs(proxyNameFromArgs(cmd)); err != nil {
		return err
	}
	runArgs := buildRunArgsFromOSArgs("start")
	return daemon.Default().Start(runArgs)
}

// execRestart executes the "restart" command: stop then start in daemon mode.
func execRestart(cmd *cobra.Command, _ []string) error {
	if _, err := buildBootArgs(proxyNameFromArgs(cmd)); err != nil {
		return err
	}
	runArgs := buildRunArgsFromOSArgs("restart")
	return daemon.Default().Restart(runArgs)
}

// execStop executes the "stop" command.
func execStop(cmd *cobra.Command, _ []string) error {
	return daemon.Default().Stop()
}

// execPS executes the "ps" command.
func execPS(cmd *cobra.Command, _ []string) error {
	return daemon.Default().Status()
}

// execLog executes the "log" command.
func execLog(cmd *cobra.Command, _ []string) error {
	return daemon.Default().Log()
}

// execSelfUpdate executes the "self update" command.
func execSelfUpdate(cmd *cobra.Command, _ []string) error {
	return oneself.Update()
}

// execSelfUninstall executes the "self uninstall" command.
func execSelfUninstall(cmd *cobra.Command, _ []string) error {
	return oneself.Uninstall()
}

// buildRunArgsFromOSArgs builds the args for re-executing the binary with the
// "run" subcommand by replacing the command name in os.Args.
func buildRunArgsFromOSArgs(cmdName string) []string {
	// os.Args[0] is the program name, os.Args[1] is the command name (e.g.
	// "start" or "restart"), and the rest are the command args.
	args := make([]string, 0, len(os.Args)-1)
	args = append(args, "run")
	if len(os.Args) > 2 {
		args = append(args, os.Args[2:]...)
	}
	return args
}
