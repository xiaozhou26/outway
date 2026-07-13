package server

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/xiaozhou26/outway/internal/config"
	"github.com/xiaozhou26/outway/internal/connect"
	httpsvr "github.com/xiaozhou26/outway/internal/server/http"
	"github.com/xiaozhou26/outway/internal/server/socks"
)

// Run starts the proxy server with the provided boot arguments and blocks
// until the server shuts down (via error or Ctrl-C).
func Run(args config.BootArgs) error {
	if err := args.Validate(); err != nil {
		return err
	}

	// Initialize the logger.
	level := parseSlogLevel(args.LogLevel)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)
	connect.SetLogger(logger)

	workers := args.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	runtime.GOMAXPROCS(workers)

	slog.Info(fmt.Sprintf("OS: %s", runtime.GOOS))
	slog.Info(fmt.Sprintf("Arch: %s", runtime.GOARCH))
	slog.Info(fmt.Sprintf("Concurrent: %d", args.Concurrent))
	slog.Info(fmt.Sprintf("Worker threads: %d", workers))
	slog.Info(fmt.Sprintf("Connect timeout: %ds", args.ConnectTimeout))
	slog.Info("UDP relay resources",
		"max_packet_size", args.UDP.MaxPacketSize,
		"batch_size", args.UDP.BatchSize,
		"batch_buffer_budget", args.UDP.BatchBufferBudget,
		"send_queue", args.UDP.SendQueueSize,
		"send_workers", args.UDP.SendWorkers,
		"socket_buffer_bytes", args.UDP.SocketBufferBytes,
		"max_associations", args.UDP.MaxAssociations,
		"idle_timeout_seconds", args.UDP.AssociationIdleTimeoutSecs,
	)
	warnIfUDPBufferClamped(args)
	if err := prepareResourceLimits(args); err != nil {
		return err
	}

	// On Linux, configure routes and sysctls for the CIDR.
	if cidr := args.CIDR; cidr != nil {
		if err := configureRoutes(*cidr); err != nil {
			return fmt.Errorf("configure source CIDR %s: %w", cidr, err)
		}
		if err := validateSourceCIDR(*cidr); err != nil {
			return fmt.Errorf("validate source CIDR %s: %w", cidr, err)
		}
	}

	// Build the connector.
	connector := connect.New(
		args.CIDR,
		args.CIDRRange,
		args.Fallback,
		args.ConnectTimeout,
		args.TCPUserTimeout,
		args.ReuseAddr,
	)

	// Build the context.
	ctx := Context{
		Bind:           args.Bind,
		Concurrent:     args.Concurrent,
		ConnectTimeout: args.ConnectTimeout,
		Auth:           args.Proxy.Auth,
		Connector:      connector,
		UDP:            args.UDP,
	}

	srv, err := newProxyServer(args.Proxy, ctx)
	if err != nil {
		return err
	}

	// Set up signal handling for graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start()
	}()

	select {
	case err := <-errCh:
		return err
	case sig := <-sigCh:
		slog.Info(fmt.Sprintf("Shutdown signal received (%v), shutting down gracefully...", sig))
		closeErr := srv.Close()
		serveErr := <-errCh
		return errors.Join(closeErr, serveErr)
	}
}

type proxyServer interface {
	Start() error
	Close() error
}

// newProxyServer constructs the appropriate proxy server based on the proxy
// config. Construction happens before the serve goroutine so Run retains a
// handle that can be closed during shutdown.
func newProxyServer(proxy config.ProxyConfig, ctx Context) (proxyServer, error) {
	switch proxy.Kind {
	case config.ProxyHTTP:
		return httpsvr.NewServer(ctx)
	case config.ProxyHTTPS:
		srv, err := httpsvr.NewServer(ctx)
		if err != nil {
			return nil, err
		}
		if _, err := srv.WithHTTPS(proxy.TLSCert, proxy.TLSKey); err != nil {
			_ = srv.Close()
			return nil, err
		}
		return srv, nil
	case config.ProxySocks5:
		return socks.NewServer(ctx)
	case config.ProxyAuto:
		return NewAutoDetectServer(ctx, proxy.TLSCert, proxy.TLSKey)
	default:
		return nil, fmt.Errorf("unknown proxy kind: %d", proxy.Kind)
	}
}

// parseSlogLevel converts a string log level to a slog.Level.
func parseSlogLevel(s string) slog.Level {
	switch s {
	case "trace", "debug", "DEBUG":
		return slog.LevelDebug
	case "info", "INFO":
		return slog.LevelInfo
	case "warn", "WARN":
		return slog.LevelWarn
	case "error", "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// configureRoutes is implemented in route_linux.go / route_other.go.
// It receives the CIDR prefix to configure.
var configureRoutes = func(cidr netip.Prefix) error { return nil }

// validateSourceCIDR is implemented on Linux and is a no-op elsewhere.
var validateSourceCIDR = func(cidr netip.Prefix) error { return nil }

// prepareResourceLimits is implemented on Unix and is a no-op elsewhere.
var prepareResourceLimits = func(args config.BootArgs) error { return nil }

// warnIfUDPBufferClamped probes whether the requested UDP socket buffer can be
// honored and warns once at startup if the kernel clamps it. The buffer is only
// used by the SOCKS5 UDP relay, so the check is skipped for HTTP-only proxies.
func warnIfUDPBufferClamped(args config.BootArgs) {
	if args.UDP.SocketBufferBytes <= 0 {
		return
	}
	if args.Proxy.Kind != config.ProxySocks5 && args.Proxy.Kind != config.ProxyAuto {
		return
	}
	applied, clamped, ok := connect.VerifyUDPBufferTuning(args.UDP.SocketBufferBytes)
	if ok && clamped {
		slog.Warn("Requested UDP socket buffer was clamped by the kernel; raise net.core.rmem_max and net.core.wmem_max, or run with CAP_NET_ADMIN",
			"requested_bytes", args.UDP.SocketBufferBytes,
			"granted_bytes", applied,
		)
	}
}
