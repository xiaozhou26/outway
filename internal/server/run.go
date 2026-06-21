package server

import (
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
	// Initialize the logger.
	level := parseSlogLevel(args.LogLevel)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)
	connect.SetLogger(logger)

	workers := args.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}

	slog.Info(fmt.Sprintf("OS: %s", runtime.GOOS))
	slog.Info(fmt.Sprintf("Arch: %s", runtime.GOARCH))
	slog.Info(fmt.Sprintf("Concurrent: %d", args.Concurrent))
	slog.Info(fmt.Sprintf("Worker threads: %d", workers))
	slog.Info(fmt.Sprintf("Connect timeout: %ds", args.ConnectTimeout))

	// On Linux, configure routes and sysctls for the CIDR.
	if cidr := args.CIDR; cidr != nil {
		configureRoutes(*cidr)
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
	}

	// Set up signal handling for graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		errCh <- startProxy(args.Proxy, ctx)
	}()

	select {
	case err := <-errCh:
		return err
	case sig := <-sigCh:
		slog.Info(fmt.Sprintf("Shutdown signal received (%v), shutting down gracefully...", sig))
		return nil
	}
}

// startProxy starts the appropriate proxy server based on the proxy config.
func startProxy(proxy config.ProxyConfig, ctx Context) error {
	switch proxy.Kind {
	case config.ProxyHTTP:
		srv, err := httpsvr.NewServer(ctx)
		if err != nil {
			return err
		}
		return srv.Start()
	case config.ProxyHTTPS:
		srv, err := httpsvr.NewServer(ctx)
		if err != nil {
			return err
		}
		if _, err := srv.WithHTTPS(proxy.TLSCert, proxy.TLSKey); err != nil {
			return err
		}
		return srv.Start()
	case config.ProxySocks5:
		srv, err := socks.NewServer(ctx)
		if err != nil {
			return err
		}
		return srv.Start()
	case config.ProxyAuto:
		srv, err := NewAutoDetectServer(ctx, proxy.TLSCert, proxy.TLSKey)
		if err != nil {
			return err
		}
		return srv.Start()
	default:
		return fmt.Errorf("unknown proxy kind: %d", proxy.Kind)
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
var configureRoutes = func(cidr netip.Prefix) {}
