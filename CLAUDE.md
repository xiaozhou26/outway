# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a high-performance HTTP/HTTPS/SOCKS5 proxy server written in Go, ported from a Rust implementation (several modules carry "mirrors the Rust ..." comments). The module path is `github.com/xiaozhou26/outway` and the binary is `outway`.

## Commands

```
go build ./...          # Build all packages
go build -o outway .    # Build the binary
go test ./...           # Run all tests
go test ./internal/connect/   # Test a single package
go test -run TestName ./internal/ext/   # Run a single test
go vet ./...            # Vet all packages
go mod tidy             # Sync dependencies
```

Version is injected at build time via ldflags:

```
go build -ldflags "-X github.com/xiaozhou26/outway/internal/oneself.currentVersion=x.y.z" -o outway .
```

## Running

The CLI is structured as `<lifecycle> <protocol>`:

- Lifecycle commands: `run` (foreground), and on non-Windows `start` / `restart` / `stop` / `ps` / `log` (daemon management).
- Protocol subcommands under each: `http`, `https`, `socks5`, `auto`.
- `self update` / `self uninstall` manage the installed binary.

Example: `outway run auto -b 127.0.0.1:1080 -u user -p pass`

## Architecture

The request flow is: **CLI (main.go) → BootArgs (config) → server.Run → protocol server → Handler → Connector → outbound**.

### Configuration boundary

`main.go` parses cobra flags into a `config.BootArgs`. This is the single hand-off from CLI to the rest of the system — `server.Run(args)` is the entry point. Nothing below `main.go` knows about cobra or flags.

### Protocol auto-detection

`internal/server/auto.go` is the most distinctive piece. `AutoDetectServer` listens on ONE port and peeks the first byte of each connection to route it:
- `0x05` → SOCKS5
- `< 0x41` → HTTPS (TLS records start with a binary byte below the ASCII letter range)
- `>= 0x41` → HTTP (ASCII request methods like `GET`, `CONNECT`)

The peeked byte must not be lost, so connections are wrapped in `bufferedConn` (a `net.Conn` whose `Read` is backed by the `bufio.Reader` used for peeking). Any change to the dispatch logic must preserve this wrapping.

### serverbase breaks an import cycle

`internal/serverbase` holds `Context` (shared runtime state: bind address, auth, connector) and the bidirectional-copy helpers. It exists specifically so that the `server`, `server/http`, and `server/socks` packages can share types without a cycle. When adding shared server state, put it here — not in `server`, which imports the protocol subpackages.

### The Connector and username extensions

`internal/connect` establishes all outbound connections and owns source-address selection policy. The notable feature: outbound source IPs can be chosen per-connection from a CIDR block based on "extensions" parsed out of the proxy username (`internal/ext`). A username like `user-session-abc` or `user-ttl-60` is parsed (`ext.TryFrom`) into an `Extension`, which is hashed (FxHash64, matching the Rust implementation's hash exactly) to deterministically pick a source address within the configured CIDR. Authenticators (`http/auth.go`, `socks/auth.go`) return the parsed `Extension`, which flows into `connector.TCP(extension)` / `.UDP(extension)`. This is why auth and connection establishment are coupled — the username carries routing information, not just credentials.

### Platform-specific files

Several concerns split by build constraint (`_linux.go` / `_unix.go` / `_windows.go` / `_other.go`):
- `internal/server/route_linux.go` configures policy routing for the CIDR (no-op elsewhere via the `configureRoutes` function variable in `run.go`).
- `internal/connect/sockopts_*.go` sets socket options (SO_REUSEADDR, TCP user timeout).
- `internal/daemon/daemon_*.go` — daemon management is Unix-only; Windows builds omit the daemon lifecycle commands (gated in `main.go` by `runtime.GOOS`).

When touching connection setup, routing, or daemonization, check for a sibling file under another build tag and keep the platform variants in sync.

### Self-update

`internal/oneself` downloads release assets from GitHub (`repoOwner`/`repoName` constants) and replaces the running executable. It maps Go's `GOOS`/`GOARCH` to Rust-style target triples (e.g. `x86_64-unknown-linux-gnu`) to match the release asset naming from the upstream Rust project.
