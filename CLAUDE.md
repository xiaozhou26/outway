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

### SOCKS5 UDP relay

`internal/server/socks` contains a high-concurrency UDP ASSOCIATE relay tuned for large proxy pools. The moving parts:

- **`udpRuntime` (`udp_runtime.go`)** — one per acceptor, shared across all associations. Owns the pooled packet buffers (`sync.Pool`, sized `MaxPacketSize + header`), the association-count limiter, structured metrics, and a sharded pool of outbound **send workers**. `dispatch()` is lock-free: shard channels are never closed and workers exit via the lifetime context.
- **Per-association goroutines (`handleUDP` in `server.go`)** — an inbound reader (client→proxy), one or two outbound response readers (target→proxy, dual-stack), and a TCP-control-connection watcher. The main loop drains inbound packets, authorizes by source IP, and sends.
- **Two send directions.** Client→target: literal-IP targets are grouped by address family and flushed with one `sendmmsg` per outbound socket directly on the association goroutine; **domain** targets go through the shared send-worker pool so a cold DNS lookup never blocks the loop. Target→client (`relayUDPResponses`): batched reads, SOCKS5-header framing, batched writes.
- **Batch I/O (`udp_io_linux.go`)** — on Linux the reader uses `recvmmsg` and the writer `sendmmsg`; other platforms fall back to scalar `ReadMsgUDP`/`WriteToUDP` (`udp_io_other.go`). `udp_io.go` holds the shared `udpReadPacket`/`udpWritePacket` types and interfaces.
- **Optional offloads (Linux, opt-in, off by default).** `--udp-gso` (`udp_gso_linux.go`) coalesces a same-target uniform-size batch into one `UDP_SEGMENT` send; `--udp-gro` (`udp_gro_linux.go`) enables `UDP_GRO` so a coalesced read is split back into individual packets. Both have `_other.go`/build-tag stubs and probe kernel support once.
- **Buffer lifecycle invariant** — exactly one pooled buffer per in-flight datagram, released once (via `releaseInboundPacket`/`releaseReadPacket`/`releaseBuffer`). GRO preserves this by copying split segments into their own pooled buffers rather than sharing one. Any change to the read/send path must keep the release count matched to the acquire count, or the pool corrupts.

The `config.UDPConfig` fields map 1:1 to the `--udp-*` flags; `MaxPacketSize` also bounds per-buffer memory, so small-packet pools (DNS/QUIC) can lower it to save RAM.

### Platform-specific files

Several concerns split by build constraint (`_linux.go` / `_unix.go` / `_windows.go` / `_other.go`):
- `internal/server/route_linux.go` configures policy routing for the CIDR (no-op elsewhere via the `configureRoutes` function variable in `run.go`).
- `internal/connect/sockopts_*.go` sets socket options (SO_REUSEADDR, TCP user timeout).
- `internal/daemon/daemon_*.go` — daemon management is Unix-only; Windows builds omit the daemon lifecycle commands (gated in `main.go` by `runtime.GOOS`).

When touching connection setup, routing, or daemonization, check for a sibling file under another build tag and keep the platform variants in sync.

### Self-update

`internal/oneself` downloads release assets from GitHub (`repoOwner`/`repoName` constants) and replaces the running executable. It maps Go's `GOOS`/`GOARCH` to Rust-style target triples (e.g. `x86_64-unknown-linux-gnu`) to match the release asset naming from the upstream Rust project.
