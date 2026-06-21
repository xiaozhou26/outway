# outway

A high-performance HTTP/HTTPS/SOCKS5 proxy server written in Go, with per-connection outbound source-address selection driven by proxy-username extensions.

## Features

- **Multiple protocols** — HTTP, HTTPS, and SOCKS5 proxying.
- **Auto-detection** — a single port can serve SOCKS5, HTTP, and HTTPS simultaneously, dispatching each connection by inspecting its first byte.
- **CIDR-based source selection** — bind outbound connections to addresses chosen from a configured CIDR block, selected deterministically per session/TTL/range via username extensions.
- **Authentication** — optional username/password (Basic auth for HTTP, username/password auth for SOCKS5).
- **Daemon management** — start, stop, restart, status, and log commands (Unix).
- **Self-update** — download and install the latest release directly from GitHub.

## Installation

```
go install github.com/xiaozhou26/outway@latest
```

Or build from source:

```
git clone https://github.com/xiaozhou26/outway.git
cd outway
go build -o outway .
```

## Usage

Commands follow a `<lifecycle> <protocol>` structure:

```
outway run http        # Run an HTTP proxy in the foreground
outway run https       # HTTPS proxy (self-signed cert if none provided)
outway run socks5      # SOCKS5 proxy
outway run auto        # Serve SOCKS5/HTTP/HTTPS on one port
```

Example with bind address and authentication:

```
outway run auto -b 127.0.0.1:1080 -u user -p pass
```

### Daemon (Unix)

```
outway start auto -b 127.0.0.1:1080   # Start in the background
outway ps                              # Show daemon status
outway log                             # Show daemon log
outway restart auto -b 127.0.0.1:1080  # Restart
outway stop                            # Stop
```

### Self-management

```
outway self update      # Update to the latest release
outway self uninstall   # Remove the installed binary
```

## Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--log` | `-L` | `info` | Log level (trace / debug / info / warn / error) |
| `--bind` | `-b` | `127.0.0.1:1080` | Bind address (listen endpoint) |
| `--concurrent` | `-c` | `1024` | Maximum concurrent active connections |
| `--workers` | `-w` | CPU cores | Worker thread count |
| `--cidr` | `-i` | | Base CIDR block for outbound source selection |
| `--cidr-range` | `-r` | `0` | Sub-range bit width (CIDR range extension) |
| `--fallback` | `-f` | | Fallback local source address or interface name |
| `--connect-timeout` | `-t` | `10` | Outbound connection timeout (seconds) |
| `--reuseaddr` | | `true` | Outbound `SO_REUSEADDR` for TCP sockets |
| `--tcp-user-timeout` | | `30` | Outbound TCP user timeout (seconds, Linux only) |
| `--username` | `-u` | | Authentication username |
| `--password` | `-p` | | Authentication password |
| `--tls-cert` | | | TLS certificate file (https/auto) |
| `--tls-key` | | | TLS private key file (https/auto) |

## Username extensions

When a base CIDR is configured, the outbound source address can be selected per connection by encoding an extension into the proxy username:

- `<user>-session-<id>` — sticky source address per session id.
- `<user>-ttl-<seconds>` — source address rotates on a fixed time window.
- `<user>-range-<value>` — source address chosen within a sub-range of the CIDR.

The extension value is hashed deterministically to pick an address inside the configured CIDR block.

## License

See the repository for license details.

Inspired by [vproxy](https://github.com/vproxy-tools/vproxy) — a high-performance transparent proxy solution.
