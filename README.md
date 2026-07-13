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

### High-concurrency IPv6 CIDR example

```bash
sudo ./outway start -i 2604:2dc0:20e:4700::/56 --bind 0.0.0.0:9299 auto -u user -p password
```

The default active-connection limit is 8192. On Unix, outway raises the soft
file-descriptor limit before listening and fails startup if the hard limit is
too low. Linux CIDR route and non-local-bind configuration is also treated as
a required startup step.

An IPv6-only source CIDR can connect only to IPv6 destinations. Configure
`--fallback` with a local address or interface when IPv4 destination support is
required.

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
| `--concurrent` | `-c` | `8192` | Maximum concurrent active connections |
| `--workers` | `-w` | CPU cores | Worker thread count |
| `--cidr` | `-i` | | Base CIDR block for outbound source selection |
| `--cidr-range` | `-r` | `0` | Sub-range bit width (CIDR range extension) |
| `--fallback` | `-f` | | Fallback local source address or interface name |
| `--connect-timeout` | `-t` | `10` | Outbound connection timeout (seconds) |
| `--reuseaddr` | | `true` | Outbound `SO_REUSEADDR` for TCP sockets |
| `--tcp-user-timeout` | | `30` | Outbound TCP user timeout (seconds, Linux only) |
| `--udp-max-packet-size` | | `65507` | Maximum complete SOCKS5 UDP relay datagram; larger packets are dropped instead of truncated |
| `--udp-batch-size` | | `32` | Receive/send batch size (`recvmmsg`/`sendmmsg` on Linux) |
| `--udp-batch-buffer-budget` | | `1024` | Process-wide extra buffer budget for concurrent Linux UDP batches; `0` uses scalar reads |
| `--udp-send-queue` | | `4096` | Global outbound UDP send queue capacity |
| `--udp-send-workers` | | auto | Outbound UDP worker count |
| `--udp-associations` | | `--concurrent` | Maximum active UDP associations |
| `--udp-association-idle-timeout` | | disabled | Optional idle association timeout in seconds |
| `--udp-metrics-interval` | | `30` | Structured UDP metrics log interval in seconds; `0` disables it |
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
