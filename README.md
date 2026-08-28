# outway

A high-performance HTTP/HTTPS/SOCKS5/MASQUE proxy server written in Go, with per-connection outbound source-address selection driven by proxy-username extensions.

## Features

- **Multiple protocols** — HTTP, HTTPS, SOCKS5, and HTTP/3 CONNECT-UDP (MASQUE) proxying.
- **Auto-detection** — a single port can serve SOCKS5, HTTP, and HTTPS simultaneously, dispatching each connection by inspecting its first byte.
- **CIDR-based source selection** — bind outbound connections to addresses chosen from a configured CIDR block, selected deterministically per session/TTL/range via username extensions.
- **High-concurrency SOCKS5 UDP relay** — batched `recvmmsg`/`sendmmsg` I/O on Linux, a bounded buffer pool, per-association source-IP authorization, and tunable socket buffers for large UDP proxy pools.
- **Authentication** — optional username/password (Basic auth for HTTP, username/password auth for SOCKS5).
- **systemd management** — install, enable, start, restart, stop, status, and journal log commands (Linux).
- **Self-update** — download and install the latest release directly from GitHub.

## Installation

### One-line install (Linux and macOS)

Install the latest stable release to `/usr/local/bin/outway`:

```bash
curl -fsSL https://raw.githubusercontent.com/xiaozhou26/outway/main/install.sh | sh
```

Uninstall it:

```bash
curl -fsSL https://raw.githubusercontent.com/xiaozhou26/outway/main/install.sh | sh -s -- uninstall
```

The script supports Linux and macOS on `amd64` and `arm64`. Set
`OUTWAY_INSTALL_DIR` to choose another installation directory, or
`OUTWAY_VERSION` to install a specific release:

```bash
curl -fsSL https://raw.githubusercontent.com/xiaozhou26/outway/main/install.sh | \
  OUTWAY_INSTALL_DIR="$HOME/.local/bin" OUTWAY_VERSION=v0.7.0 sh
```

### Install with Go

```bash
go install github.com/xiaozhou26/outway@latest
```

### Build from source

```bash
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
outway run masque      # HTTP/3 CONNECT-UDP (MASQUE) proxy over UDP
outway run auto        # Serve SOCKS5/HTTP/HTTPS on one TCP port
```

Example with bind address and authentication:

```
outway run auto -b 127.0.0.1:1080 -u user -p pass
```

MASQUE listens with HTTP/3 on UDP and uses the RFC 9298 URI template
`https://<bind>/.well-known/masque/udp/{target_host}/{target_port}/`:

```
outway run masque -b 0.0.0.0:443 --tls-cert cert.pem --tls-key key.pem
```

If TLS files are omitted, the persistent self-signed certificate is reused.
`--concurrent` limits active CONNECT-UDP tunnels rather than QUIC connections.

### High-concurrency IPv6 CIDR example

```bash
sudo ./outway systemd start -i 2001:db8::/56 --bind 0.0.0.0:1080 auto -u user -p password
```

The default active-connection limit is 8192. On Unix, outway raises the soft
file-descriptor limit before listening and fails startup if the hard limit is
too low. Linux CIDR route and non-local-bind configuration is also treated as
a required startup step.

An IPv6-only source CIDR can connect only to IPv6 destinations. Configure
`--fallback` with a local address or interface when IPv4 destination support is
required.

### Tuning the SOCKS5 UDP relay under load

For a busy UDP proxy pool (many simultaneous UDP associations, e.g. QUIC/HTTP-3
or DNS), the kernel socket buffers are usually the first thing to overflow when
traffic arrives in bursts. Enlarge them with `--udp-socket-buffer`:

```bash
sudo ./outway run socks5 -i 2001:db8::/56 -b 0.0.0.0:1080 \
  --udp-socket-buffer 8388608 -u user -p password
```

On Linux, outway sets the buffers with `SO_RCVBUFFORCE`/`SO_SNDBUFFORCE`, which
bypass the `net.core.rmem_max` / `net.core.wmem_max` sysctl ceilings but require
`CAP_NET_ADMIN` (i.e. run as root or grant the capability). Without that
capability the request is silently clamped to `rmem_max`/`wmem_max`, so raise
those sysctls first if you cannot grant it. On other platforms the size is
always subject to the OS limits.

Other knobs that matter at high concurrency:

- `--udp-max-packet-size` — the per-datagram ceiling also sizes each pooled
  relay buffer, so a pool that only carries small datagrams (DNS, QUIC) can lower
  it well below the 65507 default to cut memory per in-flight packet.
- `--udp-batch-size` — on Linux, packets are received and sent in batches via
  `recvmmsg`/`sendmmsg`; a larger batch amortizes syscall overhead.
- `--udp-batch-buffer-budget` — caps the extra pooled buffers held by concurrent
  batches, bounding memory under a large association count.
- `--udp-send-queue` / `--udp-send-workers` — size the outbound send pipeline.
- `--udp-associations` — hard cap on active associations; excess UDP ASSOCIATE
  requests are rejected rather than exhausting descriptors.
- `--udp-metrics-interval` — logs structured counters (in/out packets, queue
  depth, drops by cause) to observe where packets are lost under load.
- `--udp-gso` — on Linux, coalesce a burst of same-target, uniform-size
  datagrams (e.g. a QUIC/HTTP-3 flow to one server) into a single `UDP_SEGMENT`
  send so the kernel — or the NIC, when it supports UDP GSO offload — performs
  the segmentation. This cuts send syscalls and stack traversals for fat
  single-flow bursts; mixed-destination or ragged-size batches automatically
  fall back to `sendmmsg`. Off by default; a no-op on non-Linux platforms and on
  kernels without `UDP_SEGMENT`.
- `--udp-gro` — on Linux, enable `UDP_GRO` on the relay sockets so the kernel —
  or the NIC, when it supports UDP GRO offload — coalesces a burst of same-flow,
  same-size datagrams into a single read, which the relay splits back into
  individual datagrams. This is the receive-side counterpart to `--udp-gso` and
  cuts receive syscalls and stack traversals for fat single-flow bursts. Off by
  default; a no-op on non-Linux platforms and on kernels without `UDP_GRO`.

#### Recommended sysctls (Linux)

For a large UDP pool, tune the kernel alongside the flags. `outway` warns at
startup if `--udp-socket-buffer` is clamped, which usually means these need
raising:

```bash
# Allow larger UDP socket buffers (needed unless outway runs with CAP_NET_ADMIN,
# which uses SO_RCVBUFFORCE to bypass these ceilings).
sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.wmem_max=16777216

# Absorb bursts between the NIC and the socket queues.
sysctl -w net.core.netdev_max_backlog=250000

# More ephemeral ports for many simultaneous outbound sockets.
sysctl -w net.ipv4.ip_local_port_range="1024 65535"

# If netfilter/conntrack is in the path, a busy UDP pool can exhaust the table
# and silently drop packets; size it for the expected flow count.
sysctl -w net.netfilter.nf_conntrack_max=1048576
```

### Configuration file

Instead of repeating flags on the command line, pass `--config <path>` to `run`
or any `systemd` action. The YAML file provides defaults: every setting not
given as an explicit flag comes from the file, and a flag on the command line
always wins.

```yaml
# outway.yaml
bind: 0.0.0.0:1080
log: info
concurrent: 65536
username: user
password: password

# Outbound source selection (same values as --cidr / --cidr-range / --fallback)
cidr: 2001:db8::/56
cidr-range: 64

# Diagnostics endpoint for /metrics and pprof
diagnostics: 127.0.0.1:9100

# The --udp-* flags nest under "udp"
udp:
  socket-buffer: 8388608
  max-packet-size: 65536
  associations: 32768
  association-idle-timeout: 300
  gso: true
  gro: true
```

```bash
outway run auto --config outway.yaml          # file values, or
outway run auto --config outway.yaml -b 127.0.0.1:8080  # -b overrides the file
```

Unknown keys are rejected at startup so a typoed setting cannot be silently
ignored. `systemd install/start/restart --config <path>` bakes the flag into
the unit's `ExecStart`, so the service re-reads the file on every start.

### Recommended production configuration

A battle-tested setup for a busy proxy pool on a Linux server with IPv6 CIDR
rotation, UDP relay traffic (QUIC/HTTP-3, DNS), and diagnostics enabled:

```bash
sudo outway systemd install auto \
  -b 0.0.0.0:1080 \
  -i 2001:db8::/56 -r 64 \
  -u user -p password \
  -c 65536 \
  --udp-socket-buffer 8388608 \
  --udp-max-packet-size 65507 \
  --udp-associations 32768 \
  --udp-association-idle-timeout 300 \
  --udp-gso --udp-gro \
  --reuse-port \
  --diagnostics 127.0.0.1:9100 \
  -L info
```

Why each choice:

- `-r 64` — split the `/56` into `/64` sub-ranges so the `range` username
  extension can pin clients to a specific /64 block; omit it if you only use
  `session`/`ttl` extensions.
- `-c 65536` — a large active-connection ceiling for many-clients workloads;
  make sure the fd soft limit (`ulimit -n` / systemd `LimitNOFILE`) covers it.
  On Unix outway raises the soft limit itself and fails startup when the hard
  limit is too low.
- `--udp-socket-buffer 8388608` — the first thing to overflow under UDP bursts.
  With root/CAP_NET_ADMIN it applies via `SO_*BUFFORCE` bypassing sysctl
  ceilings; otherwise raise `net.core.rmem_max`/`wmem_max` (see above).
- `--udp-max-packet-size 65507` — keep full-size QUIC datagrams (65507 is the
  largest possible UDP payload); lower it (e.g. `4096`) for DNS-only pools to
  cut per-packet pool memory.
- `--udp-associations 32768` — cap UDP associations below `--concurrent` so a
  UDP flood cannot starve TCP tunnels; excess ASSOCIATE requests are rejected.
- `--udp-association-idle-timeout 300` — reap forgotten associations after
  five idle minutes instead of waiting for the client to close.
- `--udp-gso --udp-gro` — Linux-only batching offloads; big syscall savings
  for fat single-flow bursts, no-ops elsewhere. Enable them after confirming
  your kernel supports `UDP_SEGMENT`/`UDP_GRO` (outway probes once at startup).
- `--reuse-port` — shard accepts across CPU cores (Linux/BSD only). Leave it
  off for a single-core box; never use it for MASQUE, which intentionally
  stays on one UDP socket.
- `--diagnostics 127.0.0.1:9100` — scrape `/metrics` and pprof locally
  (e.g. with Prometheus + node_exporter style jobs); keep it off the public
  interface.

If your source CIDR is IPv6-only but clients need IPv4 destinations, add
`--fallback` with a local IPv4 address or interface name.

### Linux systemd

The legacy Unix `start`, `restart`, `stop`, `ps`, and `log` commands have been
replaced by a Linux-only `systemd` command group. The proxy remains in the
foreground and systemd owns its lifecycle, restart policy, stdout/stderr, and
journal logs.

```
sudo outway systemd install auto -b 127.0.0.1:1080  # Write the unit
sudo outway systemd enable auto -b 127.0.0.1:1080   # Enable at boot
sudo outway systemd start auto -b 127.0.0.1:1080    # Enable and start
sudo outway systemd restart auto -b 127.0.0.1:1080  # Update and restart
sudo outway systemd stop                              # Stop, keep enabled
sudo outway systemd status                            # Show service status
sudo outway systemd logs                              # Follow journal logs
```

The generated unit is installed at `/etc/systemd/system/outway.service` and
uses `StateDirectory=outway`, normally `/var/lib/outway`, for generated
`cert.pem` and `key.pem`. On non-interactive installation, the unit also sets
`NO_COLOR=1`/`TERM=dumb` and enables stronger systemd sandboxing. Custom TLS
paths supplied with `--tls-cert` and `--tls-key` are not moved.

### Self-management

```
outway self update      # Update to the latest release
outway self uninstall   # Remove the installed binary
```

## Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--config` | | | YAML config file providing defaults for unset flags (run/systemd) |
| `--log` | `-L` | `info` | Log level (trace / debug / info / warn / error) |
| `--bind` | `-b` | `127.0.0.1:1080` | Bind address (listen endpoint) |
| `--concurrent` | `-c` | `8192` | Maximum concurrent active connections |
| `--workers` | `-w` | CPU cores | Worker thread count |
| `--cidr` | `-i` | | Base CIDR block for outbound source selection |
| `--cidr-range` | `-r` | `0` | Sub-range bit width (CIDR range extension) |
| `--fallback` | `-f` | | Fallback local source address or interface name |
| `--connect-timeout` | `-t` | `10` | Outbound connection timeout (seconds) |
| `--reuseaddr` | | `true` | Outbound `SO_REUSEADDR` for TCP sockets |
| `--max-pending-dials` | | `512` | Maximum concurrent outbound TCP dials; `0` is unlimited |
| `--reuse-port` | | `false` | Shard the listener with `SO_REUSEPORT` across accept loops (Linux/BSD) |
| `--diagnostics` | | disabled | Diagnostic HTTP bind address exposing `/metrics` and pprof endpoints (e.g. `127.0.0.1:9100`) |
| `--tcp-user-timeout` | | `30` | Outbound TCP user timeout (seconds, Linux only) |
| `--udp-max-packet-size` | | `65507` | Maximum complete SOCKS5 UDP relay datagram; larger packets are dropped instead of truncated |
| `--udp-batch-size` | | `32` | Receive/send batch size (`recvmmsg`/`sendmmsg` on Linux) |
| `--udp-batch-buffer-budget` | | `1024` | Process-wide extra buffer budget for concurrent Linux UDP batches; `0` uses scalar reads |
| `--udp-send-queue` | | `4096` | Global outbound UDP send queue capacity |
| `--udp-send-workers` | | auto | Outbound UDP worker count |
| `--udp-socket-buffer` | | `0` | `SO_RCVBUF`/`SO_SNDBUF` for UDP relay sockets in bytes; `0` keeps the system default |
| `--udp-gso` | | `false` | Enable Linux `UDP_SEGMENT` (GSO) batching for same-target uniform-size sends |
| `--udp-gro` | | `false` | Enable Linux `UDP_GRO` coalescing of received datagrams on the relay sockets |
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
