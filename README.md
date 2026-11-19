# outway

A high-performance HTTP/HTTPS/SOCKS5/MASQUE proxy server written in Go, with per-connection outbound source-address selection driven by proxy-username extensions.

## Features

- **Multiple protocols** — HTTP, HTTPS, SOCKS5, and HTTP/3 CONNECT-UDP (MASQUE) proxying.
- **Auto-detection** — a single port can serve SOCKS5, HTTP, and HTTPS simultaneously, dispatching each connection by inspecting its first byte.
- **CIDR-based source selection** — bind outbound connections to addresses chosen from a configured CIDR block, selected deterministically per session/TTL/range via username extensions.
- **High-concurrency SOCKS5 UDP relay** — batched `recvmmsg`/`sendmmsg` I/O on Linux, a bounded buffer pool, per-association source-IP authorization, and tunable socket buffers for large UDP proxy pools.
- **HTTP/2 CONNECT multiplexing (h2c)** — optional: many CONNECT tunnels on one HTTP/2 cleartext connection, so new tunnels skip the TCP handshake on long links.
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

### Per-account sticky IPv6

To give every upstream account its own stable IPv6 source address, have each
client authenticate as `<user>-session-<id>` (for example
`proxy-session-12345`, where `user` is the configured `--username`) and turn on
the source-policy options:

```yaml
# /etc/outway/outway.yaml
bind: 0.0.0.0:1080
username: proxy
password: secret

cidr: 2001:db8:100:47c3::/64   # or a /56; spread then also covers the /64s
session-spread: true           # well-mixed, per-session address over every host bit
strict-source: true            # IPv6-capable targets never leave via the fallback
ndp-proxy: eno1                # answer the provider's neighbor solicitations
# fallback: 203.0.113.10       # optional: only for targets without any IPv6 address
```

```bash
sudo outway systemd start --config /etc/outway/outway.yaml auto
```

- **`session-spread`** maps `session`/`ttl` extensions through a 64→128-bit
  splitmix64 mixer onto *every* host bit of the CIDR, including the subnet bits
  of a prefix shorter than /64, and never picks the all-zero host. Without it,
  outway keeps the upstream-compatible `base | (hash mod capacity)` mapping,
  which puts every session of a /56 in its first /64, and adjacent session IDs
  share most of their low bits. Enabling it **remaps every existing session**,
  so it is off by default. Addresses stay deterministic per session id. With a
  /56 there are only 256 /64s, so with many accounts some will share a /64;
  their addresses are still distinct.
- **`strict-source`**: when a target resolves to any address in the CIDR's
  family, only those addresses are used, and the fallback is never raced or
  retried. The fallback serves only targets that have no address in that
  family. This applies to TCP, MASQUE, and SOCKS5 UDP. Without it, a slow or
  failed IPv6 dial races the fallback after 500 ms, and Happy Eyeballs may pick
  an IPv4 address.
- **`ndp-proxy`** (Linux only) is for providers that put the prefix *on-link*
  and solicit every source address. At startup it sets
  `net.ipv6.conf.<iface>.proxy_ndp=1`, and before each dial it installs a
  proxy-neighbor entry for the chosen source (`ip -6 neigh replace proxy <addr>
  dev <iface>`). Up to `ndp-proxy-max` entries (default 65536) are kept. The
  least recently used entries are removed, and every entry is removed on
  graceful shutdown. Install failures are logged and never fail the dial. The
  kernel ignores proxy entries on non-forwarding interfaces, so outway refuses
  to start unless `net.ipv6.conf.<iface>.forwarding=1`. If the interface takes
  its default route from router advertisements, also set
  `net.ipv6.conf.<iface>.accept_ra=2`, which keeps accepting RAs while
  forwarding. This replaces an external `ndppd`. An evicted address's entry is
  gone even if a long-lived connection still uses it, so size `ndp-proxy-max`
  above the number of addresses that are active at once.

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

### Fast tunnel setup on long links

On a high-RTT path between the client and outway, every new tunnel pays the
client↔outway round trips before the target's TLS handshake can even start.
Three opt-in features remove them:

| Client strategy | Round trips to TLS ready |
|---|---|
| HTTP/1.1 CONNECT, wait for `200` | 3 (TCP + CONNECT + TLS) |
| HTTP/1.1 CONNECT, send ClientHello right behind the request ("optimistic") | 2 |
| Optimistic CONNECT + `tcp-fastopen` (first flight ≤ one MSS) | 1 |
| `h2c`: CONNECT stream on an established HTTP/2 connection | 1 |

Measured through outway with netem adding 70 ms RTT between client and proxy
(p50, TLS 1.3, new tunnel per sample):

| | default ClientHello (X25519MLKEM768) | X25519-only ClientHello |
|---|---|---|
| HTTP/1.1 CONNECT, wait for `200` | 230 ms | 231 ms |
| Optimistic HTTP/1.1 CONNECT | 152 ms | 154 ms |
| Optimistic CONNECT + TCP Fast Open | 152 ms | 78 ms |
| h2c stream | 78 ms | 77 ms |
| *(direct to target over the same path)* | *153 ms* | *155 ms* |

TCP Fast Open only helps when the CONNECT line plus the ClientHello fit in
the SYN (about 1420 bytes). Go's default post-quantum ClientHello does not,
so the rest of it waits for the handshake; h2c has no such limit.

**Optimistic HTTP/1.1 CONNECT** needs no flag. Bytes the client sends after
the CONNECT headers, in the same segment or later ones, are forwarded to the
target in order once the dial succeeds. If the dial fails, outway answers
`502` and drops them.

**`h2c`** (`--h2c`, `http` and `auto` only) accepts HTTP/2 cleartext with
prior knowledge on the same port. Connections that start with the HTTP/2
preface (`PRI * HTTP/2.0`) go to the HTTP/2 server; everything else is served
as before. Each stream is one CONNECT tunnel (RFC 9113 §8.5) and is
authenticated on its own `Proxy-Authorization` header, so username extensions
such as `user-session-<id>` work per stream. The client may send DATA right
behind HEADERS, before the `200` arrives. Idle connections are pinged every
30 s.

The upload windows default to 2 MiB per connection and per stream. That is
about 28 MB/s per connection at 70 ms RTT. Size `h2c-conn-window` near the
bandwidth-delay product of the client→proxy path, not far above it. Every
tunnel on a connection shares one TCP flow. When other streams are uploading,
a new tunnel's HEADERS queues behind whatever DATA the window lets the client
send first. Measured at 70 ms RTT with 24 streams uploading on one
connection:

| `h2c-conn-window` | no loss: upload, new-tunnel `200` p50 | 0.1% loss: upload, `200` p50 |
|---|---|---|
| 16 MiB | 16 MB/s, 350 ms | 1.4–2.3 MB/s, 2.6–6.3 s |
| 2 MiB (default) | 16 MB/s, 113 ms | 4.1 MB/s, 1.0 s |
| 1 MiB | 10–13 MB/s, 77 ms | 6.5 MB/s, 180 ms |

Keep bulk uploads and latency-sensitive new tunnels from piling onto one
connection. Spread streams over several connections, or cap streams per
connection in the client. One TCP flow over a lossy long path is slow
whatever the protocol, and h2c puts all its streams in that one flow.

```yaml
h2c: true
h2c-max-streams: 1000        # concurrent tunnels per client connection
h2c-conn-window: 2097152     # upload window per connection (bytes); ~ path BDP
h2c-stream-window: 2097152   # upload window per stream (bytes)
tcp-fastopen: 256            # TFO queue length on the listen sockets
```

A minimal Go client (standard library only, Go 1.26+). Open one connection,
keep it, and open each tunnel as a stream:

```go
// newProxyConn opens ONE HTTP/2 cleartext connection to outway. Keep it and
// open every tunnel on it; only the first tunnel pays the TCP handshake.
func newProxyConn(ctx context.Context, proxyAddr string) (*http.ClientConn, error) {
	var protocols http.Protocols
	protocols.SetUnencryptedHTTP2(true) // h2c with prior knowledge
	tr := &http.Transport{
		Protocols: &protocols,
		HTTP2: &http.HTTP2Config{
			MaxReceiveBufferPerConnection: 64 << 20, // downstream windows
			MaxReceiveBufferPerStream:     16 << 20,
			SendPingTimeout:               30 * time.Second,
		},
	}
	return tr.NewClientConn(ctx, "http", proxyAddr)
}

// dialTunnel opens a CONNECT stream and returns at once. Bytes written to the
// returned conn go out as DATA frames immediately, before outway answers 200,
// so a TLS ClientHello rides right behind the HEADERS frame.
func dialTunnel(cc *http.ClientConn, proxyAddr, target, user, pass string) net.Conn {
	pr, pw := io.Pipe()
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Scheme: "http", Host: proxyAddr},
		Host:   target, // "example.com:443" -> :authority
		Header: http.Header{"Proxy-Authorization": {"Basic " +
			base64.StdEncoding.EncodeToString([]byte(user+":"+pass))}},
		Body: pr,
	}
	t := &tunnel{pw: pw, ready: make(chan struct{})}
	go func() {
		defer close(t.ready)
		t.resp, t.err = cc.RoundTrip(req)
		if t.err == nil && t.resp.StatusCode != http.StatusOK {
			t.resp.Body.Close()
			t.err = fmt.Errorf("CONNECT %s: %s", target, t.resp.Status)
		}
		if t.err != nil {
			pr.CloseWithError(t.err)
		}
	}()
	return t
}

type tunnel struct {
	pw    *io.PipeWriter
	ready chan struct{}
	resp  *http.Response
	err   error
}

func (t *tunnel) Write(p []byte) (int, error) { return t.pw.Write(p) }
func (t *tunnel) Read(p []byte) (int, error) {
	<-t.ready
	if t.err != nil {
		return 0, t.err
	}
	return t.resp.Body.Read(p)
}
func (t *tunnel) Close() error {
	t.pw.Close()
	<-t.ready
	if t.resp != nil {
		t.resp.Body.Close()
	}
	return nil
}
func (t *tunnel) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (t *tunnel) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (t *tunnel) SetDeadline(time.Time) error      { return nil }
func (t *tunnel) SetReadDeadline(time.Time) error  { return nil }
func (t *tunnel) SetWriteDeadline(time.Time) error { return nil }
```

`dialTunnel` returns a `net.Conn` that works as a `DialTLSContext` result
or with `tls.Client`. To use Fast Open with plain HTTP/1.1 instead, set
`TCP_FASTOPEN_CONNECT` on the client socket (Linux), write the CONNECT
request and the ClientHello in one write, and enable it on both kernels:
`net.ipv4.tcp_fastopen = 3`.

#### Kernel settings for long links

These help every protocol and need no outway change:

```bash
# Do not collapse the congestion window after an idle period (the main cause
# of slow first requests on a reused, then idle, long-RTT tunnel).
sysctl -w net.ipv4.tcp_slow_start_after_idle=0
# Larger initial windows on the client<->proxy route (replace the route values).
ip route change default via <gw> dev <iface> initcwnd 64 initrwnd 64
# Let receive autotuning grow to the bandwidth-delay product. Prefer this over
# a fixed SO_RCVBUF, which disables autotuning on that socket.
sysctl -w net.ipv4.tcp_rmem="4096 131072 33554432"
sysctl -w net.ipv4.tcp_wmem="4096 65536 33554432"
# Fast Open for both client and server roles.
sysctl -w net.ipv4.tcp_fastopen=3
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
session-spread: false   # see "Per-account sticky IPv6"
strict-source: false
# ndp-proxy: eno1
# ndp-proxy-max: 65536

# HTTP/2 CONNECT multiplexing and TCP Fast Open (see "Fast tunnel setup")
h2c: false
tcp-fastopen: 0

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
outway version          # Print the version (also: outway --version)
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
| `--session-spread` | | `false` | Spread `session`/`ttl` extensions over every host bit of the CIDR with a strong mixer (remaps existing sessions) |
| `--strict-source` | | `false` | Keep targets with a CIDR-family address on the CIDR source; never race or fall back |
| `--ndp-proxy` | | | Install proxy-NDP entries on this interface for chosen IPv6 sources (Linux only; needs `forwarding=1` on it) |
| `--ndp-proxy-max` | | `65536` | Maximum proxy-NDP entries kept installed; least recently used are removed |
| `--h2c` | | `false` | Accept HTTP/2 cleartext CONNECT tunnels on the same port (http/auto) |
| `--h2c-max-streams` | | `1000` | Maximum concurrent tunnels per HTTP/2 connection |
| `--h2c-conn-window` | | `2097152` | HTTP/2 upload window per connection, in bytes (size near the path's bandwidth-delay product) |
| `--h2c-stream-window` | | `2097152` | HTTP/2 upload window per stream, in bytes |
| `--tcp-fastopen` | | `0` | `TCP_FASTOPEN` queue length on listen sockets (Linux only; ignored with a warning elsewhere); `0` disables it |
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

The extension value is hashed deterministically to pick an address inside the configured CIDR block. With `--session-spread`, `session` and `ttl` values are additionally mixed across every host bit (see [Per-account sticky IPv6](#per-account-sticky-ipv6)).

## License

See the repository for license details.

Inspired by [vproxy](https://github.com/vproxy-tools/vproxy) — a high-performance transparent proxy solution.
