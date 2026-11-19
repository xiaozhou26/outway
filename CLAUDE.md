# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a high-performance HTTP/HTTPS/SOCKS5/MASQUE proxy server written in Go, ported from the Rust project [0x676e67/vproxy](https://github.com/0x676e67/vproxy) (many modules carry "mirrors the Rust ..." comments). The module path is `github.com/xiaozhou26/outway` and the binary is `outway`.

A local clone of the upstream Rust source is often present at `vproxy/` — it is **gitignored and not part of the build**. Treat it as the reference implementation: when a Go module says it mirrors Rust behavior (`internal/ext`, `internal/connect`, `internal/randx`, `internal/oneself`), the corresponding `vproxy/src/*.rs` file is the spec. Never edit it or include it in builds.

`AGENTS.md` is a near-copy of this file for Codex, and is also gitignored. If you change architecture documentation here, consider mirroring it there.

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

### Stress tests are opt-in via environment variables

Several concurrency tests `t.Skip` unless an env var is set, so `go test ./...` does not run them. CI (`.github/workflows/release.yml`) runs them explicitly on Linux. To reproduce locally:

```
OUTWAY_STRESS_CONNECTIONS=1000 OUTWAY_STRESS_ROUNDS=5 go test -count=1 -run '^TestSOCKS5ConcurrentTunnelsStress$' ./internal/server/socks
OUTWAY_STRESS_UDP_ASSOCIATIONS=32 OUTWAY_STRESS_UDP_PACKETS=100 go test -count=1 -run '^TestSOCKS5UDPAssociationsStress$' ./internal/server/socks
```

Other gates: `OUTWAY_STRESS_AUTO_CONNECTIONS` (`./internal/server`), `OUTWAY_STRESS_HTTPS_CONNECTIONS` (`./internal/server/http`). CI also runs `go test -race ./...` on Linux, and the matrix covers Linux/Windows/macOS — much of the interesting code is behind `_linux.go` build tags, so a change that compiles locally on Windows may still break the Linux build.

## Running

The CLI is structured as `<lifecycle> <protocol>`:

- Lifecycle commands: `run` (foreground), plus Linux-only `systemd install` / `enable` / `start` / `restart` / `stop` / `status` / `logs` service management.
- Protocol subcommands under each: `http`, `https`, `socks5`, `masque` (`quic` alias), `auto`.
- `self update` / `self uninstall` manage the installed binary; `version` (or `--version`) prints the ldflags-injected version.

Example: `outway run auto -b 127.0.0.1:1080 -u user -p pass`

MASQUE is a separate UDP/HTTP3 listener (`internal/server/masque`) and is **not** part of TCP auto-detection or SO_REUSEPORT sharding. Its RFC 9298 path is `/.well-known/masque/udp/{target_host}/{target_port}/`; `--concurrent` limits active CONNECT-UDP tunnels, not QUIC connections. The per-tunnel datagram relay is `pump.go` (`serveTunnel`/`tunnel`): it takes over the HTTP/3 stream, pools its target→client buffers in a per-server `sync.Pool` (safe because quic-go's `SendDatagram` copies its input), sizes datagrams from `--udp-max-packet-size` instead of a hardcoded MTU, and tracks active tunnels so `Close()` tears them down immediately.

**Why MASQUE deliberately stays on one UDP socket** (no SO_REUSEPORT sharding, evaluated 2026-08): UDP has no per-flow kernel state, so SO_REUSEPORT hashes *every datagram* independently by its 4-tuple. A QUIC connection that migrates or undergoes NAT rebinding (new client port) would land on a different shard socket and die — unlike TCP, where the established connection is pinned to the socket the SYN selected. quic-go applies GSO/ECN/DF to externally provided `*net.UDPConn`s identically to its own listeners, so a single socket loses no offloads.

## Architecture

The request flow is: **CLI (main.go) → BootArgs (config) → server.Run → protocol server → Handler → Connector → outbound**.

### Configuration boundary

`main.go` parses cobra flags into a `config.BootArgs`. This is the single hand-off from CLI to the rest of the system — an optional `--config <path>` YAML file (parsed strictly by `config.LoadFile`, internal/config/file.go) seeds the flag variables via `preloadConfigFile` before cobra parses, so file values act as defaults and explicit flags win. — `server.Run(args)` is the entry point. Nothing below `main.go` knows about cobra or flags. The `systemd` subcommands reuse this: `buildRunArgsFromOSArgs` (main.go:367) rewrites `outway systemd <action> ...` into the `outway run ...` line baked into `ExecStart`, so flag parsing stays in one place.

### Protocol auto-detection

`internal/server/auto.go` is the most distinctive piece. `AutoDetectServer` listens on ONE port and peeks the first byte of each connection to route it:
- `0x05` → SOCKS5
- `< 0x41` → HTTPS (TLS records start with a binary byte below the ASCII letter range)
- `>= 0x41` → HTTP (ASCII request methods like `GET`, `CONNECT`)

The peeked byte must not be lost, so connections are wrapped in `bufferedConn` (auto.go:273 — a `net.Conn` whose `Read` is backed by the `bufio.Reader` used for peeking). Any change to the dispatch logic must preserve this wrapping.

**h2c (`--h2c`, off by default).** When enabled, a cleartext connection whose first three bytes are `PRI` (the HTTP/2 preface) is served by `Handler.ServeH2C` (`internal/server/http/h2c.go`) instead of the HTTP/1 loop. The check lives in two places that must stay in step: `serveHTTP` in auto.go (only when the first byte is `'P'`) and `HttpServer.accept` in http/server.go (plain HTTP only, never under TLS). `IsH2CPreface` only peeks, and `prefacedConn` reads through the same `bufio.Reader`, so the preface reaches the x/net `http2.Server`. Each stream is one RFC 9113 §8.5 CONNECT tunnel and is authenticated on its **own** `Proxy-Authorization` header, so username extensions apply per stream. `--concurrent` counts the TCP connection; streams are bounded per connection by `--h2c-max-streams`. Early DATA sent before the `200` waits in the stream's receive buffer, bounded by `--h2c-stream-window`, until the dial succeeds. `tunnelH2C` flushes every target read as its own DATA frame and returns as soon as the target finishes, so END_STREAM is not delayed. The advertised 16 KiB max frame size (`h2cMaxFrameSize`) and the 2 MiB default windows are deliberate; do not raise them. Go's client writes each DATA frame while holding its connection write lock, and the window bounds how much DATA can sit ahead of a new stream's HEADERS. With x/net's 1 MiB frames and 16 MiB windows, a new tunnel on an upload-busy connection waited 5–15 s for its 200.

**TCP Fast Open (`--tcp-fastopen <qlen>`, off by default)** is applied in `ListenTCPShards`' control function (`fastopen_linux.go`). Elsewhere it is ignored with a warning. Every TCP listener (http, socks5, auto, all shards) gets it.

### serverbase breaks an import cycle

`internal/serverbase` holds `Context` (shared runtime state: bind address, auth, connector, UDP config, reuse-port) and the bidirectional-copy helpers. It exists specifically so that the `server`, `server/http`, and `server/socks` packages can share types without a cycle. When adding shared server state, put it here — not in `server`, which imports the protocol subpackages.

It also carries most of the per-request contention work, which is easy to undo accidentally:

- **`ConnectionSet`** (serverbase.go:197) — the active-connection registry, sharded 32 ways by a Fibonacci hash of the conn pointer's **high** bits (pointer alignment would otherwise cluster the low bits). `CloseAll` copies each shard out and closes **outside** the lock.
- **`LifetimeShards`** (serverbase.go:292) — 8 child contexts off the root lifetime, keyed by the same hash. Rationale: `context.WithTimeout`/`AfterFunc` register with their nearest cancellable ancestor *under that ancestor's mutex*, so deriving every request from one root context serializes all handlers on a single lock.
- **`CopyBidirectionalContext`** (serverbase.go:402) — the tunnel path. Cancellation interrupts blocked reads via `context.AfterFunc` setting deadlines; the "first direction finished" latch is an `atomic.Bool` CAS rather than `sync.Once`, because `Once.Do` parks the losing side on a mutex during every short-tunnel teardown. Only one extra goroutine is spawned; the caller drives the reverse direction.
- **`DebugEnabled()`** (serverbase.go:33) — hot paths guard `slog.Debug` with it, since boxing the arguments of a disabled debug call costs several allocations per request.
- Also here: `ConnectionGate` / `NewTLSHandshakeGate`, pooled bufio readers/writers, `AddrPortOf` (avoids a `String()`→reparse round-trip per accept), the shared `AuthMode` enum, and the shared accept/teardown helpers — `AcceptLoop` (gate + registration + handler goroutine for one listener), `CloseListeners`, and `IsConnClosed`. The HTTP, SOCKS5, and auto servers all delegate their accept loops and listener teardown to these instead of carrying three copies.

**Zero-copy split.** `copy_linux.go` / `copy_other.go` both call `io.Copy`; the build tags exist to control *interface visibility*, not to switch algorithms. On Linux it passes the `net.TCPConn` through untouched so the runtime selects `splice(2)`; elsewhere it wraps both ends in `readerOnly`/`writerOnly` shims to **hide** `ReaderFrom`/`WriterTo`, forcing `io.CopyBuffer` onto a pooled 24 KiB buffer instead of a fresh 32 KiB stdlib allocation per direction. Preserve that asymmetry.

### SO_REUSEPORT accept sharding

Opt-in via `--reuse-port` (default off): flag → `BootArgs.ReusePort` → `serverbase.Context.ReusePort` → `AcceptShards()` → `ListenTCPShards()`. `AcceptShards` (serverbase.go:60) returns 1 unless enabled *and* supported (`unix && !solaris`), otherwise `GOMAXPROCS` capped at 16. `ListenTCPShards` binds the first listener, then binds the rest on `first.Addr().String()` — the *resolved* address — so a `:0` bind shares one port instead of each shard grabbing its own.

Callers keep `listeners[0]` as the main loop and run one goroutine per extra listener (`auto.go:106`, `http/server.go:177`, `socks/server.go:127`). The main accept loop deliberately holds a WaitGroup slot so handler goroutines can `wg.Add` from any shard without racing `wg.Wait`.

### The Connector and username extensions

`internal/connect` establishes all outbound connections and owns source-address selection policy. The notable feature: outbound source IPs can be chosen per-connection from a CIDR block based on "extensions" parsed out of the proxy username (`internal/ext`). A username like `user-session-abc` or `user-ttl-60` is parsed (`ext.TryFrom`) into an `Extension`, which is hashed (FxHash64, constant `0x517cc1b727220a95`, matching the Rust hash exactly) to deterministically pick a source address within the configured CIDR. Authenticators (`http/auth.go`, `socks/auth.go`) return the parsed `Extension`, which flows into `connector.TCP(extension)` / `.UDP(extension)`. This is why auth and connection establishment are coupled — the username carries routing information, not just credentials.

One `Connector` per process; `TCP()`/`UDP()` return per-request views. Points worth knowing before editing:

- **Dial racing.** `connectAny` (connect.go:133) is a Happy-Eyeballs-style staggered race across resolved addresses (250 ms stagger); `connectWithCIDRFallback` (connect.go:303) adds the fallback path after `min(500ms, ConnectTimeout/2)` or on first failure. Both use an **unbuffered** result channel on purpose — a losing-but-successful dial must not be queued after the winner returns; it gets closed instead. `Connect` sets the single context deadline and the helpers deliberately do not re-wrap it.
- **Dial cap.** `dialSlots` / `udpDialSlots` are context-aware semaphores sharing the `--max-pending-dials` budget (default 512, 0 = unbounded). `dialSlots` is acquired in `TcpConnector.dialContext`; `udpDialSlots` bounds outbound UDP socket creation in `UdpConnector.Connect` (MASQUE tunnels) and `CreateSocketDualStack` (SOCKS5 associations), so fd consumption has backpressure under bursts.
- **uint128 math.** `connect/uint128.go` is a hand-rolled hi/lo `uint128` for IPv6 CIDR arithmetic, mirroring Rust's native `u128`; `modUint128` maps onto `math/bits.Div64` (with a long-division fallback for the both-halves-set case, cross-checked against `math/big` in tests). `internal/randx` supplies the random host bits (`RandomU128` returns big-endian to match Rust).
- An address-family mismatch between the CIDR and the target is a hard error unless a fallback is configured.

**Source policy options (all off by default; defaults must keep existing users' addresses).** All three hook into `Connector.sourceIP`, the single place a CIDR source is chosen (TCP, UDP `Connect`, SOCKS5 UDP sockets, BIND's `SocketAddr`):

- `--session-spread` / `SessionSpread`: `assignSourceIP(..., spread)` sends `session`/`ttl` values through two splitmix64 outputs (`spreadIPv6`/`spreadIPv4`) onto every host bit. The legacy `base | value mod capacity` path (`assignIPv6FromExtension`, which mirrors Rust) stays the default because switching remaps every session. Under a /56 the legacy path puts all sessions in the first /64, and FxHash avoids collisions poorly for adjacent IDs; `policy_test.go` pins both regressions. Do not change `ext.go` hashing.
- `--strict-source` / `StrictSource`: `strictAddrs` drops other-family addresses whenever the target has a CIDR-family one, `connectAddr` skips `connectWithCIDRFallback`, and `pinnedToCIDR` blocks UDP fallback retries. The SOCKS5 UDP batch path picks its own address (`pickFamilyTarget`, socks/server.go), so it asks `UdpConnector.PreferCIDRFamily()`. Any new outbound path that chooses among resolved addresses must apply the same rule.
- `--ndp-proxy <iface>` / `PrepareSource`: `internal/ndp` is a CLOCK (second-chance) cache bounded by `--ndp-proxy-max`. Install and delete are injected `Func`s, so the cache is testable anywhere; `ndp_linux.go` backs them with netlink `NeighSet`/`NeighDel` using `NTF_PROXY`. A hit costs an RLock, a map lookup, and an atomic store. Misses, evictions, and `Close` serialize on the write lock so kernel install and delete for one address never interleave. New entries start unreferenced. Failures are rate-limited warnings and never fail a dial. `Open` refuses to start when `net.ipv6.conf.<iface>.forwarding=0`, because the kernel ignores proxy entries on non-forwarding interfaces. `run.go` closes the cache (removing all entries) after the services stop. Off Linux, `Open` returns an error.

### DNS cache

`internal/connect/dns_cache.go` is a **process-wide singleton** (`defaultDNSCache`), not per-Connector. It stacks three mechanisms: a bounded TTL cache (30 s positive, 3 s negative, 4096 entries — **failures are cached too**, so readers must check `entry.err`), singleflight collapsing of concurrent lookups for the same host, and a 128-slot resolution budget. Everything is **sharded 16 ways by FNV-1a of the normalized hostname**: each shard owns its entries, its in-flight map, and its share of the resolution slots (8 each, at least 1), so hits, misses, and cold lookups on different hosts never contend on one lock. Eviction is intentionally *not* LRU (a global LRU would be a hot lock); each shard sweeps its own expired entries and otherwise drops an arbitrary key.

`LookupCachedHost` (connect.go:585) is exported purely for the SOCKS5 UDP hot path: a cache **hit** lets the association goroutine send inline, a **miss** defers to the send-worker pool so a cold lookup never blocks the relay loop.

### SOCKS5 UDP relay

`internal/server/socks` contains a high-concurrency UDP ASSOCIATE relay tuned for large proxy pools. The moving parts:

- **`udpRuntime` (`udp_runtime.go`)** — one per acceptor, shared across all associations. Owns the pooled packet buffers (`sync.Pool`, sized `MaxPacketSize + header`), the association-count limiter, structured metrics, the pooled batch arrays (`getBatchSlices`/`putBatchSlices` and the per-family Linux writer kits — returned only after every pump has stopped), and a sharded pool of outbound **send workers**. `dispatch()` is lock-free: shard channels are never closed and workers exit via the lifetime context.
- **epoll reactor (Linux) — the relay is not goroutine-per-socket.** `udpReactor` (`udp_reactor_linux.go`) is a lazily created epoll instance plus a worker pool (`GOMAXPROCS` clamped to 2..16), obtained via `runtime.sharedReactor()` (`udp_runtime.go:91`). It is **per `udpRuntime` (per acceptor)**, not process-wide — the goroutine budget scales with acceptor count too. The fd registry itself is sharded 16 ways by a Fibonacci hash of the fd. `(*udpAssociation).serveSocket` (udp_association.go:381) registers each of the association's sockets by raw fd with `EPOLLIN|EPOLLONESHOT` and re-arms after each pump, so a busy association holds **no dedicated read goroutine** — about one goroutine per association, matching the Rust/tokio version. The fallback (`go func(){ for pump() {} }()`) is chosen **per socket** whenever the reactor is unavailable or `register` fails, so Linux can still land on it; both paths must keep working.
- **`handleUDP` split into `udpAssociation`.** The association state machine lives in `udp_association.go`: `setup` (bind inbound, reply, outbound sockets), `teardown` (deregister → close → join → return pooled arrays), `processInbound`/`inboundPump` (client→target, udp_association.go:331), and the TCP control-watching loop. Target→client is `(*udpResponder).pumpOnce` (server.go:393). The one remaining per-association goroutine only watches the TCP control connection, enforcing idle timeout and ending the association on client close or shutdown.
- **Two send directions.** Client→target: literal-IP targets are grouped by address family and flushed with one `sendmmsg` per outbound socket, on the reactor worker running `inboundPump`; **domain** targets go through the shared send-worker pool (see the DNS cache note above). Target→client: batched reads, SOCKS5-header framing, batched writes.
- **Batch I/O (`udp_io_linux.go`)** — on Linux the reader uses `recvmmsg` and the writer `sendmmsg`; other platforms fall back to scalar `ReadMsgUDP`/`WriteToUDP` (`udp_io_other.go`). `udp_io.go` holds the shared `udpReadPacket`/`udpWritePacket` types and interfaces.
- **Optional offloads (Linux, opt-in, off by default).** `--udp-gso` (`udp_gso_linux.go`) coalesces a same-target uniform-size batch into one `UDP_SEGMENT` send; `--udp-gro` (`udp_gro_linux.go`) enables `UDP_GRO` so a coalesced read is split back into individual packets. Both have `_other.go`/build-tag stubs and probe kernel support once.
- **Buffer lifecycle invariant** — exactly one pooled buffer per in-flight datagram, released once (via `releaseInboundPacket`/`releaseReadPacket`/`releaseBuffer`). GRO preserves this by copying split segments into their own pooled buffers rather than sharing one. Any change to the read/send path must keep the release count matched to the acquire count, or the pool corrupts.

Three reactor invariants are load-bearing and easy to "clean up" into a bug:

1. **`reg.mu` around `handler()` is a memory barrier, not just mutual exclusion** (`udp_reactor_linux.go:130`). Successive pumps for one fd run on *different* worker goroutines while mutating non-atomic per-association state (batch accumulators, reused write slices, the batch reader's arrays). Dropping the lock because "EPOLLONESHOT already serializes per-fd" removes the only happens-before edge and creates a data race with no visible exclusion failure. Comments saying state "is used only by this goroutine" now mean *one reactor worker at a time*.
2. **Deregister strictly before close** (`udpAssociation.teardown`, udp_association.go:152). Teardown is `cancel()` → `deregister(fd)` for every registered fd → close sockets → `serveWG.Wait()` → return pooled arrays. `deregister` removes the fd from epoll and then takes `reg.mu` to wait out any in-flight handler. Closing a socket first lets the kernel recycle the fd number while epoll or a running handler still refers to it. Do not reorder these defers or add an early `Close()`.
3. **A pump returning `false` deliberately does not re-arm** (udp_association.go:386); the fd stays registered but idle until deregistration. An unconditional `rearm` spins a worker on a permanently-readable errored fd.

`reactorFds` is unsynchronized by design — appended only from `serveSocket` calls on the `handleUDP` goroutine before the control-watch loop starts. Note also that pumps still issue a *blocking* `ReadMsgUDP` while holding `reg.mu`, which is safe only because epoll already signalled readiness; changes that make spurious wakeups possible (edge-triggered mode, two registrations per fd, a second reader on one socket) turn teardown into a hang.

The `config.UDPConfig` fields map 1:1 to the `--udp-*` flags; `MaxPacketSize` also bounds per-buffer memory, so small-packet pools (DNS/QUIC) can lower it to save RAM.

**Socket buffer sizing** (`internal/connect/sockbuf*.go`): on Linux `TuneUDPBuffers` tries `SO_RCVBUFFORCE`/`SO_SNDBUFFORCE` first — these bypass the `net.core.rmem_max`/`wmem_max` sysctls but require `CAP_NET_ADMIN` — then falls back to the clamped `SetReadBuffer`/`SetWriteBuffer`. `VerifyUDPBufferTuning` probes the granted size on a throwaway socket at startup (`warnIfUDPBufferClamped`, run.go:187) and warns when clamped. Note Linux reports **2×** the requested value on read-back.

### Platform-specific files

Several concerns split by build constraint (`_linux.go` / `_unix.go` / `_windows.go` / `_other.go`):
- `internal/server/route_linux.go` configures policy routing for the CIDR (no-op elsewhere via the `configureRoutes` function variable in `run.go`).
- `internal/connect/sockopts_*.go` sets socket options (SO_REUSEADDR, TCP user timeout); `sockbuf_*.go` sizes UDP buffers.
- `internal/server/socks/udp_{reactor,io,gso,gro,trunc}_*.go` — the UDP fast paths.
- `internal/serverbase/{copy,reuseport}_*.go` — splice and SO_REUSEPORT.
- `internal/systemd` installs and controls the Linux service; `systemd_linux.go` / `systemd_other.go` keep the root package cross-platform. The generated unit sets `StateDirectory=outway` (0700), sandboxing directives, and only the capabilities the flags actually require.
- `internal/state` resolves persistent certificate storage, preferring systemd's `STATE_DIRECTORY` (tests set it via `t.Setenv`). On Linux, root with no `HOME` (a bare unit without `StateDirectory=`) falls back to `/var/lib/outway`; `goos`/`geteuid`/`userHomeDir` are swappable for tests.

When touching connection setup, routing, systemd service management, or state paths, check platform build tags and keep variants in sync.

### Self-update

`internal/oneself` downloads release assets from GitHub and replaces the running executable. It also owns `currentVersion` (injected via ldflags by release.yml from the tag; `oneself.Version()` backs `outway --version` and `outway version`).

- The constants point at **this repo** (`repoOwner = "xiaozhou26"`, `repoName = "outway"`). Before v0.9.0 they pointed at the upstream Rust repo, so older binaries' `self update` looks there.
- `findAsset` first matches the exact name release.yml publishes (`goAssetName`: `outway-<goos>-<goarch>.tar.gz`, or `.zip` on Windows). Rust-style triples from `currentTarget()` and a loose OS+arch match are fallbacks. The archives contain `outway-<goos>-<goarch>[.exe]`, which `isBinaryName` accepts alongside a plain `outway`. Changing the release asset naming affects whether `self update` finds anything; `TestGoAssetNameMatchesReleaseWorkflow` pins it.
