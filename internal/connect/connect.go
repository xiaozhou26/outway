// Package connect implements outbound connection establishment with optional
// CIDR-based source address selection, fallback addresses/interfaces, and
// dual-stack UDP support. It mirrors the Rust outway connect module.
package connect

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/xiaozhou26/outway/internal/config"
	"github.com/xiaozhou26/outway/internal/ext"
	"github.com/xiaozhou26/outway/internal/randx"
)

// TargetAddr represents a connection target: either a direct socket address or
// a host:port to be resolved.
type TargetAddr struct {
	Addr *netip.AddrPort // non-nil for a direct socket address
	Host string          // domain or IP literal (when Addr is nil)
	Port uint16
}

// FromAddr builds a TargetAddr from a direct socket address.
func FromAddr(addr netip.AddrPort) TargetAddr {
	return TargetAddr{Addr: &addr}
}

// FromHost builds a TargetAddr from a host and port (resolved later).
func FromHost(host string, port uint16) TargetAddr {
	return TargetAddr{Host: host, Port: port}
}

// Connector holds outbound connection configuration shared across TCP/UDP/HTTP
// connectors.
type Connector struct {
	CIDR           *netip.Prefix
	CIDRRange      *uint8
	Fallback       *config.Fallback
	ConnectTimeout time.Duration
	TCPUserTimeout *time.Duration // Linux only
	// Congestion, when non-empty, is set with TCP_CONGESTION on every
	// outbound TCP socket (Linux only). Run probes it at startup with
	// ProbeCongestion, so a per-dial failure means the kernel changed since.
	Congestion string
	ReuseAddr  *bool
	// SessionSpread maps session/TTL extensions onto the whole host field
	// through a strong 64→128-bit mixer instead of the Rust-compatible
	// `base | value mod capacity`, so sessions spread across every subnet of a
	// short prefix and adjacent IDs land on unrelated addresses. Off by
	// default because enabling it remaps every existing session.
	SessionSpread bool
	// StrictSource pins targets that have an address in the CIDR's family to
	// the CIDR source: other-family addresses are discarded and the fallback
	// is never raced. The fallback serves only targets with no CIDR-family
	// address.
	StrictSource bool
	// PrepareSource, when non-nil, runs on every source address chosen from
	// the CIDR before it is bound (e.g. installing a proxy-NDP entry). It must
	// be cheap for already-seen addresses and must not fail the dial.
	PrepareSource func(netip.Addr)
	dialSlots     chan struct{}
	// udpDialSlots bounds concurrent outbound UDP socket creations with the
	// same budget and semantics as dialSlots (0 = unbounded), so association
	// or tunnel bursts cannot exhaust fds without backpressure.
	udpDialSlots chan struct{}
	// udpCreating is the in-flight UDP-creation gauge exposed for tests and
	// debugging; it reports the semaphore's occupancy, not a lock.
	udpCreating atomic.Int32

	// dialTCP is nil in production; tests use it to deterministically exercise
	// the connection race without depending on kernel routing behavior.
	dialTCP func(context.Context, netip.Addr, string, netip.AddrPort) (*net.TCPConn, error)
}

// New creates a Connector from boot configuration. maxPendingDials caps
// concurrent outbound TCP dials and UDP socket creations (0 leaves both
// unbounded).
func New(cidr *netip.Prefix, cidrRange *uint8, fallback *config.Fallback, connectTimeoutSec uint64, tcpUserTimeout *uint64, reuseaddr *bool, maxPendingDials int) *Connector {
	c := &Connector{
		CIDR:           cidr,
		CIDRRange:      cidrRange,
		Fallback:       fallback,
		ConnectTimeout: time.Duration(connectTimeoutSec) * time.Second,
		ReuseAddr:      reuseaddr,
	}
	if maxPendingDials > 0 {
		c.dialSlots = make(chan struct{}, maxPendingDials)
		c.udpDialSlots = make(chan struct{}, maxPendingDials)
	}
	if tcpUserTimeout != nil {
		d := time.Duration(*tcpUserTimeout) * time.Second
		c.TCPUserTimeout = &d
	}
	return c
}

// acquireSlot blocks until a slot in the given semaphore frees up or ctx ends.
func (c *Connector) acquireSlot(slots chan struct{}, ctx context.Context) error {
	if slots == nil {
		return nil
	}
	select {
	case slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Connector) releaseSlot(slots chan struct{}) {
	if slots != nil {
		<-slots
	}
}

// TCP returns a TCP connector bound to the given extension. The connector is
// returned by value: it is two pointers' worth of state (16-byte Extension plus
// the parent pointer), so per-request construction stays on the caller's stack
// instead of escaping to the heap.
func (c *Connector) TCP(e ext.Extension) TcpConnector {
	return TcpConnector{inner: c, extension: e}
}

// UDP returns a UDP connector bound to the given extension, returned by value
// for the same reason as TCP.
func (c *Connector) UDP(e ext.Extension) UdpConnector {
	return UdpConnector{inner: c, extension: e}
}

// TcpConnector establishes outbound TCP connections using the parent
// Connector's source-address policy.
type TcpConnector struct {
	inner     *Connector
	extension ext.Extension
}

// SocketAddr returns a bind address (port 0) chosen from the CIDR, fallback, or
// the default function. Used by SOCKS5 BIND.
func (t TcpConnector) SocketAddr(defaultFn func() (netip.Addr, error)) (netip.AddrPort, error) {
	if t.inner.CIDR != nil {
		return netip.AddrPortFrom(t.inner.sourceIP(t.extension), 0), nil
	}
	if t.inner.Fallback != nil && !t.inner.Fallback.IsInterface() {
		return netip.AddrPortFrom(t.inner.Fallback.Address, 0), nil
	}
	ip, err := defaultFn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(ip, 0), nil
}

// Connect establishes a TCP connection to the given target address.
func (t TcpConnector) Connect(ctx context.Context, target TargetAddr) (*net.TCPConn, error) {
	ctx, cancel := context.WithTimeout(ctx, t.inner.ConnectTimeout)
	defer cancel()

	var addrs []netip.AddrPort
	if target.Addr != nil {
		return t.connectAddr(ctx, *target.Addr)
	} else {
		resolved, err := resolveHost(ctx, target.Host, target.Port)
		if err != nil {
			return nil, err
		}
		addrs = t.inner.strictAddrs(resolved)
	}

	return t.connectAny(ctx, addrs)
}

func (t TcpConnector) connectAny(ctx context.Context, addrs []netip.AddrPort) (*net.TCPConn, error) {
	if len(addrs) == 0 {
		return nil, errors.New("failed to connect to any resolved address")
	}
	if len(addrs) == 1 {
		return t.connectAddr(ctx, addrs[0])
	}

	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan connResult)
	start := func(addr netip.AddrPort) {
		go func() {
			conn, err := t.connectAddr(raceCtx, addr)
			result := connResult{conn: conn, err: err}
			select {
			case results <- result:
			case <-raceCtx.Done():
				if conn != nil {
					_ = conn.Close()
				}
			}
		}()
	}

	const addressFallbackDelay = 250 * time.Millisecond
	started := 1
	completed := 0
	start(addrs[0])
	timer := time.NewTimer(addressFallbackDelay)
	defer timer.Stop()
	resetTimer := func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(addressFallbackDelay)
	}
	var lastErr error

	for {
		select {
		case result := <-results:
			completed++
			if result.err == nil {
				cancel()
				return result.conn, nil
			}
			lastErr = result.err
			if completed == len(addrs) {
				return nil, lastErr
			}
			if completed == started && started < len(addrs) {
				start(addrs[started])
				started++
				if started < len(addrs) {
					resetTimer()
				}
			}
		case <-timer.C:
			if started < len(addrs) {
				start(addrs[started])
				started++
				if started < len(addrs) {
					resetTimer()
				}
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (t TcpConnector) connectAddr(ctx context.Context, target netip.AddrPort) (*net.TCPConn, error) {
	if t.inner.CIDR != nil && t.inner.CIDR.Addr().Is4() != target.Addr().Is4() {
		if t.inner.Fallback != nil {
			return t.connectWithFallback(ctx, target, *t.inner.Fallback)
		}
		return nil, fmt.Errorf("target %s address family does not match source CIDR %s; configure a fallback for dual-stack proxying", target, *t.inner.CIDR)
	}
	switch {
	case t.inner.CIDR != nil && t.inner.Fallback != nil && !t.inner.StrictSource:
		return t.connectWithCIDRFallback(ctx, target, *t.inner.CIDR, *t.inner.Fallback)
	case t.inner.CIDR != nil:
		return t.connectWithCIDR(ctx, target, *t.inner.CIDR)
	case t.inner.Fallback != nil:
		return t.connectWithFallback(ctx, target, *t.inner.Fallback)
	default:
		return t.connectPlain(ctx, target)
	}
}

// dialContext builds a net.Dialer with the configured source address and socket
// options, then dials the target.
func (t TcpConnector) dialContext(ctx context.Context, bindIP netip.Addr, bindInterface string, target netip.AddrPort) (*net.TCPConn, error) {
	if err := t.inner.acquireSlot(t.inner.dialSlots, ctx); err != nil {
		return nil, err
	}
	defer t.inner.releaseSlot(t.inner.dialSlots)
	if t.inner.dialTCP != nil {
		return t.inner.dialTCP(ctx, bindIP, bindInterface, target)
	}

	dialer := &net.Dialer{
		Timeout:   t.inner.ConnectTimeout,
		KeepAlive: 60 * time.Second,
	}

	if bindIP.IsValid() {
		dialer.LocalAddr = &net.TCPAddr{IP: net.IP(bindIP.AsSlice()), Port: 0}
	}

	dialer.Control = func(network, address string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			sockErr = applySocketOptions(fd, network, bindInterface, t.inner)
		})
		if err != nil {
			return err
		}
		return sockErr
	}

	conn, err := dialer.DialContext(ctx, "tcp", target.String())
	if err != nil {
		return nil, err
	}
	tc := conn.(*net.TCPConn)
	_ = tc.SetNoDelay(true)
	if debugEnabled() {
		logger().Debug("TCP connected", "target", target, "local", tc.LocalAddr())
	}
	return tc, nil
}

// The connect* helpers below rely on the deadline Connect placed on ctx: it
// starts earlier than any per-attempt timer would, so wrapping ctx again here
// would only add a redundant timer and a child registration per dial.

func (t TcpConnector) connectPlain(ctx context.Context, target netip.AddrPort) (*net.TCPConn, error) {
	return t.dialContext(ctx, netip.Addr{}, "", target)
}

func (t TcpConnector) connectWithCIDR(ctx context.Context, target netip.AddrPort, _ netip.Prefix) (*net.TCPConn, error) {
	bindIP := t.inner.sourceIP(t.extension)
	return t.dialContext(ctx, bindIP, "", target)
}

func (t TcpConnector) connectWithFallback(ctx context.Context, target netip.AddrPort, fb config.Fallback) (*net.TCPConn, error) {
	var bindIP netip.Addr
	iface := ""
	if fb.IsInterface() {
		iface = fb.Interface
	} else {
		bindIP = fb.Address
	}
	return t.dialContext(ctx, bindIP, iface, target)
}

type connResult struct {
	conn *net.TCPConn
	err  error
}

// connectWithCIDRFallback tries the CIDR-preferred path first; if it does not
// complete within the connect timeout it also races the fallback path,
// returning the first success.
func (t TcpConnector) connectWithCIDRFallback(ctx context.Context, target netip.AddrPort, cidr netip.Prefix, fb config.Fallback) (*net.TCPConn, error) {
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	// An unbuffered result channel ensures a losing successful dial cannot be
	// queued after the winner returns; cancellation instead closes that socket.
	results := make(chan connResult)
	startDial := func(dial func() (*net.TCPConn, error)) {
		go func() {
			conn, err := dial()
			result := connResult{conn: conn, err: err}
			select {
			case results <- result:
			case <-raceCtx.Done():
				if conn != nil {
					_ = conn.Close()
				}
			}
		}()
	}

	startDial(func() (*net.TCPConn, error) {
		return t.connectWithCIDR(raceCtx, target, cidr)
	})

	fallbackDelay := 500 * time.Millisecond
	if halfTimeout := t.inner.ConnectTimeout / 2; halfTimeout < fallbackDelay {
		fallbackDelay = halfTimeout
	}
	timer := time.NewTimer(fallbackDelay)
	defer timer.Stop()
	fallbackStarted := false
	failures := 0
	var lastErr error

	for {
		select {
		case result := <-results:
			if result.err == nil {
				cancel()
				return result.conn, nil
			}
			lastErr = result.err
			failures++
			if !fallbackStarted {
				fallbackStarted = true
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				startDial(func() (*net.TCPConn, error) {
					return t.connectWithFallback(raceCtx, target, fb)
				})
				continue
			}
			if failures == 2 {
				return nil, lastErr
			}
		case <-timer.C:
			if !fallbackStarted {
				fallbackStarted = true
				startDial(func() (*net.TCPConn, error) {
					return t.connectWithFallback(raceCtx, target, fb)
				})
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// UdpConnector establishes outbound UDP sockets using the parent Connector's
// source-address policy.
type UdpConnector struct {
	inner     *Connector
	extension ext.Extension
}

// CreateSocketDualStack creates one or two UDP sockets for dual-stack outbound
// traffic depending on the CIDR/fallback configuration. Socket creation is
// bounded by the UDP dial budget; ctx ends the wait for a slot.
func (u UdpConnector) CreateSocketDualStack(ctx context.Context) (*net.UDPConn, *net.UDPConn, error) {
	if err := u.inner.acquireSlot(u.inner.udpDialSlots, ctx); err != nil {
		return nil, nil, err
	}
	defer u.inner.releaseSlot(u.inner.udpDialSlots)
	u.inner.udpCreating.Add(1)
	defer u.inner.udpCreating.Add(-1)

	cidr := u.inner.CIDR
	fb := u.inner.Fallback

	switch {
	case cidr != nil && fb != nil && !fb.IsInterface():
		preferred, err := u.createSocketWithCIDR(*cidr)
		if err != nil {
			return nil, nil, err
		}
		fallback, err := u.createSocketWithAddr(fb.Address)
		if err != nil {
			_ = preferred.Close()
			return nil, nil, err
		}
		return preferred, fallback, nil
	case cidr == nil && fb != nil && !fb.IsInterface():
		fallback, err := u.createSocketWithAddr(fb.Address)
		if err != nil {
			return nil, nil, err
		}
		return fallback, nil, nil
	case cidr != nil:
		preferred, err := u.createSocketWithCIDR(*cidr)
		if err != nil {
			return nil, nil, err
		}
		return preferred, nil, nil
	default:
		preferred, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			return nil, nil, err
		}
		fallback, ferr := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6zero, Port: 0})
		if ferr != nil {
			return preferred, nil, nil
		}
		return preferred, fallback, nil
	}
}

func (u UdpConnector) createSocketWithAddr(ip netip.Addr) (*net.UDPConn, error) {
	return net.ListenUDP("udp", &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: 0})
}

func (u UdpConnector) createSocketWithCIDR(_ netip.Prefix) (*net.UDPConn, error) {
	ip := u.inner.sourceIP(u.extension)
	return u.createSocketWithAddr(ip)
}

// Connect resolves target and returns a connected UDP socket using the same
// CIDR, fallback address, and fallback interface policy as TCP connections.
// Targets matching the configured CIDR family are attempted first, followed by
// targets that can use the fallback path.
func (u UdpConnector) Connect(ctx context.Context, target TargetAddr) (*net.UDPConn, error) {
	ctx, cancel := context.WithTimeout(ctx, u.inner.ConnectTimeout)
	defer cancel()

	// Resolve before taking a dial slot: a cold DNS lookup must not hold
	// fd-budget backpressure hostage, mirroring TcpConnector.Connect.
	var addrs []netip.AddrPort
	if target.Addr != nil {
		addrs = []netip.AddrPort{*target.Addr}
	} else {
		resolved, err := resolveHost(ctx, target.Host, target.Port)
		if err != nil {
			return nil, err
		}
		addrs = u.inner.strictAddrs(resolved)
	}

	if err := u.inner.acquireSlot(u.inner.udpDialSlots, ctx); err != nil {
		return nil, err
	}
	defer u.inner.releaseSlot(u.inner.udpDialSlots)
	u.inner.udpCreating.Add(1)
	defer u.inner.udpCreating.Add(-1)

	var lastErr error
	if u.inner.CIDR != nil {
		for _, addr := range addrs {
			if u.inner.CIDR.Addr().Is4() != addr.Addr().Is4() {
				continue
			}
			bindIP := u.inner.sourceIP(u.extension)
			conn, err := u.dialContext(ctx, bindIP, "", addr)
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
	}
	for _, addr := range addrs {
		if u.inner.pinnedToCIDR(addr) {
			continue
		}
		bindIP, iface, ok := u.fallbackBindForTarget(addr)
		if !ok {
			continue
		}
		conn, err := u.dialContext(ctx, bindIP, iface, addr)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("failed to connect UDP socket to any resolved address")
	}
	return nil, lastErr
}

func (u UdpConnector) fallbackBindForTarget(target netip.AddrPort) (bindIP netip.Addr, iface string, ok bool) {
	if fallback := u.inner.Fallback; fallback != nil {
		if fallback.IsInterface() {
			return netip.Addr{}, fallback.Interface, true
		}
		if fallback.Address.Is4() == target.Addr().Is4() {
			return fallback.Address, "", true
		}
		return netip.Addr{}, "", false
	}
	if u.inner.CIDR == nil {
		return netip.Addr{}, "", true
	}
	return netip.Addr{}, "", false
}

func (u UdpConnector) dialContext(ctx context.Context, bindIP netip.Addr, iface string, target netip.AddrPort) (*net.UDPConn, error) {
	network := "udp6"
	wildcard := net.IPv6zero
	if target.Addr().Is4() {
		network = "udp4"
		wildcard = net.IPv4zero
	}
	localIP := wildcard
	if bindIP.IsValid() {
		localIP = net.IP(bindIP.AsSlice())
	}
	dialer := net.Dialer{LocalAddr: &net.UDPAddr{IP: localIP}}
	if iface != "" {
		dialer.Control = func(_, _ string, raw syscall.RawConn) error {
			var sockErr error
			if err := raw.Control(func(fd uintptr) {
				sockErr = bindToDevice(int(fd), iface)
			}); err != nil {
				return err
			}
			return sockErr
		}
	}
	conn, err := dialer.DialContext(ctx, network, target.String())
	if err != nil {
		return nil, err
	}
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("UDP dial returned an unexpected connection type")
	}
	return udpConn, nil
}

// SendPacket sends a UDP packet to the target address using the preferred and
// optional fallback outbound sockets. Resolution is bounded by the connect
// timeout; the sends themselves are best-effort datagram writes that inherit
// the caller's context.
func (u UdpConnector) SendPacket(ctx context.Context, pkt []byte, target TargetAddr, preferred, fallback *net.UDPConn) (int, error) {
	var addrs []netip.AddrPort
	if target.Addr != nil {
		addrs = []netip.AddrPort{*target.Addr}
	} else {
		resolveCtx, cancel := context.WithTimeout(ctx, u.inner.ConnectTimeout)
		resolved, err := resolveHost(resolveCtx, target.Host, target.Port)
		cancel()
		if err != nil {
			return 0, err
		}
		addrs = u.inner.strictAddrs(resolved)
	}

	var lastErr error
	for _, addr := range addrs {
		n, err := u.sendPacketWithAddr(ctx, pkt, addr, preferred, fallback)
		if err == nil {
			return n, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("failed to send packet to any resolved address")
	}
	return 0, lastErr
}

func (u UdpConnector) sendPacketWithAddr(ctx context.Context, pkt []byte, addr netip.AddrPort, preferred, fallback *net.UDPConn) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	n, err := u.trySendTo(pkt, addr, preferred)
	if err == nil || fallback == nil || u.inner.pinnedToCIDR(addr) {
		return n, err
	}
	return u.trySendTo(pkt, addr, fallback)
}

func (u UdpConnector) trySendTo(pkt []byte, addr netip.AddrPort, s *net.UDPConn) (int, error) {
	// WriteToUDPAddrPort avoids the *net.UDPAddr allocation of WriteToUDP.
	return s.WriteToUDPAddrPort(pkt, addr)
}

// PreferCIDRFamily reports whether StrictSource is in effect, so callers that
// pick among resolved addresses themselves (the SOCKS5 UDP batch path) must
// choose a CIDR-family address whenever one exists.
func (u UdpConnector) PreferCIDRFamily() bool {
	return u.inner.StrictSource && u.inner.CIDR != nil
}

// LookupCachedHost returns resolved addresses for host from the DNS cache
// without triggering a lookup, so a caller on a latency-sensitive path can take
// a fast route for already-resolved hosts and defer cold lookups elsewhere. An
// IP literal resolves to itself. ok is false on a cache miss.
func LookupCachedHost(host string) ([]netip.Addr, bool) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, true
	}
	return defaultDNSCache.LookupCached(host)
}

// resolveHost resolves a host:port to a list of socket addresses.
func resolveHost(ctx context.Context, host string, port uint16) ([]netip.AddrPort, error) {
	// Fast path: literal IP.
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.AddrPort{netip.AddrPortFrom(ip, port)}, nil
	}

	ips, err := defaultDNSCache.Lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	addrs := make([]netip.AddrPort, len(ips))
	for index, ip := range ips {
		addrs[index] = netip.AddrPortFrom(ip, port)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("failed to resolve %s", host)
	}
	return addrs, nil
}

// sourceIP picks the CIDR source address for e and runs the PrepareSource
// hook on it. The caller must have checked that c.CIDR is set.
func (c *Connector) sourceIP(e ext.Extension) netip.Addr {
	ip := assignSourceIP(*c.CIDR, c.CIDRRange, e, c.SessionSpread)
	if c.PrepareSource != nil {
		c.PrepareSource(ip)
	}
	return ip
}

// pinnedToCIDR reports whether StrictSource forbids sending traffic for addr
// anywhere but the CIDR source, i.e. addr is in the CIDR's family.
func (c *Connector) pinnedToCIDR(addr netip.AddrPort) bool {
	return c.StrictSource && c.CIDR != nil && c.CIDR.Addr().Is4() == addr.Addr().Unmap().Is4()
}

// strictAddrs applies StrictSource to a resolved address list: when any
// address is in the CIDR's family, only those are kept, so neither the
// Happy-Eyeballs race nor the fallback can carry the connection out over the
// other family. A target with no CIDR-family address is returned unchanged
// and is served by the fallback.
func (c *Connector) strictAddrs(addrs []netip.AddrPort) []netip.AddrPort {
	if !c.StrictSource || c.CIDR == nil {
		return addrs
	}
	matching := 0
	for _, addr := range addrs {
		if c.pinnedToCIDR(addr) {
			matching++
		}
	}
	if matching == 0 || matching == len(addrs) {
		return addrs
	}
	kept := make([]netip.AddrPort, 0, matching)
	for _, addr := range addrs {
		if c.pinnedToCIDR(addr) {
			kept = append(kept, addr)
		}
	}
	return kept
}

// assignSourceIP picks a source IP from the CIDR for the given extension.
// spread selects the session-spread mapping for session/TTL extensions.
func assignSourceIP(cidr netip.Prefix, cidrRange *uint8, e ext.Extension, spread bool) netip.Addr {
	if spread {
		if value, ok := sessionValue(e); ok {
			if cidr.Addr().Is4() {
				return spreadIPv4(cidr, value)
			}
			return spreadIPv6(cidr, value)
		}
	}
	if cidr.Addr().Is4() {
		return assignIPv4FromExtension(cidr, cidrRange, e)
	}
	return assignIPv6FromExtension(cidr, cidrRange, e)
}

// sessionValue returns the hash carried by a session or TTL extension, the
// two extension types that pin a client to one address.
func sessionValue(e ext.Extension) (uint64, bool) {
	switch e.Type {
	case ext.ExtSession, ext.ExtTTL:
		return e.Value, true
	default:
		return 0, false
	}
}

// splitmixGamma is the splitmix64 increment (2^64 / golden ratio).
const splitmixGamma = 0x9e3779b97f4a7c15

// splitmix64 is one splitmix64 step on state x: a full-avalanche 64-bit
// bijection, so inputs that differ in a single bit produce unrelated outputs.
func splitmix64(x uint64) uint64 {
	x += splitmixGamma
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	return x ^ (x >> 31)
}

// spreadBits expands value into 128 well-mixed bits: two consecutive outputs
// of a splitmix64 generator seeded with value.
func spreadBits(value uint64) uint128 {
	return uint128{hi: splitmix64(value), lo: splitmix64(value + splitmixGamma)}
}

// spreadIPv6 deterministically maps value onto every host bit of cidr
// (including the subnet bits of a prefix shorter than /64). A zero low word
// is replaced with 1, which rules out the all-zero host and, for prefixes up
// to /64, the subnet-router anycast interface ID.
func spreadIPv6(cidr netip.Prefix, value uint64) netip.Addr {
	prefixLen := uint(cidr.Bits())
	if prefixLen >= 128 {
		return cidr.Masked().Addr()
	}
	hostMask := newUint128FromBitRange(128 - prefixLen)
	host := andUint128(spreadBits(value), hostMask)
	if host.lo == 0 {
		host.lo = 1
	}
	base := andUint128(ipv6ToUint128(cidr.Masked().Addr()), notUint128(hostMask))
	return uint128ToIPv6(orUint128(base, host))
}

// spreadIPv4 deterministically maps value onto the host bits of cidr,
// avoiding the network (all-zero) and, when the prefix has room for it, the
// broadcast (all-ones) address.
func spreadIPv4(cidr netip.Prefix, value uint64) netip.Addr {
	prefixLen := uint(cidr.Bits())
	if prefixLen >= 32 {
		return cidr.Masked().Addr()
	}
	hostBits := 32 - prefixLen
	base := ipv4ToUint32(cidr.Masked().Addr())
	host := uint32(1) // a /31 has no broadcast; its non-zero host is .1
	if hostBits >= 2 {
		usable := (uint64(1) << hostBits) - 2
		host = uint32(1 + splitmix64(value)%usable)
	}
	return uint32ToIPv4(base | host)
}

// extractValue returns the u64 carried by the extension, if any.
func extractValue(e ext.Extension) (uint64, bool) {
	switch e.Type {
	case ext.ExtRange, ext.ExtSession, ext.ExtTTL:
		return e.Value, true
	default:
		return 0, false
	}
}

// assignIPv4FromExtension mirrors the Rust assign_ipv4_from_extension.
func assignIPv4FromExtension(cidr netip.Prefix, cidrRange *uint8, e ext.Extension) netip.Addr {
	if combined, ok := extractValue(e); ok {
		switch e.Type {
		case ext.ExtTTL, ext.ExtSession:
			prefixLen := uint(cidr.Bits())
			if prefixLen >= 32 {
				return cidr.Masked().Addr()
			}
			subnetMask := uint32(0xffffffff) << (32 - prefixLen)
			base := ipv4ToUint32(cidr.Masked().Addr()) & subnetMask
			capacity := uint32(1<<(32-prefixLen)) - 1
			if capacity == 0 {
				return cidr.Masked().Addr()
			}
			return uint32ToIPv4(base | (uint32(combined) % capacity))
		case ext.ExtRange:
			if cidrRange != nil {
				return assignIPv4WithRange(cidr, *cidrRange, uint32(combined))
			}
		}
	}
	return assignRandIPv4(cidr)
}

// assignIPv6FromExtension mirrors the Rust assign_ipv6_from_extension.
func assignIPv6FromExtension(cidr netip.Prefix, cidrRange *uint8, e ext.Extension) netip.Addr {
	if combined, ok := extractValue(e); ok {
		switch e.Type {
		case ext.ExtTTL, ext.ExtSession:
			prefixLen := uint(cidr.Bits())
			if prefixLen >= 128 {
				return cidr.Masked().Addr()
			}
			hostBits := 128 - prefixLen
			mask := newUint128FromBitRange(hostBits) // (1 << hostBits) - 1
			base := ipv6ToUint128(cidr.Masked().Addr())
			subnetMask := notUint128(mask) // subnet mask
			capacity := subUint128(newUint128LShiftOne(hostBits), uint128One())
			if isZeroUint128(capacity) {
				return cidr.Masked().Addr()
			}
			combined128 := uint128FromU64(combined)
			mod := modUint128(combined128, capacity)
			result := orUint128(andUint128(base, subnetMask), mod)
			return uint128ToIPv6(result)
		case ext.ExtRange:
			if cidrRange != nil {
				return assignIPv6WithRange(cidr, *cidrRange, uint128FromU64(combined))
			}
		}
	}
	return assignRandIPv6(cidr)
}

// assignRandIPv4 generates a random IPv4 within the CIDR.
func assignRandIPv4(cidr netip.Prefix) netip.Addr {
	prefixLen := uint(cidr.Bits())
	base := ipv4ToUint32(cidr.Masked().Addr())
	r := randx.RandomU32()
	netPart := (base >> (32 - prefixLen)) << (32 - prefixLen)
	hostPart := (r << prefixLen) >> prefixLen
	return uint32ToIPv4(netPart | hostPart)
}

// assignRandIPv6 generates a random IPv6 within the CIDR.
func assignRandIPv6(cidr netip.Prefix) netip.Addr {
	prefixLen := uint(cidr.Bits())
	base := ipv6ToUint128(cidr.Masked().Addr())
	r := randx.RandomU128()
	r128 := bytesToUint128(r)
	// netPart: keep the top prefixLen bits of base, zero the rest.
	// mask = ~((1 << (128 - prefixLen)) - 1)  [top prefixLen bits set]
	hostBits := 128 - prefixLen
	netMask := notUint128(newUint128FromBitRange(hostBits))
	netPart := andUint128(base, netMask)
	// hostPart: keep the bottom (128 - prefixLen) bits of r, zero the top.
	hostMask := newUint128FromBitRange(hostBits)
	hostPart := andUint128(r128, hostMask)
	return uint128ToIPv6(orUint128(netPart, hostPart))
}

// assignIPv4WithRange mirrors the Rust assign_ipv4_with_range.
func assignIPv4WithRange(cidr netip.Prefix, rng uint8, combined uint32) netip.Addr {
	base := ipv4ToUint32(cidr.Masked().Addr())
	prefixLen := uint(cidr.Bits())

	if uint(rng) < prefixLen {
		return assignRandIPv4(cidr)
	}

	combinedShifted := (combined & ((1 << (uint(rng) - prefixLen)) - 1)) << (32 - uint(rng))
	subnetMask := uint32(0xffffffff) << (32 - prefixLen)
	subnetWithFixed := (base & subnetMask) | combinedShifted
	hostMask := uint32(1<<(32-uint(rng))) - 1
	hostPart := randx.RandomU32() & hostMask
	return uint32ToIPv4(subnetWithFixed | hostPart)
}

// assignIPv6WithRange mirrors the Rust assign_ipv6_with_range.
func assignIPv6WithRange(cidr netip.Prefix, rng uint8, combined uint128) netip.Addr {
	base := ipv6ToUint128(cidr.Masked().Addr())
	prefixLen := uint(cidr.Bits())

	if uint(rng) < prefixLen {
		return assignRandIPv6(cidr)
	}

	rngU := uint(rng)
	maskBits := uint128FromU64(0)
	if rngU-prefixLen < 128 {
		maskBits = subUint128(newUint128LShiftOne(rngU-prefixLen), uint128One())
	}
	combinedShifted := shlUint128(andUint128(combined, maskBits), 128-rngU)
	subnetMask := notUint128(subUint128(newUint128LShiftOne(128-prefixLen), uint128One()))
	subnetWithFixed := orUint128(andUint128(base, subnetMask), combinedShifted)
	hostMask := subUint128(newUint128LShiftOne(128-rngU), uint128One())
	hostPart := andUint128(uint128FromU64(randx.RandomU64()), hostMask)
	return uint128ToIPv6(orUint128(subnetWithFixed, hostPart))
}

// ---- uint32 helpers ----

func ipv4ToUint32(addr netip.Addr) uint32 {
	b := addr.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func uint32ToIPv4(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// applySocketOptions sets SO_REUSEADDR, TCP_USER_TIMEOUT (Linux),
// TCP_CONGESTION (Linux), and SO_BINDTODEVICE (Linux) on the given socket fd.
func applySocketOptions(fd uintptr, network, iface string, c *Connector) error {
	if c.ReuseAddr != nil && *c.ReuseAddr {
		_ = setReuseAddr(fd)
	}

	if runtime.GOOS == "linux" {
		if c.TCPUserTimeout != nil && (network == "tcp" || network == "tcp4" || network == "tcp6") {
			ms := int(c.TCPUserTimeout.Milliseconds())
			_ = setTCPUserTimeout(int(fd), ms)
		}
		if c.Congestion != "" && (network == "tcp" || network == "tcp4" || network == "tcp6") {
			if err := setCongestion(int(fd), c.Congestion); err != nil {
				return fmt.Errorf("set TCP congestion control %q: %w", c.Congestion, err)
			}
		}
		if iface != "" {
			if err := bindToDevice(int(fd), iface); err != nil {
				return err
			}
		}
	}
	return nil
}
