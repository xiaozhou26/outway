// Package connect implements outbound connection establishment with optional
// CIDR-based source address selection, fallback addresses/interfaces, and
// dual-stack UDP support. It mirrors the Rust outway connect module.
package connect

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
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
	ReuseAddr      *bool
	dialSlots      chan struct{}
}

// New creates a Connector from boot configuration. maxPendingDials caps
// concurrent outbound TCP dials; zero or negative leaves dialing unbounded.
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
	}
	if tcpUserTimeout != nil {
		d := time.Duration(*tcpUserTimeout) * time.Second
		c.TCPUserTimeout = &d
	}
	return c
}

// TCP returns a TCP connector bound to the given extension.
func (c *Connector) TCP(e ext.Extension) *TcpConnector {
	return &TcpConnector{inner: c, extension: e}
}

// UDP returns a UDP connector bound to the given extension.
func (c *Connector) UDP(e ext.Extension) *UdpConnector {
	return &UdpConnector{inner: c, extension: e}
}

// TcpConnector establishes outbound TCP connections using the parent
// Connector's source-address policy.
type TcpConnector struct {
	inner     *Connector
	extension ext.Extension
}

// SocketAddr returns a bind address (port 0) chosen from the CIDR, fallback, or
// the default function. Used by SOCKS5 BIND.
func (t *TcpConnector) SocketAddr(defaultFn func() (netip.Addr, error)) (netip.AddrPort, error) {
	if t.inner.CIDR != nil {
		if t.inner.CIDR.Addr().Is4() {
			addr := assignIPv4FromExtension(*t.inner.CIDR, t.inner.CIDRRange, t.extension)
			return netip.AddrPortFrom(addr, 0), nil
		}
		addr := assignIPv6FromExtension(*t.inner.CIDR, t.inner.CIDRRange, t.extension)
		return netip.AddrPortFrom(addr, 0), nil
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
func (t *TcpConnector) Connect(ctx context.Context, target TargetAddr) (*net.TCPConn, error) {
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
		addrs = resolved
	}

	return t.connectAny(ctx, addrs)
}

func (t *TcpConnector) connectAny(ctx context.Context, addrs []netip.AddrPort) (*net.TCPConn, error) {
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

func (t *TcpConnector) connectAddr(ctx context.Context, target netip.AddrPort) (*net.TCPConn, error) {
	if t.inner.CIDR != nil && t.inner.CIDR.Addr().Is4() != target.Addr().Is4() {
		if t.inner.Fallback != nil {
			return t.connectWithFallback(ctx, target, *t.inner.Fallback)
		}
		return nil, fmt.Errorf("target %s address family does not match source CIDR %s; configure a fallback for dual-stack proxying", target, *t.inner.CIDR)
	}
	switch {
	case t.inner.CIDR != nil && t.inner.Fallback != nil:
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
func (t *TcpConnector) dialContext(ctx context.Context, bindIP netip.Addr, bindInterface string, target netip.AddrPort) (*net.TCPConn, error) {
	if t.inner.dialSlots != nil {
		select {
		case t.inner.dialSlots <- struct{}{}:
			defer func() { <-t.inner.dialSlots }()
		case <-ctx.Done():
			return nil, ctx.Err()
		}
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

func (t *TcpConnector) connectPlain(ctx context.Context, target netip.AddrPort) (*net.TCPConn, error) {
	return t.dialContext(ctx, netip.Addr{}, "", target)
}

func (t *TcpConnector) connectWithCIDR(ctx context.Context, target netip.AddrPort, cidr netip.Prefix) (*net.TCPConn, error) {
	bindIP := assignSourceIP(cidr, t.inner.CIDRRange, t.extension)
	return t.dialContext(ctx, bindIP, "", target)
}

func (t *TcpConnector) connectWithFallback(ctx context.Context, target netip.AddrPort, fb config.Fallback) (*net.TCPConn, error) {
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
func (t *TcpConnector) connectWithCIDRFallback(ctx context.Context, target netip.AddrPort, cidr netip.Prefix, fb config.Fallback) (*net.TCPConn, error) {
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
// traffic depending on the CIDR/fallback configuration.
func (u *UdpConnector) CreateSocketDualStack() (*net.UDPConn, *net.UDPConn, error) {
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
			preferred.Close()
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

func (u *UdpConnector) createSocketWithAddr(ip netip.Addr) (*net.UDPConn, error) {
	return net.ListenUDP("udp", &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: 0})
}

func (u *UdpConnector) createSocketWithCIDR(cidr netip.Prefix) (*net.UDPConn, error) {
	ip := assignSourceIP(cidr, u.inner.CIDRRange, u.extension)
	return u.createSocketWithAddr(ip)
}

// SendPacket sends a UDP packet to the target address using the preferred and
// optional fallback outbound sockets, racing them after the connect timeout.
func (u *UdpConnector) SendPacket(ctx context.Context, pkt []byte, target TargetAddr, preferred, fallback *net.UDPConn) (int, error) {
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
		addrs = resolved
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

func (u *UdpConnector) sendPacketWithAddr(ctx context.Context, pkt []byte, addr netip.AddrPort, preferred, fallback *net.UDPConn) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	n, err := u.trySendTo(pkt, addr, preferred)
	if err == nil || fallback == nil {
		return n, err
	}
	return u.trySendTo(pkt, addr, fallback)
}

func (u *UdpConnector) trySendTo(pkt []byte, addr netip.AddrPort, s *net.UDPConn) (int, error) {
	return s.WriteToUDP(pkt, net.UDPAddrFromAddrPort(addr))
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

// assignSourceIP picks a source IP from the CIDR for the given extension.
func assignSourceIP(cidr netip.Prefix, cidrRange *uint8, e ext.Extension) netip.Addr {
	if cidr.Addr().Is4() {
		return assignIPv4FromExtension(cidr, cidrRange, e)
	}
	return assignIPv6FromExtension(cidr, cidrRange, e)
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

// ---- uint128 helpers (two uint64 halves: hi, lo) ----

type uint128 struct{ hi, lo uint64 }

func uint128One() uint128             { return uint128{0, 1} }
func uint128FromU64(v uint64) uint128 { return uint128{0, v} }
func isZeroUint128(a uint128) bool    { return a.hi == 0 && a.lo == 0 }
func bytesToUint128(b [16]byte) uint128 {
	hi := uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
	lo := uint64(b[8])<<56 | uint64(b[9])<<48 | uint64(b[10])<<40 | uint64(b[11])<<32 |
		uint64(b[12])<<24 | uint64(b[13])<<16 | uint64(b[14])<<8 | uint64(b[15])
	return uint128{hi, lo}
}

func ipv6ToUint128(addr netip.Addr) uint128 { return bytesToUint128(addr.As16()) }

func uint128ToIPv6(a uint128) netip.Addr {
	b := [16]byte{}
	for i := 0; i < 8; i++ {
		b[i] = byte(a.hi >> (8 * (7 - i)))
		b[i+8] = byte(a.lo >> (8 * (7 - i)))
	}
	return netip.AddrFrom16(b)
}

// newUint128LShiftOne returns 1 << n.
func newUint128LShiftOne(n uint) uint128 {
	if n >= 128 {
		return uint128{}
	}
	if n < 64 {
		return uint128{0, 1 << n}
	}
	return uint128{1 << (n - 64), 0}
}

// newUint128FromBitRange returns (1 << n) - 1 (a mask of n low bits).
func newUint128FromBitRange(n uint) uint128 {
	if n >= 128 {
		return uint128{^uint64(0), ^uint64(0)}
	}
	if n < 64 {
		return uint128{0, (1 << n) - 1}
	}
	return uint128{(1 << (n - 64)) - 1, ^uint64(0)}
}

func notUint128(a uint128) uint128 { return uint128{^a.hi, ^a.lo} }

func andUint128(a, b uint128) uint128 { return uint128{a.hi & b.hi, a.lo & b.lo} }
func orUint128(a, b uint128) uint128  { return uint128{a.hi | b.hi, a.lo | b.lo} }

func shlUint128(a uint128, n uint) uint128 {
	if n == 0 {
		return a
	}
	if n >= 128 {
		return uint128{}
	}
	if n < 64 {
		return uint128{a.hi<<n | a.lo>>(64-n), a.lo << n}
	}
	return uint128{a.lo << (n - 64), 0}
}

func shrUint128(a uint128, n uint) uint128 {
	if n == 0 {
		return a
	}
	if n >= 128 {
		return uint128{}
	}
	if n < 64 {
		return uint128{a.hi >> n, a.lo>>n | a.hi<<(64-n)}
	}
	return uint128{0, a.hi >> (n - 64)}
}

func subUint128(a, b uint128) uint128 {
	lo := a.lo - b.lo
	carry := uint64(0)
	if a.lo < b.lo {
		carry = 1
	}
	return uint128{a.hi - b.hi - carry, lo}
}

// modUint128 computes a % b using shift-and-subtract.
func modUint128(a, b uint128) uint128 {
	if isZeroUint128(b) {
		return a
	}
	if b.hi == 0 && a.hi == 0 {
		return uint128{0, a.lo % b.lo}
	}
	// Find the highest set bit.
	r := uint128{}
	for i := 127; i >= 0; i-- {
		r = shlUint128(r, 1)
		if (a.hi>>(63-i%64))&1 != 0 || (i < 64 && (a.lo>>(63-i))&1 != 0) {
			// set bit i of r
			if i >= 64 {
				r.hi |= 1 << (i - 64)
			} else {
				r.lo |= 1 << i
			}
		}
		if cmpUint128(r, b) >= 0 {
			r = subUint128(r, b)
		}
	}
	return r
}

func cmpUint128(a, b uint128) int {
	if a.hi != b.hi {
		if a.hi > b.hi {
			return 1
		}
		return -1
	}
	if a.lo > b.lo {
		return 1
	}
	if a.lo < b.lo {
		return -1
	}
	return 0
}

// applySocketOptions sets SO_REUSEADDR, TCP_USER_TIMEOUT (Linux) and
// SO_BINDTODEVICE (Linux) on the given socket fd.
func applySocketOptions(fd uintptr, network, iface string, c *Connector) error {
	if c.ReuseAddr != nil && *c.ReuseAddr {
		_ = setReuseAddr(fd)
	}

	if runtime.GOOS == "linux" {
		if c.TCPUserTimeout != nil && (network == "tcp" || network == "tcp4" || network == "tcp6") {
			ms := int(c.TCPUserTimeout.Milliseconds())
			_ = setTCPUserTimeout(int(fd), ms)
		}
		if iface != "" {
			if err := bindToDevice(int(fd), iface); err != nil {
				return err
			}
		}
	}
	return nil
}

// readNoop silences unused-import warnings when io is not otherwise referenced.
var _ = io.EOF
