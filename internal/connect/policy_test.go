package connect

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/xiaozhou26/outway/internal/config"
	"github.com/xiaozhou26/outway/internal/ext"
)

// ---- session spread ----

func TestSplitmix64KnownVector(t *testing.T) {
	// First output of a splitmix64 generator seeded with 0.
	if got := splitmix64(0); got != 0xe220a8397b1dcdaf {
		t.Fatalf("splitmix64(0) = %#x, want 0xe220a8397b1dcdaf", got)
	}
}

func TestSessionSpreadDisabledKeepsLegacyMapping(t *testing.T) {
	v6 := netip.MustParsePrefix("2001:db8:100::/56")
	v4 := netip.MustParsePrefix("10.0.0.0/24")
	for _, e := range []ext.Extension{
		ext.TryFrom("c2a", "c2a-session-2001"),
		ext.TryFrom("c2a", "c2a-ttl-60"),
	} {
		if got, want := assignSourceIP(v6, nil, e, false), assignIPv6FromExtension(v6, nil, e); got != want {
			t.Errorf("IPv6 %v: spread=false gave %s, want legacy %s", e, got, want)
		}
		if got, want := assignSourceIP(v4, nil, e, false), assignIPv4FromExtension(v4, nil, e); got != want {
			t.Errorf("IPv4 %v: spread=false gave %s, want legacy %s", e, got, want)
		}
	}
}

func TestSessionSpreadIsDeterministicAndContained(t *testing.T) {
	for _, cidr := range []netip.Prefix{
		netip.MustParsePrefix("2604:2dc0:100:47c3::/64"),
		netip.MustParsePrefix("2001:db8:100::/56"),
		netip.MustParsePrefix("10.20.0.0/16"),
	} {
		e := ext.TryFrom("c2a", "c2a-session-acct-42")
		first := assignSourceIP(cidr, nil, e, true)
		if !cidr.Contains(first) {
			t.Fatalf("%s: %s not in prefix", cidr, first)
		}
		for range 3 {
			if again := assignSourceIP(cidr, nil, e, true); again != first {
				t.Fatalf("%s: not deterministic: %s then %s", cidr, first, again)
			}
		}
	}
}

// TestSessionSpreadFillsSubnetBits is the /56 regression: the legacy mapping
// leaves every session in the first /64, the spread mapping uses the subnet
// bits too.
func TestSessionSpreadFillsSubnetBits(t *testing.T) {
	cidr := netip.MustParsePrefix("2001:db8:100::/56")
	legacy := map[netip.Prefix]struct{}{}
	spread := map[netip.Prefix]struct{}{}
	for i := range 512 {
		e := ext.Extension{Type: ext.ExtSession, Value: uint64(i) * 7919}
		legacyAddr := assignSourceIP(cidr, nil, e, false)
		spreadAddr := assignSourceIP(cidr, nil, e, true)
		legacy[netip.PrefixFrom(legacyAddr, 64).Masked()] = struct{}{}
		spread[netip.PrefixFrom(spreadAddr, 64).Masked()] = struct{}{}
	}
	if len(legacy) != 1 {
		t.Fatalf("legacy mapping used %d /64s; the regression this guards no longer reproduces", len(legacy))
	}
	// 512 draws over 256 subnets should cover nearly all of them.
	if len(spread) < 200 {
		t.Fatalf("spread mapping used only %d of 256 /64s", len(spread))
	}
}

// TestSessionSpreadSeparatesAdjacentIDs is the poor-avalanche regression: with
// FxHash, consecutive session IDs share their low bits under the legacy
// mapping.
func TestSessionSpreadSeparatesAdjacentIDs(t *testing.T) {
	cidr := netip.MustParsePrefix("2604:2dc0:100:47c3::/64")
	a := ext.TryFrom("c2a", "c2a-session-2001")
	b := ext.TryFrom("c2a", "c2a-session-2002")
	if a.Type != ext.ExtSession || b.Type != ext.ExtSession {
		t.Fatalf("usernames did not parse as sessions: %v %v", a, b)
	}
	lowBits := func(addr netip.Addr) uint64 { return ipv6ToUint128(addr).lo & (1<<48 - 1) }
	if lowBits(assignSourceIP(cidr, nil, a, false)) != lowBits(assignSourceIP(cidr, nil, b, false)) {
		t.Log("legacy mapping already separates these IDs; keeping the spread assertion only")
	}
	spreadA, spreadB := assignSourceIP(cidr, nil, a, true), assignSourceIP(cidr, nil, b, true)
	diff := ipv6ToUint128(spreadA).lo ^ ipv6ToUint128(spreadB).lo
	if bitsSet := popcount(diff); bitsSet < 16 {
		t.Fatalf("spread addresses %s and %s differ in only %d of 64 interface-ID bits", spreadA, spreadB, bitsSet)
	}
}

func popcount(v uint64) int {
	n := 0
	for ; v != 0; v &= v - 1 {
		n++
	}
	return n
}

func TestSpreadIPv6AvoidsZeroHost(t *testing.T) {
	// A /127 has one host bit, so half of all values would hit the zero host
	// without the guard.
	cidr := netip.MustParsePrefix("2001:db8::/127")
	want := netip.MustParseAddr("2001:db8::1")
	for v := range uint64(64) {
		if got := spreadIPv6(cidr, v); got != want {
			t.Fatalf("spreadIPv6(/127, %d) = %s, want %s", v, got, want)
		}
	}
	if got := spreadIPv6(netip.MustParsePrefix("2001:db8::5/128"), 99); got != netip.MustParseAddr("2001:db8::5") {
		t.Fatalf("spreadIPv6(/128) = %s", got)
	}
	// For /64 and shorter the guard also excludes interface ID 0.
	for v := range uint64(10000) {
		if addr := spreadIPv6(netip.MustParsePrefix("2001:db8::/56"), v); ipv6ToUint128(addr).lo == 0 {
			t.Fatalf("spreadIPv6(/56, %d) = %s has a zero interface ID", v, addr)
		}
	}
}

func TestSpreadIPv4AvoidsNetworkAndBroadcast(t *testing.T) {
	cidr := netip.MustParsePrefix("192.0.2.0/24")
	seen := map[netip.Addr]struct{}{}
	for v := range uint64(20000) {
		addr := spreadIPv4(cidr, v)
		if !cidr.Contains(addr) {
			t.Fatalf("spreadIPv4(%d) = %s outside %s", v, addr, cidr)
		}
		if b := addr.As4()[3]; b == 0 || b == 255 {
			t.Fatalf("spreadIPv4(%d) = %s is the network or broadcast address", v, addr)
		}
		seen[addr] = struct{}{}
	}
	if len(seen) != 254 {
		t.Fatalf("spreadIPv4 reached %d of 254 usable hosts", len(seen))
	}
	if got := spreadIPv4(netip.MustParsePrefix("192.0.2.4/31"), 12345); got != netip.MustParseAddr("192.0.2.5") {
		t.Fatalf("spreadIPv4(/31) = %s, want 192.0.2.5", got)
	}
	if got := spreadIPv4(netip.MustParsePrefix("192.0.2.4/32"), 12345); got != netip.MustParseAddr("192.0.2.4") {
		t.Fatalf("spreadIPv4(/32) = %s, want 192.0.2.4", got)
	}
}

func TestSessionSpreadLeavesOtherExtensionsAlone(t *testing.T) {
	cidr := netip.MustParsePrefix("2001:db8::/64")
	// No extension: still a random address per call.
	a := assignSourceIP(cidr, nil, ext.None, true)
	b := assignSourceIP(cidr, nil, ext.None, true)
	if a == b {
		t.Fatalf("ext.None mapped to the same address twice (%s)", a)
	}
}

// ---- strict source ----

func TestStrictAddrsKeepsOnlyCIDRFamily(t *testing.T) {
	cidr := netip.MustParsePrefix("2001:db8::/64")
	fb := config.Fallback{Address: netip.MustParseAddr("192.0.2.1")}
	v4 := netip.MustParseAddrPort("198.51.100.1:443")
	v6 := netip.MustParseAddrPort("[2001:db8:ffff::1]:443")
	mapped := netip.AddrPortFrom(netip.AddrFrom16(netip.MustParseAddr("198.51.100.2").As16()), 443)

	c := New(&cidr, nil, &fb, 2, nil, nil, 0)
	mixed := []netip.AddrPort{v4, v6, mapped}
	if got := c.strictAddrs(mixed); len(got) != 3 {
		t.Fatalf("strict off: got %v, want input unchanged", got)
	}
	c.StrictSource = true
	if got := c.strictAddrs(mixed); len(got) != 1 || got[0] != v6 {
		t.Fatalf("strict: got %v, want only %s", got, v6)
	}
	onlyV4 := []netip.AddrPort{v4, mapped}
	if got := c.strictAddrs(onlyV4); len(got) != 2 {
		t.Fatalf("strict with no CIDR-family address: got %v, want input unchanged for the fallback", got)
	}
}

func TestStrictSourceNeverRacesFallback(t *testing.T) {
	cidr := netip.MustParsePrefix("2001:db8::/64")
	fb := config.Fallback{Address: netip.MustParseAddr("192.0.2.1")}
	c := New(&cidr, nil, &fb, 2, nil, nil, 0)
	c.StrictSource = true

	var mu sync.Mutex
	var binds []netip.Addr
	cidrErr := errors.New("cidr dial failed")
	c.dialTCP = func(_ context.Context, bind netip.Addr, _ string, _ netip.AddrPort) (*net.TCPConn, error) {
		mu.Lock()
		binds = append(binds, bind)
		mu.Unlock()
		if bind.Is6() {
			// Outlive the 500 ms fallback delay before failing.
			time.Sleep(700 * time.Millisecond)
			return nil, cidrErr
		}
		return nil, errors.New("fallback must not be dialed")
	}

	_, err := c.TCP(ext.None).connectAddr(context.Background(), netip.MustParseAddrPort("[2001:db8:ffff::1]:443"))
	if !errors.Is(err, cidrErr) {
		t.Fatalf("err = %v, want the CIDR dial error", err)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, bind := range binds {
		if !cidr.Contains(bind) {
			t.Fatalf("dialed from %s; strict source must only use the CIDR (binds %v)", bind, binds)
		}
	}
}

func TestStrictSourceUsesFallbackForOtherFamilyOnlyTargets(t *testing.T) {
	cidr := netip.MustParsePrefix("2001:db8::/64")
	fb := config.Fallback{Address: netip.MustParseAddr("192.0.2.1")}
	c := New(&cidr, nil, &fb, 2, nil, nil, 0)
	c.StrictSource = true
	client, peer := tcpPair(t)
	defer func() { _ = peer.Close() }()
	var bound netip.Addr
	c.dialTCP = func(_ context.Context, bind netip.Addr, _ string, _ netip.AddrPort) (*net.TCPConn, error) {
		bound = bind
		return client, nil
	}
	conn, err := c.TCP(ext.None).Connect(context.Background(), FromAddr(netip.MustParseAddrPort("198.51.100.1:443")))
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if bound != fb.Address {
		t.Fatalf("bound %s, want fallback %s", bound, fb.Address)
	}
}

// TestStrictSourceConnectDropsOtherFamilyBeforeRacing drives Connect through a
// stubbed DNS answer carrying both families: Happy Eyeballs must never start
// the IPv4 attempt.
func TestStrictSourceConnectDropsOtherFamilyBeforeRacing(t *testing.T) {
	saved := defaultDNSCache
	defaultDNSCache = newDNSCache(time.Minute, time.Second, 16, 4, func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("2001:db8:ffff::1")}, nil
	})
	t.Cleanup(func() { defaultDNSCache = saved })

	cidr := netip.MustParsePrefix("2001:db8::/64")
	fb := config.Fallback{Address: netip.MustParseAddr("192.0.2.1")}
	c := New(&cidr, nil, &fb, 2, nil, nil, 0)
	c.StrictSource = true

	client, peer := tcpPair(t)
	defer func() { _ = peer.Close() }()
	var mu sync.Mutex
	var targets []netip.AddrPort
	c.dialTCP = func(_ context.Context, _ netip.Addr, _ string, target netip.AddrPort) (*net.TCPConn, error) {
		mu.Lock()
		targets = append(targets, target)
		mu.Unlock()
		return client, nil
	}
	conn, err := c.TCP(ext.None).Connect(context.Background(), FromHost("dual.example", 443))
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	mu.Lock()
	defer mu.Unlock()
	if len(targets) != 1 || !targets[0].Addr().Is6() {
		t.Fatalf("dialed %v, want only the IPv6 address", targets)
	}
}

func TestUDPConnectStrictSourceNeverFallsBack(t *testing.T) {
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = target.Close() }()
	// 192.0.2.1 is not a local address, so the CIDR bind fails; without
	// strict source the same-family fallback would take over (see
	// TestUDPConnectUsesSameFamilyFallbackWhenCIDRBindFails).
	cidr := netip.MustParsePrefix("192.0.2.1/32")
	fallback := config.Fallback{Address: netip.MustParseAddr("127.0.0.1")}
	connector := New(&cidr, nil, &fallback, 1, nil, nil, 0)
	connector.StrictSource = true
	conn, err := connector.UDP(ext.None).Connect(context.Background(), FromAddr(target.LocalAddr().(*net.UDPAddr).AddrPort()))
	if err == nil {
		_ = conn.Close()
		t.Fatal("strict source fell back to the fallback address")
	}
}

func TestSendPacketStrictSourceSkipsFallbackSocket(t *testing.T) {
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sink.Close() }()
	preferred, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	_ = preferred.Close() // every send on it fails
	fallback, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fallback.Close() }()

	cidr := netip.MustParsePrefix("127.0.0.0/8")
	fb := config.Fallback{Address: netip.MustParseAddr("127.0.0.1")}
	connector := New(&cidr, nil, &fb, 1, nil, nil, 0)
	target := FromAddr(sink.LocalAddr().(*net.UDPAddr).AddrPort())

	if _, err := connector.UDP(ext.None).SendPacket(context.Background(), []byte("x"), target, preferred, fallback); err != nil {
		t.Fatalf("non-strict send should retry on the fallback socket: %v", err)
	}
	connector.StrictSource = true
	if _, err := connector.UDP(ext.None).SendPacket(context.Background(), []byte("x"), target, preferred, fallback); err == nil {
		t.Fatal("strict send leaked onto the fallback socket")
	}
	if !connector.UDP(ext.None).PreferCIDRFamily() {
		t.Fatal("PreferCIDRFamily = false with strict source and a CIDR")
	}
}

// ---- source hook ----

func TestPrepareSourceRunsBeforeDial(t *testing.T) {
	cidr := netip.MustParsePrefix("2001:db8::/64")
	c := New(&cidr, nil, nil, 2, nil, nil, 0)
	var prepared []netip.Addr
	c.PrepareSource = func(addr netip.Addr) { prepared = append(prepared, addr) }
	client, peer := tcpPair(t)
	defer func() { _ = peer.Close() }()
	var bound netip.Addr
	c.dialTCP = func(_ context.Context, bind netip.Addr, _ string, _ netip.AddrPort) (*net.TCPConn, error) {
		if len(prepared) == 0 {
			t.Error("dial ran before PrepareSource")
		}
		bound = bind
		return client, nil
	}
	e := ext.Extension{Type: ext.ExtSession, Value: 7}
	conn, err := c.TCP(e).Connect(context.Background(), FromAddr(netip.MustParseAddrPort("[2001:db8:ffff::1]:443")))
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if len(prepared) != 1 || prepared[0] != bound {
		t.Fatalf("prepared %v, bound %s; want exactly the bound address", prepared, bound)
	}

	addr, err := c.TCP(e).SocketAddr(func() (netip.Addr, error) { return netip.Addr{}, nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared) != 2 || prepared[1] != addr.Addr() {
		t.Fatalf("SocketAddr did not prepare its address: %v vs %s", prepared, addr)
	}
}
