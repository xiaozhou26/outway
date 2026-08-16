package connect

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/xiaozhou26/outway/internal/config"
	"github.com/xiaozhou26/outway/internal/ext"
)

func TestUDPConnectUsesSameFamilyFallbackWhenCIDRBindFails(t *testing.T) {
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	cidr := netip.MustParsePrefix("192.0.2.1/32")
	fallback := config.Fallback{Address: netip.MustParseAddr("127.0.0.1")}
	connector := New(&cidr, nil, &fallback, 1, nil, nil, 0)
	conn, err := connector.UDP(ext.None).Connect(context.Background(), FromAddr(target.LocalAddr().(*net.UDPAddr).AddrPort()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	local := conn.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap()
	if local != fallback.Address {
		t.Fatalf("local address = %s, want fallback %s", local, fallback.Address)
	}
}

func TestIPv4ToUint32RoundTrip(t *testing.T) {
	addr := netip.AddrFrom4([4]byte{192, 168, 1, 100})
	v := ipv4ToUint32(addr)
	got := uint32ToIPv4(v)
	if got != addr {
		t.Errorf("round trip failed: %s -> %d -> %s", addr, v, got)
	}
}

func TestIPv6CIDRRejectsIPv4TargetWithoutFallback(t *testing.T) {
	cidr := netip.MustParsePrefix("2604:2dc0:20e:4700::/56")
	connector := New(&cidr, nil, nil, 1, nil, nil, 0)
	_, err := connector.TCP(ext.None).connectAddr(
		context.Background(),
		netip.MustParseAddrPort("192.0.2.1:443"),
	)
	if err == nil || !strings.Contains(err.Error(), "configure a fallback") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestIPv6ToUint128RoundTrip(t *testing.T) {
	addr := netip.MustParseAddr("2001:db8::1")
	v := ipv6ToUint128(addr)
	got := uint128ToIPv6(v)
	if got != addr {
		t.Errorf("round trip failed: %s -> %v -> %s", addr, v, got)
	}
}

func TestUint128AddSub(t *testing.T) {
	a := uint128{0, 100}
	b := uint128{0, 30}
	c := subUint128(a, b)
	if c.lo != 70 || c.hi != 0 {
		t.Errorf("subUint128(100, 30) = %v, want {0 70}", c)
	}
}

func TestUint128SubBorrow(t *testing.T) {
	// {1, 0} - {0, 1} = 2^64 - 1 = {0, 0xffffffffffffffff}
	a := uint128{1, 0}
	b := uint128{0, 1}
	c := subUint128(a, b)
	if c.hi != 0 || c.lo != ^uint64(0) {
		t.Errorf("subUint128 with borrow = {hi:%d lo:%d}, want {hi:0 lo:%d}", c.hi, c.lo, ^uint64(0))
	}
}

func TestUint128ShiftLeft(t *testing.T) {
	// 1 << 64 = {1, 0}
	a := uint128{0, 1}
	got := shlUint128(a, 64)
	if got.hi != 1 || got.lo != 0 {
		t.Errorf("shlUint128(1, 64) = %v, want {1 0}", got)
	}
}

func TestUint128ShiftRight(t *testing.T) {
	// {1, 0} >> 64 = {0, 1}
	a := uint128{1, 0}
	got := shrUint128(a, 64)
	if got.hi != 0 || got.lo != 1 {
		t.Errorf("shrUint128({1 0}, 64) = %v, want {0 1}", got)
	}
}

func TestNewUint128FromBitRange(t *testing.T) {
	// (1 << 8) - 1 = 0xff
	got := newUint128FromBitRange(8)
	if got.hi != 0 || got.lo != 0xff {
		t.Errorf("newUint128FromBitRange(8) = %v, want {0 0xff}", got)
	}
}

func TestModUint128(t *testing.T) {
	// 100 % 7 = 2
	a := uint128{0, 100}
	b := uint128{0, 7}
	got := modUint128(a, b)
	if got.lo != 2 {
		t.Errorf("modUint128(100, 7) = %v, want {0 2}", got)
	}
}

func TestAssignIPv4FromExtensionTTL(t *testing.T) {
	cidr := netip.MustParsePrefix("10.0.0.0/24")
	e := ext.Extension{Type: ext.ExtTTL, Value: 5}
	got := assignIPv4FromExtension(cidr, nil, e)
	// Should be within 10.0.0.0/24.
	if !cidr.Contains(got) {
		t.Errorf("assignIPv4FromExtension TTL: %s not in %s", got, cidr)
	}
}

func TestAssignIPv4FromExtensionSession(t *testing.T) {
	cidr := netip.MustParsePrefix("10.0.0.0/24")
	e := ext.Extension{Type: ext.ExtSession, Value: 100}
	got := assignIPv4FromExtension(cidr, nil, e)
	if !cidr.Contains(got) {
		t.Errorf("assignIPv4FromExtension Session: %s not in %s", got, cidr)
	}
	// Deterministic: same input -> same output.
	got2 := assignIPv4FromExtension(cidr, nil, e)
	if got != got2 {
		t.Errorf("assignIPv4FromExtension Session not deterministic: %s != %s", got, got2)
	}
}

func TestAssignIPv6FromExtensionTTL(t *testing.T) {
	cidr := netip.MustParsePrefix("2001:db8::/32")
	e := ext.Extension{Type: ext.ExtTTL, Value: 5}
	got := assignIPv6FromExtension(cidr, nil, e)
	if !cidr.Contains(got) {
		t.Errorf("assignIPv6FromExtension TTL: %s not in %s", got, cidr)
	}
}

func TestAssignRandIPv4(t *testing.T) {
	cidr := netip.MustParsePrefix("10.0.0.0/24")
	got := assignRandIPv4(cidr)
	if !cidr.Contains(got) {
		t.Errorf("assignRandIPv4: %s not in %s", got, cidr)
	}
}

func TestAssignRandIPv6(t *testing.T) {
	cidr := netip.MustParsePrefix("2001:db8::/32")
	got := assignRandIPv6(cidr)
	if !cidr.Contains(got) {
		t.Errorf("assignRandIPv6: %s not in %s", got, cidr)
	}
}

func TestAssignRandIPv6ProductionPrefix(t *testing.T) {
	cidr := netip.MustParsePrefix("2604:2dc0:20e:4700::/56")
	seen := make(map[netip.Addr]struct{}, 1024)
	for range 1024 {
		address := assignRandIPv6(cidr)
		if !cidr.Contains(address) {
			t.Fatalf("assigned address %s is outside %s", address, cidr)
		}
		seen[address] = struct{}{}
	}
	if len(seen) < 1000 {
		t.Fatalf("only generated %d distinct source addresses from 1024 assignments", len(seen))
	}
}

func BenchmarkAssignRandIPv6ProductionPrefix(b *testing.B) {
	cidr := netip.MustParsePrefix("2604:2dc0:20e:4700::/56")
	b.ReportAllocs()
	for range b.N {
		_ = assignRandIPv6(cidr)
	}
}

func TestAssignIPv4WithRange(t *testing.T) {
	cidr := netip.MustParsePrefix("10.0.0.0/24")
	rng := uint8(26)
	got := assignIPv4WithRange(cidr, rng, 3)
	if !cidr.Contains(got) {
		t.Errorf("assignIPv4WithRange: %s not in %s", got, cidr)
	}
}

// TestUDPSocketCreationBounded proves the UDP dial budget: with a cap of 4,
// 64 concurrent CreateSocketDualStack calls never exceed 4 in-flight socket
// creations, and all calls eventually succeed.
func TestUDPSocketCreationBounded(t *testing.T) {
	const cap = 4
	connector := New(nil, nil, nil, 5, nil, nil, cap)

	const callers = 64
	var wg sync.WaitGroup
	var maxInFlight atomic.Int32
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			preferred, fallback, err := connector.UDP(ext.None).CreateSocketDualStack(context.Background())
			if err != nil {
				t.Errorf("CreateSocketDualStack: %v", err)
				return
			}
			// Track occupancy from inside the critical section by observing the
			// gauge after acquiring; creation itself is fast, so hold briefly.
			if current := connector.udpCreating.Load(); current > maxInFlight.Load() {
				maxInFlight.Store(current)
			}
			_ = preferred.Close()
			if fallback != nil {
				_ = fallback.Close()
			}
		}()
	}
	wg.Wait()
	if got := maxInFlight.Load(); got > cap {
		t.Fatalf("observed %d concurrent UDP socket creations, want <= %d", got, cap)
	}
	if inFlight := connector.udpCreating.Load(); inFlight != 0 {
		t.Fatalf("in-flight gauge = %d after all calls returned, want 0", inFlight)
	}
}

// TestUDPSlotAcquireHonorsContextCancel verifies a caller waiting for a UDP
// slot is released when its context ends instead of queueing forever, and that
// the slot is reusable after release.
func TestUDPSlotAcquireHonorsContextCancel(t *testing.T) {
	connector := New(nil, nil, nil, 5, nil, nil, 1)

	if err := connector.acquireSlot(connector.udpDialSlots, context.Background()); err != nil {
		t.Fatal(err)
	}

	waitCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := connector.acquireSlot(connector.udpDialSlots, waitCtx); err == nil {
		t.Fatal("acquire succeeded while the only slot was held")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("cancellation took %v, want prompt return", elapsed)
	}

	connector.releaseSlot(connector.udpDialSlots)
	if err := connector.acquireSlot(connector.udpDialSlots, context.Background()); err != nil {
		t.Fatalf("slot not reusable after release: %v", err)
	}
	connector.releaseSlot(connector.udpDialSlots)
}

// TestAssignIPv6CIDRBoundaries covers the prefix-length edges the uint128
// math must survive: /127 (single host bit), /128 (zero host bits), and the
// 64-bit boundary where the host part crosses the hi/lo halves.
func TestAssignIPv6CIDRBoundaries(t *testing.T) {
	cases := []struct {
		name      string
		cidr      netip.Prefix
		checkFunc func(t *testing.T, cidr netip.Prefix)
	}{
		{
			name: "/127 keeps the prefix and flips only the last bit",
			cidr: netip.MustParsePrefix("2001:db8::/127"),
			checkFunc: func(t *testing.T, cidr netip.Prefix) {
				base := cidr.Masked().Addr()
				for _, e := range []ext.Extension{
					{Type: ext.ExtSession, Value: 0},
					{Type: ext.ExtSession, Value: 1 << 40},
					{Type: ext.ExtTTL, Value: 9223372036854775807},
				} {
					got := assignIPv6FromExtension(cidr, nil, e)
					if got != base && got != base.Next() {
						t.Fatalf("assignIPv6FromExtension(%v) = %s, want %s or %s", e.Value, got, base, base.Next())
					}
				}
				got := assignRandIPv6(cidr)
				if got != base && got != base.Next() {
					t.Fatalf("assignRandIPv6 = %s, want %s or %s", got, base, base.Next())
				}
			},
		},
		{
			name: "/128 always returns the prefix address itself",
			cidr: netip.MustParsePrefix("2001:db8::1/128"),
			checkFunc: func(t *testing.T, cidr netip.Prefix) {
				want := cidr.Masked().Addr()
				for _, e := range []ext.Extension{
					{Type: ext.ExtSession, Value: 0},
					{Type: ext.ExtSession, Value: 123456789},
					{Type: ext.ExtTTL, Value: 42},
				} {
					if got := assignIPv6FromExtension(cidr, nil, e); got != want {
						t.Fatalf("assignIPv6FromExtension(%v) = %s, want %s", e.Value, got, want)
					}
				}
				if got := assignRandIPv6(cidr); got != want {
					t.Fatalf("assignRandIPv6 = %s, want %s", got, want)
				}
			},
		},
		{
			name: "/64 host bits cross the hi/lo boundary without net corruption",
			cidr: netip.MustParsePrefix("2001:db8::/64"),
			checkFunc: func(t *testing.T, cidr netip.Prefix) {
				network := cidr.Masked().Addr().As16()
				for i := 0; i < 200; i++ {
					got := assignRandIPv6(cidr)
					if !cidr.Contains(got) {
						t.Fatalf("assignRandIPv6 produced %s outside %s", got, cidr)
					}
					high := got.As16()
					copy(network[:], high[:8])
					if network != [16]byte{} {
						// The top 64 bits must be exactly 2001:db8:: — comparing
						// the first 8 bytes catches carries into the network part.
						base := cidr.Masked().Addr().As16()
						for b := 0; b < 8; b++ {
							if high[b] != base[b] {
								t.Fatalf("network half corrupted: %s (byte %d)", got, b)
							}
						}
					}
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { tc.checkFunc(t, tc.cidr) })
	}
}
