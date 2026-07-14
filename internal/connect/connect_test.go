package connect

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/xiaozhou26/outway/internal/ext"
)

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
