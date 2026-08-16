package connect

import (
	"math/big"
	"net/netip"
	"testing"
)

func uint128ToBig(a uint128) *big.Int {
	v := new(big.Int).SetUint64(a.hi)
	v.Lsh(v, 64)
	v.Or(v, new(big.Int).SetUint64(a.lo))
	return v
}

func bigToUint128(v *big.Int) uint128 {
	mask := new(big.Int).SetUint64(^uint64(0))
	lo := new(big.Int).And(v, mask).Uint64()
	hi := new(big.Int).Rsh(v, 64).Uint64()
	return uint128{hi, lo}
}

func TestModUint128AgainstBigInt(t *testing.T) {
	vectors := []struct{ a, b uint128 }{
		{uint128{0, 10}, uint128{0, 3}},
		{uint128{1, 0}, uint128{0, 3}},                 // 2^64 % 3
		{uint128{0xdeadbeef, 0xcafebabe}, uint128{0, 7}},
		{uint128{^uint64(0), ^uint64(0)}, uint128{0, 1 << 32}},
		{uint128{0x1234, 0x5678}, uint128{0xabcd, 0xef01}}, // b.hi != 0, a < b
		{uint128{0, 42}, uint128{9, 1}},                    // b.hi != 0, a.hi == 0
		{uint128{5, 5}, uint128{0, 5}},
		{uint128{1 << 63, 0}, uint128{0, 1<<63 - 1}},
	}
	for _, v := range vectors {
		want := new(big.Int).Mod(uint128ToBig(v.a), uint128ToBig(v.b))
		got := modUint128(v.a, v.b)
		if bigToUint128(want) != got {
			t.Fatalf("mod(%x:%x, %x:%x) = %x:%x, want %v", v.a.hi, v.a.lo, v.b.hi, v.b.lo, got.hi, got.lo, want)
		}
	}
	if modUint128(uint128{7, 7}, uint128{}) != (uint128{7, 7}) {
		t.Fatal("modulo by zero should return the dividend")
	}
}

func TestUint128ShiftsAndMasks(t *testing.T) {
	one := uint128One()
	if got := shlUint128(one, 64); got != (uint128{1, 0}) {
		t.Fatalf("1<<64 = %x:%x", got.hi, got.lo)
	}
	if got := shlUint128(uint128{1, 0}, 64); got != (uint128{0, 0}) {
		t.Fatalf("2^64<<64 should overflow to zero")
	}
	if got := shrUint128(uint128{1, 0}, 64); got != (uint128{0, 1}) {
		t.Fatalf("2^64>>64 = %x:%x", got.hi, got.lo)
	}
	if got := newUint128FromBitRange(70); got.hi != (1<<6)-1 || got.lo != ^uint64(0) {
		t.Fatalf("bit range 70 = %x:%x", got.hi, got.lo)
	}
	if got := newUint128LShiftOne(70); got != (uint128{1 << 6, 0}) {
		t.Fatalf("1<<70 = %x:%x", got.hi, got.lo)
	}
}

func TestSubUint128Borrows(t *testing.T) {
	got := subUint128(uint128{2, 0}, uint128{1, 1})
	if got != (uint128{0, ^uint64(0)}) {
		t.Fatalf("borrow subtraction = %x:%x", got.hi, got.lo)
	}
	if got := subUint128(uint128{7, 9}, uint128{0, 0}); got != (uint128{7, 9}) {
		t.Fatal("subtracting zero changed the value")
	}
}

func TestIPv6Uint128RoundTrip(t *testing.T) {
	addrs := []string{
		"2001:db8::1",
		"::",
		"::1",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		"fd00:1234:5678:9abc:def0:1122:3344:5566",
	}
	for _, s := range addrs {
		addr := netip.MustParseAddr(s)
		if got := uint128ToIPv6(ipv6ToUint128(addr)); got != addr {
			t.Fatalf("round trip %s -> %s", s, got)
		}
	}
}
