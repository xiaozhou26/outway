package connect

import (
	"math/bits"
	"net/netip"
)

// uint128 helpers (two uint64 halves: hi, lo), used by the IPv6 source-address
// assignment math. They mirror the Rust implementation's semantics.

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

// modUint128 computes a % b. It maps onto math/bits.Div64 instead of a
// shift-and-subtract loop: a 128-by-64 division is two Div64 calls, and any
// divisor with a nonzero high half exceeds a dividend with a zero high half.
func modUint128(a, b uint128) uint128 {
	if isZeroUint128(b) {
		return a
	}
	if b.hi == 0 {
		_, hiRem := bits.Div64(0, a.hi, b.lo)
		_, loRem := bits.Div64(hiRem, a.lo, b.lo)
		return uint128{0, loRem}
	}
	if a.hi == 0 {
		// b >= 2^64 > a, so the dividend is the remainder.
		return a
	}
	// General 128-by-128 long division, MSB first. Only reachable with both
	// halves of the dividend set, which the extension math never produces; the
	// big.Int-cross-checked test keeps it honest.
	r := uint128{}
	for i := 127; i >= 0; i-- {
		r = shlUint128(r, 1)
		var bit uint64
		if i >= 64 {
			bit = (a.hi >> uint(i-64)) & 1
		} else {
			bit = (a.lo >> uint(i)) & 1
		}
		r.lo |= bit
		if cmpUint128(r, b) >= 0 {
			r = subUint128(r, b)
		}
	}
	return r
}
