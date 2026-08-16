package randx

import "testing"

// TestRandomU128VariesAcrossCalls pins the generator's basic contract: every
// call yields a fresh value and every byte position participates (a broken
// big-endian packing would freeze or bias specific positions).
func TestRandomU128VariesAcrossCalls(t *testing.T) {
	const draws = 4096
	seen := make(map[[16]byte]struct{}, draws)
	var first [16]byte
	for i := 0; i < draws; i++ {
		v := RandomU128()
		if i == 0 {
			first = v
			continue
		}
		if v == first && i < draws-1 {
			// A repeat of the very first value is legal but astronomically
			// unlikely before the final draw; treat it as a stuck generator.
			t.Fatalf("generator repeated its first output at draw %d", i)
		}
		seen[v] = struct{}{}
	}
	if len(seen) < draws-1 {
		t.Fatalf("only %d distinct values in %d draws", len(seen), draws)
	}
}

// TestRandomU128AllBytePositionsMove checks that each of the 16 byte positions
// takes more than one value across many draws, catching any fixed header or
// dropped half (hi/lo mix-up would still move bytes, a skipped write would
// not).
func TestRandomU128AllBytePositionsMove(t *testing.T) {
	const draws = 1024
	var first [16]byte = RandomU128()
	moved := [16]bool{}
	for i := 0; i < draws; i++ {
		v := RandomU128()
		for b := 0; b < 16; b++ {
			if v[b] != first[b] {
				moved[b] = true
			}
		}
	}
	for b, ok := range moved {
		if !ok {
			t.Fatalf("byte position %d never changed across %d draws", b, draws)
		}
	}
}

func TestRandomU32AndU64Distinct(t *testing.T) {
	seen32 := make(map[uint32]struct{}, 1000)
	seen64 := make(map[uint64]struct{}, 1000)
	for i := 0; i < 1000; i++ {
		seen32[RandomU32()] = struct{}{}
		seen64[RandomU64()] = struct{}{}
	}
	if len(seen32) < 999 {
		t.Fatalf("RandomU32 produced only %d distinct values", len(seen32))
	}
	if len(seen64) < 999 {
		t.Fatalf("RandomU64 produced only %d distinct values", len(seen64))
	}
}
