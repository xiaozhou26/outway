package connect

import "testing"

func TestVerifyUDPBufferTuningContract(t *testing.T) {
	const requested = 4 << 20
	applied, clamped, ok := VerifyUDPBufferTuning(requested)
	if !ok {
		t.Skip("effective socket buffer size is not readable on this platform")
	}
	if applied <= 0 {
		t.Fatalf("applied buffer must be positive, got %d", applied)
	}
	if clamped != (applied < requested) {
		t.Fatalf("clamped=%v inconsistent with applied=%d requested=%d", clamped, applied, requested)
	}
}

func TestVerifyUDPBufferTuningRejectsNonPositive(t *testing.T) {
	if _, _, ok := VerifyUDPBufferTuning(0); ok {
		t.Fatal("a zero request must report ok=false")
	}
}
