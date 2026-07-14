package ext

import "testing"

func TestFxHash64Empty(t *testing.T) {
	// FxHash of empty input should be 0.
	if got := fxHash64(nil); got != 0 {
		t.Errorf("fxHash64(nil) = %d, want 0", got)
	}
}

func TestFxHash64SingleByte(t *testing.T) {
	// FxHash of a single byte should be deterministic.
	h1 := fxHash64([]byte{0x42})
	h2 := fxHash64([]byte{0x42})
	if h1 != h2 {
		t.Errorf("fxHash64 not deterministic: %d != %d", h1, h2)
	}
}

func TestFxHash64MultiByte(t *testing.T) {
	// FxHash of "hello" should be deterministic and non-zero.
	h := fxHash64([]byte("hello"))
	if h == 0 {
		t.Errorf("fxHash64('hello') = 0, want non-zero")
	}
	// Different inputs should (very likely) produce different hashes.
	h2 := fxHash64([]byte("world"))
	if h == h2 {
		t.Errorf("fxHash64('hello') == fxHash64('world')")
	}
}

func TestTryFromNoPrefix(t *testing.T) {
	// When the full string doesn't start with the prefix, return None.
	got := TryFrom("user", "other")
	if got.Type != ExtNone {
		t.Errorf("TryFrom('user', 'other') = %v, want ExtNone", got)
	}
}

func TestTryFromSession(t *testing.T) {
	// Session extension: prefix + "-session-" + suffix.
	got := TryFrom("user", "user-session-abc")
	if got.Type != ExtSession {
		t.Errorf("TryFrom session: type = %v, want ExtSession", got.Type)
	}
	if got.Value == 0 {
		t.Errorf("TryFrom session: value = 0, want non-zero")
	}
}

func TestTryFromTTL(t *testing.T) {
	// TTL extension: prefix + "-ttl-" + number.
	got := TryFrom("user", "user-ttl-60")
	if got.Type != ExtTTL {
		t.Errorf("TryFrom ttl: type = %v, want ExtTTL", got.Type)
	}
	if got.Value == 0 {
		t.Errorf("TryFrom ttl: value = 0, want non-zero")
	}
}

func TestTryFromTTLInvalid(t *testing.T) {
	// TTL with non-numeric or zero should return None.
	got := TryFrom("user", "user-ttl-abc")
	if got.Type != ExtNone {
		t.Errorf("TryFrom ttl invalid: type = %v, want ExtNone", got.Type)
	}
	got = TryFrom("user", "user-ttl-0")
	if got.Type != ExtNone {
		t.Errorf("TryFrom ttl zero: type = %v, want ExtNone", got.Type)
	}
}

func TestTryFromRange(t *testing.T) {
	// Range extension: prefix + "-range-" + suffix.
	got := TryFrom("user", "user-range-xyz")
	if got.Type != ExtRange {
		t.Errorf("TryFrom range: type = %v, want ExtRange", got.Type)
	}
	if got.Value == 0 {
		t.Errorf("TryFrom range: value = 0, want non-zero")
	}
}

func TestTryFromPlainPrefix(t *testing.T) {
	// Just the prefix with no extension marker should return None.
	got := TryFrom("user", "user")
	if got.Type != ExtNone {
		t.Errorf("TryFrom plain: type = %v, want ExtNone", got.Type)
	}
}

func TestDefaultHashIsFxHashParity(t *testing.T) {
	t.Cleanup(func() { UseStrongHash(false) })
	UseStrongHash(false)
	const full = "user-session-abc123"
	got := TryFrom("user", full)
	if got.Type != ExtSession {
		t.Fatalf("expected session extension, got %v", got.Type)
	}
	if got.Value != fxHash64([]byte(full)) {
		t.Fatalf("default hash is not FxHash (upstream parity broken): %d", got.Value)
	}
	// Deterministic across calls.
	if again := TryFrom("user", full); again.Value != got.Value {
		t.Fatal("hash is not deterministic")
	}
}

func TestStrongSessionHashDistribution(t *testing.T) {
	t.Cleanup(func() { UseStrongHash(false) })
	const n = 512
	distinct := func() int {
		seen := make(map[uint64]struct{}, n)
		for i := 0; i < n; i++ {
			e := TryFrom("user", "user-session-"+strconvI(i))
			seen[e.Value] = struct{}{}
		}
		return len(seen)
	}

	UseStrongHash(false)
	weak := distinct()
	UseStrongHash(true)
	strong := distinct()

	// Both hashes must map distinct session keys to distinct values, and the
	// strong hash must be no worse. For plain sequential keys FxHash already
	// distributes fully, so this guards behavior parity rather than proving an
	// improvement.
	if strong != n {
		t.Errorf("strong hash: %d distinct of %d sessions, want all distinct", strong, n)
	}
	if strong < weak {
		t.Fatalf("strong distribution %d is worse than default %d", strong, weak)
	}
	t.Logf("distinct source values for %d sessions: default(fxhash)=%d strong(fnv)=%d", n, weak, strong)

	UseStrongHash(true)
	a := TryFrom("user", "user-session-abc")
	if b := TryFrom("user", "user-session-abc"); a.Value != b.Value {
		t.Fatal("strong hash is not deterministic")
	}
}

func strconvI(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
