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
