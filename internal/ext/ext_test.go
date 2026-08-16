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

// BenchmarkTryFrom covers username parsing on the auth fast path.
func BenchmarkTryFrom(b *testing.B) {
	usernames := []string{
		"plain-user",
		"user-session-abc123defg",
		"user-ttl-60",
		"user-range-1048576",
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = TryFrom("user", usernames[i&3])
	}
}

// TestTryFromMalformedValues pins the behavior for malformed session/ttl/range
// values: malformed TTLs collapse to None, session/range markers always win
// over their content, and the marker order is session > ttl > range.
func TestTryFromMalformedValues(t *testing.T) {
	cases := []struct {
		name string
		full string
		want ExtensionType
	}{
		{"empty session value", "user-session-", ExtSession},
		{"session marker wins over ttl in same name", "user-session-a-ttl-60", ExtSession},
		{"empty ttl value", "user-ttl-", ExtNone},
		{"non-numeric ttl", "user-ttl-abc", ExtNone},
		{"zero ttl", "user-ttl-0", ExtNone},
		{"negative ttl", "user-ttl--5", ExtNone},
		{"float ttl", "user-ttl-1.5", ExtNone},
		{"ttl with trailing junk", "user-ttl-60x", ExtNone},
		{"ttl overflow", "user-ttl-99999999999999999999999", ExtNone},
		{"max uint64 ttl is valid", "user-ttl-9223372036854775807", ExtTTL},
		{"empty range value", "user-range-", ExtRange},
		{"marker without prefix", "session-x", ExtNone},
	}
	for _, tc := range cases {
		got := TryFrom("user", tc.full)
		if got.Type != tc.want {
			t.Errorf("%s: TryFrom(%q).Type = %v, want %v", tc.name, tc.full, got.Type, tc.want)
		}
	}

	// A malformed TTL must be indistinguishable from no extension at all: both
	// produce the zero Extension, so the fallback source selection is uniform.
	if got := TryFrom("user", "user-ttl-abc"); got != None {
		t.Errorf("malformed TTL produced %+v, want None", got)
	}
}

// TestTryFromSessionIsDeterministic pins the source-stickiness contract: the
// same session username always maps to the same extension value.
func TestTryFromSessionIsDeterministic(t *testing.T) {
	first := TryFrom("user", "user-session-abc123")
	if first.Type != ExtSession {
		t.Fatalf("type = %v, want ExtSession", first.Type)
	}
	for i := 0; i < 100; i++ {
		if got := TryFrom("user", "user-session-abc123"); got != first {
			t.Fatalf("session extension not deterministic: %+v vs %+v", got, first)
		}
	}
	if other := TryFrom("user", "user-session-other"); other == first {
		t.Fatal("different session strings produced the same extension value")
	}
}
