// Package ext parses proxy username extensions (session / ttl / range) used to
// deterministically select outbound source addresses. This mirrors the Rust
// outway extension module.
package ext

import (
	"hash/fnv"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// ExtensionType identifies the kind of extension parsed from a username.
type ExtensionType int

const (
	// ExtNone means no extension was parsed.
	ExtNone ExtensionType = iota
	// ExtTTL is a time-window based extension.
	ExtTTL
	// ExtRange is a CIDR range allocation extension.
	ExtRange
	// ExtSession is a per-session sticky extension.
	ExtSession
)

// Extension holds an optional parsed extension value.
type Extension struct {
	Type  ExtensionType
	Value uint64
}

// None is the zero-value extension.
var None = Extension{Type: ExtNone}

const (
	extTTL     = "-ttl-"
	extSession = "-session-"
	extRange   = "-range-"
)

// fxHash64 implements the FxHash64 algorithm (constant 0x517cc1b727220a95,
// rotation 5) over a byte slice, matching the Rust fxhash::hash64 behavior on
// little-endian 64-bit platforms.
func fxHash64(data []byte) uint64 {
	const mult uint64 = 0x517cc1b727220a95
	var hash uint64
	i := 0
	for ; i+8 <= len(data); i += 8 {
		n := uint64(data[i]) | uint64(data[i+1])<<8 | uint64(data[i+2])<<16 |
			uint64(data[i+3])<<24 | uint64(data[i+4])<<32 | uint64(data[i+5])<<40 |
			uint64(data[i+6])<<48 | uint64(data[i+7])<<56
		hash = (rotl64(hash, 5) ^ n) * mult
	}
	rem := data[i:]
	if len(rem) >= 4 {
		n := uint64(rem[0]) | uint64(rem[1])<<8 | uint64(rem[2])<<16 | uint64(rem[3])<<24
		hash = (rotl64(hash, 5) ^ n) * mult
		rem = rem[4:]
	}
	if len(rem) >= 2 {
		n := uint64(rem[0]) | uint64(rem[1])<<8
		hash = (rotl64(hash, 5) ^ n) * mult
		rem = rem[2:]
	}
	if len(rem) >= 1 {
		n := uint64(rem[0])
		hash = (rotl64(hash, 5) ^ n) * mult
	}
	return hash
}

func rotl64(x uint64, r uint) uint64 {
	return (x << r) | (x >> (64 - r))
}

// strongHash selects a better-distributed hash for extension values.
var strongHash atomic.Bool

// UseStrongHash opts into a stronger, better-distributed hash for session / ttl
// / range → address selection. It is off by default so the default mapping
// matches the upstream FxHash implementation exactly; FxHash true-collides on
// short, similar session keys, so a large pool sees fewer distinct sources than
// sessions. Set once at startup before serving.
func UseStrongHash(enabled bool) { strongHash.Store(enabled) }

// hashValue maps an extension key to a 64-bit value. The default is FxHash64
// (upstream parity); the opt-in strong mode uses FNV-1a, which yields a distinct
// value for every distinct key so a session pool spreads evenly.
func hashValue(data []byte) uint64 {
	if strongHash.Load() {
		h := fnv.New64a()
		_, _ = h.Write(data)
		return h.Sum64()
	}
	return fxHash64(data)
}

// TryFrom parses an extension from a full username given the configured
// username prefix. It mirrors the Rust Extension::try_from.
func TryFrom(prefix, full string) Extension {
	extracted, hasPrefix := strings.CutPrefix(full, prefix)
	if !hasPrefix {
		return None
	}

	// Session: hash the entire full username string.
	if strings.Contains(full, extSession) {
		return Extension{Type: ExtSession, Value: hashValue([]byte(full))}
	}

	// TTL: strip the configured prefix and the "-ttl-" marker, parse remainder.
	if strings.Contains(extracted, extTTL) {
		rest := strings.TrimPrefix(extracted, extTTL)
		return parseTTL(rest)
	}

	// Range: strip the configured prefix and the "-range-" marker, hash remainder.
	if strings.Contains(extracted, extRange) {
		rest := strings.TrimPrefix(extracted, extRange)
		return Extension{Type: ExtRange, Value: hashValue([]byte(rest))}
	}

	return None
}

// parseTTL parses a TTL value (seconds) and produces a time-windowed hash.
func parseTTL(s string) Extension {
	ttl, err := strconv.ParseUint(s, 10, 64)
	if err != nil || ttl == 0 {
		return None
	}
	now := uint64(time.Now().Unix())
	window := now - (now % ttl)
	var buf [8]byte
	for i := 0; i < 8; i++ {
		buf[i] = byte(window >> (8 * (7 - i)))
	}
	return Extension{Type: ExtTTL, Value: hashValue(buf[:])}
}
