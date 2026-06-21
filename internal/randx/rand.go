// Package randx provides fast pseudo-random number generators mirroring the
// Rust implementation's interface.
package randx

import "math/rand/v2"

// RandomU32 returns a pseudo-random uint32.
func RandomU32() uint32 {
	return rand.Uint32()
}

// RandomU64 returns a pseudo-random uint64.
func RandomU64() uint64 {
	return rand.Uint64()
}

// RandomU128 returns a pseudo-random 128-bit value as a [16]byte in big-endian
// byte order (byte 0 is the most significant byte).
func RandomU128() [16]byte {
	var b [16]byte
	hi := rand.Uint64()
	lo := rand.Uint64()
	for i := 0; i < 8; i++ {
		b[i] = byte(hi >> (8 * (7 - i)))
		b[i+8] = byte(lo >> (8 * (7 - i)))
	}
	return b
}
