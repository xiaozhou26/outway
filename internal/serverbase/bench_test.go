package serverbase

import (
	"net"
	"net/netip"
	"testing"
)

type benchConn struct {
	net.Conn
}

// BenchmarkConnectionSetChurnParallel measures concurrent Add+Remove on the
// per-server connection registry — the lock hit on every connection open and
// close. It is the case the shard split targets.
func BenchmarkConnectionSetChurnParallel(b *testing.B) {
	set := NewConnectionSet()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		c := &benchConn{}
		for pb.Next() {
			set.Add(c)
			set.Remove(c)
		}
	})
}

// BenchmarkAddrPortOf compares AddrPortOf against the RemoteAddr().String() ->
// netip.ParseAddrPort round-trip it replaces on the per-connection accept path.
func BenchmarkAddrPortOf(b *testing.B) {
	var addr net.Addr = &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 51820}
	b.Run("string-roundtrip", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			ap, _ := netip.ParseAddrPort(addr.String())
			_ = ap
		}
	})
	b.Run("AddrPortOf", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			_ = AddrPortOf(addr)
		}
	})
}
