package socks

import (
	"net/netip"
	"testing"
)

func writePacket(addr netip.AddrPort, size int) udpWritePacket {
	return udpWritePacket{buffer: make([]byte, size), addr: addr}
}

func TestGSOEligible(t *testing.T) {
	a := netip.MustParseAddrPort("198.51.100.1:9000")
	b := netip.MustParseAddrPort("198.51.100.2:9000")

	tests := []struct {
		name    string
		enabled bool
		batch   []udpWritePacket
		size    int
		ok      bool
	}{
		{name: "disabled", enabled: false, batch: []udpWritePacket{writePacket(a, 100), writePacket(a, 100)}},
		{name: "single packet", enabled: true, batch: []udpWritePacket{writePacket(a, 100)}},
		{name: "uniform", enabled: true, batch: []udpWritePacket{writePacket(a, 100), writePacket(a, 100), writePacket(a, 100)}, size: 100, ok: true},
		{name: "smaller last", enabled: true, batch: []udpWritePacket{writePacket(a, 100), writePacket(a, 100), writePacket(a, 40)}, size: 100, ok: true},
		{name: "larger last", enabled: true, batch: []udpWritePacket{writePacket(a, 100), writePacket(a, 120)}},
		{name: "middle differs", enabled: true, batch: []udpWritePacket{writePacket(a, 100), writePacket(a, 60), writePacket(a, 100)}},
		{name: "mixed dest", enabled: true, batch: []udpWritePacket{writePacket(a, 100), writePacket(b, 100)}},
		{name: "zero size", enabled: true, batch: []udpWritePacket{writePacket(a, 0), writePacket(a, 0)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			size, ok := gsoEligible(test.enabled, test.batch)
			if ok != test.ok || size != test.size {
				t.Fatalf("gsoEligible = (%d, %v), want (%d, %v)", size, ok, test.size, test.ok)
			}
		})
	}
}
