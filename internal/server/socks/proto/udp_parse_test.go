package proto

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestParseUdpHeaderParity(t *testing.T) {
	cases := []Address{
		SocketAddress(netip.MustParseAddrPort("192.0.2.1:443")),
		SocketAddress(netip.MustParseAddrPort("[2001:db8::1]:53")),
		DomainAddress("example.com", 8080),
	}
	for _, address := range cases {
		packet := BuildUdpPacket(2, address, []byte("payload"))
		want, wantLen, err := ReadUdpHeader(bytes.NewReader(packet))
		if err != nil {
			t.Fatalf("ReadUdpHeader: %v", err)
		}
		got, gotLen, err := ParseUdpHeader(packet)
		if err != nil {
			t.Fatalf("ParseUdpHeader: %v", err)
		}
		if gotLen != wantLen || got.Frag != want.Frag || got.Address.String() != want.Address.String() {
			t.Fatalf("ParseUdpHeader = (%+v, %d), want (%+v, %d)", got.Address, gotLen, want.Address, wantLen)
		}
	}
}

func TestParseUdpHeaderShort(t *testing.T) {
	cases := [][]byte{
		{},
		{0, 0, 0},
		{0, 0, 0, byte(AddrIPv4), 1, 2},
		{0, 0, 0, byte(AddrIPv6), 1, 2, 3},
		{0, 0, 0, byte(AddrDomain), 5, 'a'},
		{0, 0, 0, 0x09},
	}
	for _, buf := range cases {
		if _, _, err := ParseUdpHeader(buf); err == nil {
			t.Fatalf("expected error for %v", buf)
		}
	}
}

func BenchmarkReadUdpHeader(b *testing.B) {
	packet := BuildUdpPacket(0, SocketAddress(netip.MustParseAddrPort("192.0.2.1:443")), []byte("payload"))
	b.ReportAllocs()
	for range b.N {
		if _, _, err := ReadUdpHeader(bytes.NewReader(packet)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseUdpHeader(b *testing.B) {
	packet := BuildUdpPacket(0, SocketAddress(netip.MustParseAddrPort("192.0.2.1:443")), []byte("payload"))
	b.ReportAllocs()
	for range b.N {
		if _, _, err := ParseUdpHeader(packet); err != nil {
			b.Fatal(err)
		}
	}
}
