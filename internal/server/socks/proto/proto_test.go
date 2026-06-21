package proto

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestAddressIPv4RoundTrip(t *testing.T) {
	addr := SocketAddress(netipMustAddrPort("192.168.1.1:8080"))
	var buf bytes.Buffer
	if err := addr.MarshalTo(&buf); err != nil {
		t.Fatalf("MarshalTo: %v", err)
	}
	got, err := ReadAddress(&buf)
	if err != nil {
		t.Fatalf("ReadAddress: %v", err)
	}
	if got.Socket == nil || got.Socket.String() != "192.168.1.1:8080" {
		t.Errorf("round trip failed: got %v", got)
	}
}

func TestAddressIPv6RoundTrip(t *testing.T) {
	addr := SocketAddress(netipMustAddrPort("[2001:db8::1]:443"))
	var buf bytes.Buffer
	if err := addr.MarshalTo(&buf); err != nil {
		t.Fatalf("MarshalTo: %v", err)
	}
	got, err := ReadAddress(&buf)
	if err != nil {
		t.Fatalf("ReadAddress: %v", err)
	}
	if got.Socket == nil || got.Socket.String() != "[2001:db8::1]:443" {
		t.Errorf("round trip failed: got %v", got)
	}
}

func TestAddressDomainRoundTrip(t *testing.T) {
	addr := DomainAddress("example.com", 80)
	var buf bytes.Buffer
	if err := addr.MarshalTo(&buf); err != nil {
		t.Fatalf("MarshalTo: %v", err)
	}
	got, err := ReadAddress(&buf)
	if err != nil {
		t.Fatalf("ReadAddress: %v", err)
	}
	if got.Domain != "example.com" || got.Port != 80 {
		t.Errorf("round trip failed: got %v", got)
	}
}

func TestRequestRoundTrip(t *testing.T) {
	req := Request{
		Command: CmdConnect,
		Address: DomainAddress("example.com", 443),
	}
	var buf bytes.Buffer
	if err := req.MarshalTo(&buf); err != nil {
		t.Fatalf("MarshalTo: %v", err)
	}
	got, err := ReadRequest(&buf)
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	if got.Command != CmdConnect {
		t.Errorf("command: got %v, want %v", got.Command, CmdConnect)
	}
	if got.Address.Domain != "example.com" || got.Address.Port != 443 {
		t.Errorf("address: got %v", got.Address)
	}
}

func TestResponseRoundTrip(t *testing.T) {
	resp := NewResponse(ReplySucceeded, SocketAddress(netipMustAddrPort("127.0.0.1:1080")))
	var buf bytes.Buffer
	if err := resp.MarshalTo(&buf); err != nil {
		t.Fatalf("MarshalTo: %v", err)
	}
	// Response is write-only in this proto (no ReadResponse), so just check
	// the first two bytes: version + reply.
	if buf.Len() < 2 {
		t.Fatalf("buffer too short: %d", buf.Len())
	}
	b := buf.Bytes()
	if b[0] != Version5 {
		t.Errorf("version: got %#x, want %#x", b[0], Version5)
	}
	if b[1] != byte(ReplySucceeded) {
		t.Errorf("reply: got %#x, want %#x", b[1], byte(ReplySucceeded))
	}
}

func TestParseCommand(t *testing.T) {
	cases := []struct {
		in   uint8
		want Command
		ok   bool
	}{
		{0x01, CmdConnect, true},
		{0x02, CmdBind, true},
		{0x03, CmdUDPAssociate, true},
		{0x09, 0, false},
	}
	for _, c := range cases {
		got, err := ParseCommand(c.in)
		if c.ok {
			if err != nil {
				t.Errorf("ParseCommand(%#x): err = %v", c.in, err)
				continue
			}
			if got != c.want {
				t.Errorf("ParseCommand(%#x): got %v, want %v", c.in, got, c.want)
			}
		} else {
			if err == nil {
				t.Errorf("ParseCommand(%#x): expected error, got %v", c.in, got)
			}
		}
	}
}

func TestParseReply(t *testing.T) {
	cases := []struct {
		in   uint8
		want Reply
		ok   bool
	}{
		{0x00, ReplySucceeded, true},
		{0x04, ReplyHostUnreachable, true},
		{0x07, ReplyCommandNotSupported, true},
		{0x99, 0, false},
	}
	for _, c := range cases {
		got, err := ParseReply(c.in)
		if c.ok {
			if err != nil {
				t.Errorf("ParseReply(%#x): err = %v", c.in, err)
				continue
			}
			if got != c.want {
				t.Errorf("ParseReply(%#x): got %v, want %v", c.in, got, c.want)
			}
		} else {
			if err == nil {
				t.Errorf("ParseReply(%#x): expected error, got %v", c.in, got)
			}
		}
	}
}

// netipMustAddrPort panics on parse error (test helper).
func netipMustAddrPort(s string) netip.AddrPort {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		panic(err)
	}
	return ap
}
