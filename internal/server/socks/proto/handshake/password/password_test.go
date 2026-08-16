package password

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/xiaozhou26/outway/internal/server/socks/proto/handshake"
)

func TestRequestRoundTrip(t *testing.T) {
	cases := []UsernamePassword{
		{"user", "pass"},
		{"user-session-abc", "p:a/s+word"},
		{"", ""},
	}
	for _, want := range cases {
		var buf bytes.Buffer
		if err := (Request{UserPass: want}).MarshalTo(&buf); err != nil {
			t.Fatal(err)
		}
		got, err := ReadRequest(&buf)
		if err != nil {
			t.Fatal(err)
		}
		if got.UserPass != want {
			t.Fatalf("round trip: got %+v want %+v", got.UserPass, want)
		}
	}
}

func TestReadRequestRejectsWrongVersion(t *testing.T) {
	wire := []byte{0x02, 0x04, 'u', 's', 'e', 'r', 0x00}
	if _, err := ReadRequest(bytes.NewReader(wire)); err == nil {
		t.Fatal("expected sub-negotiation version error")
	}
}

func TestReadRequestTruncatedPassword(t *testing.T) {
	// Announces a 4-byte password but delivers 3.
	wire := []byte{byte(handshake.SubnegotiationVersion), 0x04, 'u', 's', 'e', 'r', 0x04, 'p', 'a', 's'}
	if _, err := ReadRequest(bytes.NewReader(wire)); !errors.Is(err, io.ErrUnexpectedEOF) && err == nil {
		t.Fatalf("expected truncation error, got %v", err)
	}
}

func TestResponseMarshal(t *testing.T) {
	var ok bytes.Buffer
	if err := NewResponse(StatusSucceeded).MarshalTo(&ok); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ok.Bytes(), []byte{byte(handshake.SubnegotiationVersion), 0x00}) {
		t.Fatalf("success response = %v", ok.Bytes())
	}

	var failed bytes.Buffer
	if err := NewResponse(StatusFailed).MarshalTo(&failed); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(failed.Bytes(), []byte{byte(handshake.SubnegotiationVersion), 0xff}) {
		t.Fatalf("failure response = %v", failed.Bytes())
	}
}
