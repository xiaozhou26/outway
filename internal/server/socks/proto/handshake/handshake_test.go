package handshake

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestReadRequestParsesMethods(t *testing.T) {
	req, err := ReadRequest(bytes.NewReader([]byte{0x05, 0x02, 0x00, 0x02}))
	if err != nil {
		t.Fatal(err)
	}
	if len(req.Methods) != 2 || req.Methods[0] != MethodNoAuth || req.Methods[1] != MethodPassword {
		t.Fatalf("methods = %v", req.Methods)
	}
	if !req.EvaluateMethod(MethodPassword) {
		t.Fatal("offered method not reported as offered")
	}
	if req.EvaluateMethod(MethodGssApi) {
		t.Fatal("unoffered method reported as offered")
	}
}

func TestReadRequestZeroMethods(t *testing.T) {
	if _, err := ReadRequest(bytes.NewReader([]byte{0x05, 0x00})); err != nil {
		t.Fatalf("empty method list should parse: %v", err)
	}
}

func TestReadRequestRejectsWrongVersion(t *testing.T) {
	if _, err := ReadRequest(bytes.NewReader([]byte{0x04, 0x01, 0x00})); err == nil {
		t.Fatal("expected version error")
	}
}

func TestReadRequestTruncated(t *testing.T) {
	cases := [][]byte{
		{0x05},
		{0x05, 0x03, 0x00, 0x01}, // announces 3 methods, delivers 2
	}
	for _, wire := range cases {
		if _, err := ReadRequest(bytes.NewReader(wire)); !errors.Is(err, io.ErrUnexpectedEOF) && err == nil {
			t.Fatalf("wire %v: expected truncation error, got %v", wire, err)
		}
	}
}

func TestResponseMarshal(t *testing.T) {
	var buf bytes.Buffer
	if err := NewResponse(MethodPassword).MarshalTo(&buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), []byte{0x05, 0x02}) {
		t.Fatalf("response = %v", buf.Bytes())
	}
}

func TestMethodRoundTripAndString(t *testing.T) {
	for _, m := range []Method{MethodNoAuth, MethodGssApi, MethodPassword, MethodNoAcceptableMethods, 0x42} {
		if got := MethodFromByte(m.Byte()); got != m {
			t.Fatalf("round trip %d -> %d", m, got)
		}
	}
	if MethodNoAuth.String() != "NoAuth" || MethodPassword.String() != "UserPass" {
		t.Fatalf("unexpected method names: %q %q", MethodNoAuth, MethodPassword)
	}
	if Method(0x7f).String() != "Method(0x7f)" {
		t.Fatalf("unknown method name = %q", Method(0x7f))
	}
}
