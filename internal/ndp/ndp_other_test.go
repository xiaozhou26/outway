//go:build !linux

package ndp

import "testing"

func TestOpenUnsupportedOffLinux(t *testing.T) {
	if _, err := Open("eth0", 16); err == nil {
		t.Fatal("expected --ndp-proxy to be rejected off Linux")
	}
}
