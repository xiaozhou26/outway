//go:build !linux

package connect

import "testing"

func TestProbeCongestionUnsupportedOffLinux(t *testing.T) {
	if err := ProbeCongestion("bbr"); err == nil {
		t.Fatal("ProbeCongestion succeeded off Linux; startup must refuse upstream-congestion here")
	}
}
