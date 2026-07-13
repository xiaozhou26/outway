//go:build linux

package connect

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func udpRcvbuf(t *testing.T, conn *net.UDPConn) int {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var value int
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		value, sockErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
	}); err != nil {
		t.Fatal(err)
	}
	if sockErr != nil {
		t.Fatal(sockErr)
	}
	return value
}

func TestTuneUDPBuffersAppliesRequestedSize(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	before := udpRcvbuf(t, conn)
	requested := 4 << 20
	if before >= 2*requested {
		t.Skipf("default receive buffer %d already exceeds the test request", before)
	}
	TuneUDPBuffers(conn, requested)
	after := udpRcvbuf(t, conn)
	if after <= before {
		t.Fatalf("receive buffer did not grow: before=%d after=%d", before, after)
	}
}

func TestTuneUDPBuffersZeroKeepsDefaults(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	before := udpRcvbuf(t, conn)
	TuneUDPBuffers(conn, 0)
	TuneUDPBuffers(nil, 1<<20)
	if after := udpRcvbuf(t, conn); after != before {
		t.Fatalf("zero size must keep defaults: before=%d after=%d", before, after)
	}
}
