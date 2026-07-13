//go:build linux

package socks

import (
	"net"
	"testing"
	"time"
)

// TestSendUDPGSOSegments verifies the kernel splits one UDP_SEGMENT send into
// the expected sequence of datagrams: several full-size segments followed by a
// smaller trailer, each carrying the matching slice of the coalesced buffer.
func TestSendUDPGSOSegments(t *testing.T) {
	if !udpGSOSupported() {
		t.Skip("kernel does not support UDP_SEGMENT")
	}

	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()

	dst := target.LocalAddr().(*net.UDPAddr).AddrPort()
	const gsoSize = 100
	sizes := []int{gsoSize, gsoSize, gsoSize, gsoSize, gsoSize, 40}
	batch := make([]udpWritePacket, len(sizes))
	for i, size := range sizes {
		buffer := make([]byte, size)
		for j := range buffer {
			buffer[j] = byte('A' + i)
		}
		batch[i] = udpWritePacket{buffer: buffer, owner: buffer, addr: dst}
	}

	sent, err := sendUDPGSO(sender, batch, gsoSize)
	if err != nil {
		t.Fatalf("sendUDPGSO: %v", err)
	}
	if sent != len(batch) {
		t.Fatalf("sent %d datagrams, want %d", sent, len(batch))
	}

	if err := target.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	received := make([]int, 0, len(sizes))
	buffer := make([]byte, 4096)
	for len(received) < len(sizes) {
		n, _, err := target.ReadFromUDP(buffer)
		if err != nil {
			t.Fatalf("read datagram %d: %v (GSO did not segment as expected)", len(received), err)
		}
		// Each datagram must be a single byte value repeated, identifying which
		// source packet it came from, and its length must match that packet.
		want := byte('A' + len(received))
		for i := 0; i < n; i++ {
			if buffer[i] != want {
				t.Fatalf("datagram %d byte %d = %q, want %q", len(received), i, buffer[i], want)
			}
		}
		received = append(received, n)
	}
	for i, size := range sizes {
		if received[i] != size {
			t.Fatalf("datagram %d size = %d, want %d", i, received[i], size)
		}
	}
}
