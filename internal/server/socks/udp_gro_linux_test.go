//go:build linux

package socks

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/xiaozhou26/outway/internal/config"
)

func TestParseGROSizeEmpty(t *testing.T) {
	if got := parseGROSize(nil); got != 0 {
		t.Fatalf("parseGROSize(nil) = %d, want 0", got)
	}
}

// TestLinuxUDPBatchReaderGRO sends a uniform-size burst as a single GSO
// (UDP_SEGMENT) write and reads it back on a UDP_GRO socket. On loopback the
// GSO super-datagram is delivered coalesced, so readGRO must split it back into
// the exact individual datagrams.
func TestLinuxUDPBatchReaderGRO(t *testing.T) {
	if !udpGROSupported() {
		t.Skip("kernel does not support UDP_GRO")
	}

	recvConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer recvConn.Close()
	_ = recvConn.SetReadBuffer(4 << 20)
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()

	runtime := newUDPRuntime(config.UDPConfig{
		MaxPacketSize: config.DefaultUDPMaxPacketSize,
		BatchSize:     32,
		SendQueueSize: 1,
		GRO:           true,
	}, 1, context.Background())
	reader := newUDPBatchReader(recvConn, runtime, 0, config.DefaultUDPMaxPacketSize)
	if lr, ok := reader.(*linuxUDPBatchReader); !ok || !lr.gro {
		t.Fatal("expected GRO to be enabled on the reader")
	}

	const count = 48
	const size = 200
	target := recvConn.LocalAddr().(*net.UDPAddr).AddrPort()
	batch := make([]udpWritePacket, count)
	for i := range count {
		payload := make([]byte, size)
		binary.BigEndian.PutUint32(payload[:4], uint32(i))
		batch[i] = udpWritePacket{buffer: payload, addr: target}
	}
	if _, err := sendUDPGSO(sender, batch, size); err != nil {
		t.Fatalf("sendUDPGSO: %v", err)
	}

	_ = recvConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	seen := make(map[uint32]bool, count)
	for len(seen) < count {
		packets, err := reader.Read()
		if err != nil {
			t.Fatalf("read after %d/%d datagrams: %v", len(seen), count, err)
		}
		for _, packet := range packets {
			if packet.truncated {
				t.Fatal("unexpected truncated datagram")
			}
			if packet.n != size {
				t.Fatalf("segment length %d, want %d", packet.n, size)
			}
			index := binary.BigEndian.Uint32(packet.buffer[:4])
			if seen[index] {
				t.Fatalf("duplicate datagram %d", index)
			}
			seen[index] = true
			runtime.releaseReadPacket(packet)
		}
	}

	if runtime.metrics.groCoalescedReads.Load() == 0 {
		t.Fatal("expected at least one coalesced GRO read")
	}
	t.Logf("coalesced reads=%d for %d datagrams", runtime.metrics.groCoalescedReads.Load(), count)
}
