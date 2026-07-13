//go:build linux

package socks

import (
	"net"
	"testing"
)

// BenchmarkLinuxUDPBatchWriter measures the per-batch send path; the reusable
// address slots should keep it allocation-free.
func BenchmarkLinuxUDPBatchWriter(b *testing.B) {
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	defer target.Close()
	_ = target.SetReadBuffer(8 << 20)
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	defer sender.Close()

	const batchSize = 32
	writer := newUDPBatchWriter(sender, batchSize)
	dst := target.LocalAddr().(*net.UDPAddr).AddrPort()
	payload := make([]byte, 200)
	batch := make([]udpWritePacket, batchSize)
	for i := range batch {
		batch[i] = udpWritePacket{buffer: payload, addr: dst}
	}

	b.ReportAllocs()
	b.SetBytes(int64(batchSize * len(payload)))
	b.ResetTimer()
	for range b.N {
		if _, err := writer.Write(batch); err != nil {
			b.Fatal(err)
		}
	}
}
