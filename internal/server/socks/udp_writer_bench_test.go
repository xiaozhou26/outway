//go:build linux

package socks

import (
	"context"
	"net"
	"testing"

	"github.com/xiaozhou26/outway/internal/config"
)

// BenchmarkLinuxUDPBatchWriter measures the per-batch send path; the pooled
// message arrays should keep it allocation-free after the first batch.
func BenchmarkLinuxUDPBatchWriter(b *testing.B) {
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = target.Close() }()
	_ = target.SetReadBuffer(8 << 20)
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = sender.Close() }()
	const batchSize = 32
	runtime := newUDPRuntime(config.UDPConfig{
		MaxPacketSize: 1500,
		BatchSize:     batchSize,
		SendQueueSize: 8192,
	}, 1024, context.Background())
	defer runtime.putBatchSlices(runtime.getBatchSlices())
	writer := newUDPBatchWriter(sender, runtime)
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
