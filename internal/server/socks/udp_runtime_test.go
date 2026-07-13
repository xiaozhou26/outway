package socks

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xiaozhou26/outway/internal/config"
)

func newDispatchTestRuntime(lifetime context.Context) *udpRuntime {
	return newUDPRuntime(config.UDPConfig{
		MaxPacketSize: 1500,
		BatchSize:     32,
		SendQueueSize: 8192,
	}, 1024, lifetime)
}

// canceledContext returns a context whose Err is already non-nil so send
// workers skip the network I/O and only release the packet buffer.
func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestUDPDispatchReleasesBuffers(t *testing.T) {
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt := newDispatchTestRuntime(lifetime)
	skip := canceledContext()

	const packets = 4096
	for i := range packets {
		job := udpSendJob{associationID: uint64(i), ctx: skip, packet: inboundPacket{buffer: rt.getBuffer()}}
		if !rt.dispatch(job) {
			// Queue full: the caller owns the buffer on a drop.
			rt.releaseInboundPacket(job.packet)
		}
	}

	// Workers drain asynchronously; queue depth must return to zero.
	deadline := time.Now().Add(2 * time.Second)
	for rt.metrics.queueDepth.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("queue depth did not drain: %d", rt.metrics.queueDepth.Load())
		}
		time.Sleep(time.Millisecond)
	}
}

func TestUDPDispatchAfterShutdownReturnsFalse(t *testing.T) {
	lifetime, cancel := context.WithCancel(context.Background())
	rt := newDispatchTestRuntime(lifetime)

	// Prime the dispatcher, then shut down and wait for workers to exit.
	if !rt.dispatch(udpSendJob{associationID: 1, ctx: canceledContext(), packet: inboundPacket{buffer: rt.getBuffer()}}) {
		t.Fatal("first dispatch should be admitted")
	}
	cancel()
	if !rt.wait(2 * time.Second) {
		t.Fatal("workers did not stop after shutdown")
	}

	// Dispatching after shutdown must not send or panic.
	if rt.dispatch(udpSendJob{associationID: 2, ctx: canceledContext(), packet: inboundPacket{buffer: rt.getBuffer()}}) {
		t.Fatal("dispatch after shutdown should return false")
	}
}

func TestUDPDispatchConcurrentShutdownNoPanic(t *testing.T) {
	lifetime, cancel := context.WithCancel(context.Background())
	rt := newDispatchTestRuntime(lifetime)
	skip := canceledContext()

	var wg sync.WaitGroup
	for w := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 2000 {
				job := udpSendJob{associationID: uint64(w*2000 + i), ctx: skip, packet: inboundPacket{buffer: rt.getBuffer()}}
				if !rt.dispatch(job) {
					rt.releaseInboundPacket(job.packet)
				}
			}
		}()
	}
	// Cancel mid-flight: dispatchers race worker shutdown. Must not panic on a
	// closed channel (channels are never closed) and must not deadlock.
	time.Sleep(time.Millisecond)
	cancel()
	wg.Wait()
	if !rt.wait(2 * time.Second) {
		t.Fatal("workers did not stop after concurrent shutdown")
	}
}

func BenchmarkUDPDispatchParallel(b *testing.B) {
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt := newDispatchTestRuntime(lifetime)
	skip := canceledContext()
	var nextID atomic.Uint64

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		id := nextID.Add(1)
		for pb.Next() {
			job := udpSendJob{associationID: id, ctx: skip, packet: inboundPacket{buffer: rt.getBuffer()}}
			if !rt.dispatch(job) {
				rt.releaseInboundPacket(job.packet)
			}
		}
	})
}
