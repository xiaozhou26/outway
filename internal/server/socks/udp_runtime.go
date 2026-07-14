package socks

import (
	"context"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xiaozhou26/outway/internal/config"
)

type udpMetrics struct {
	activeAssociations atomic.Int64
	totalAssociations  atomic.Uint64
	inPackets          atomic.Uint64
	inBytes            atomic.Uint64
	outPackets         atomic.Uint64
	outBytes           atomic.Uint64
	queueDrops         atomic.Uint64
	truncatedDrops     atomic.Uint64
	malformedDrops     atomic.Uint64
	fragmentDrops      atomic.Uint64
	unauthorizedDrops  atomic.Uint64
	associationDrops   atomic.Uint64
	errors             atomic.Uint64
	queueDepth         atomic.Int64
	batchFallbacks     atomic.Uint64
	groCoalescedReads  atomic.Uint64
	groTruncatedReads  atomic.Uint64
}

type udpRuntime struct {
	config           config.UDPConfig
	pool             sync.Pool
	metrics          udpMetrics
	startOnce        sync.Once
	shards           []chan udpSendJob
	sequence         atomic.Uint64
	lifetime         context.Context
	associationSlots chan struct{}
	workerWG         sync.WaitGroup
	batchSlots       chan struct{}
	reactor          *udpReactor
	reactorOnce      sync.Once
	reactorReady     atomic.Bool
}

// sharedReactor lazily creates the process-wide UDP read reactor and returns it.
// ok is false when a reactor is unavailable (non-Linux, or epoll setup failed),
// in which case callers fall back to a blocking read goroutine per socket. The
// reactor is closed when the runtime lifetime ends.
func (r *udpRuntime) sharedReactor() (*udpReactor, bool) {
	r.reactorOnce.Do(func() {
		workers := runtime.GOMAXPROCS(0)
		if workers < 2 {
			workers = 2
		}
		if workers > 16 {
			workers = 16
		}
		reactor, err := newUDPReactor(workers)
		if err != nil {
			return
		}
		r.reactor = reactor
		r.reactorReady.Store(true)
		go func() {
			<-r.lifetime.Done()
			reactor.close()
		}()
	})
	if r.reactorReady.Load() {
		return r.reactor, true
	}
	return nil, false
}

func newUDPRuntime(cfg config.UDPConfig, concurrent uint32, lifetime context.Context) *udpRuntime {
	cfg = normalizeUDPConfig(cfg)
	maxAssociations := cfg.MaxAssociations
	if maxAssociations == 0 {
		maxAssociations = concurrent
	}
	r := &udpRuntime{
		config:           cfg,
		lifetime:         lifetime,
		associationSlots: make(chan struct{}, int(maxAssociations)),
	}
	if cfg.BatchBufferBudget > 0 {
		r.batchSlots = make(chan struct{}, cfg.BatchBufferBudget)
	}
	r.pool.New = func() any {
		return make([]byte, cfg.MaxPacketSize+protoUDPHeaderMaxLen)
	}
	if cfg.MetricsIntervalSecs > 0 {
		go r.logMetrics(lifetime, time.Duration(cfg.MetricsIntervalSecs)*time.Second)
	}
	return r
}

// Keep the pool allocation independent from proto imports in configuration.
const protoUDPHeaderMaxLen = 3 + 1 + 1 + 255 + 2

func normalizeUDPConfig(cfg config.UDPConfig) config.UDPConfig {
	if cfg.MaxPacketSize == 0 {
		cfg.MaxPacketSize = config.DefaultUDPMaxPacketSize
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = config.DefaultUDPBatchSize
	}
	if cfg.SendQueueSize == 0 {
		cfg.SendQueueSize = config.DefaultUDPSendQueueSize
	}
	return cfg
}

func (r *udpRuntime) getBuffer() []byte    { return r.pool.Get().([]byte) }
func (r *udpRuntime) putBuffer(buf []byte) { r.pool.Put(buf) }

func (r *udpRuntime) tryAcquireBatchBuffer() bool {
	if r.batchSlots == nil {
		return false
	}
	select {
	case r.batchSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (r *udpRuntime) releaseBuffer(buf []byte, batchSlot bool) {
	if batchSlot {
		<-r.batchSlots
	}
	r.putBuffer(buf)
}

func (r *udpRuntime) releaseReadPacket(packet udpReadPacket) {
	r.releaseBuffer(packet.buffer, packet.batchSlot)
}

func (r *udpRuntime) releaseInboundPacket(packet inboundPacket) {
	r.releaseBuffer(packet.buffer, packet.batchSlot)
}

func (r *udpRuntime) beginAssociation() (uint64, bool) {
	if r.lifetime.Err() != nil {
		return 0, false
	}
	select {
	case r.associationSlots <- struct{}{}:
	default:
		r.metrics.associationDrops.Add(1)
		return 0, false
	}
	if r.lifetime.Err() != nil {
		<-r.associationSlots
		return 0, false
	}
	r.metrics.activeAssociations.Add(1)
	r.metrics.totalAssociations.Add(1)
	return r.sequence.Add(1), true
}

func (r *udpRuntime) endAssociation() {
	<-r.associationSlots
	r.metrics.activeAssociations.Add(-1)
}

// dispatch enqueues a send job onto the shard owning the association. It reads
// r.shards without a lock: startOnce establishes a happens-before edge, and the
// shards slice is written once and never mutated afterward. Shard channels are
// never closed (workers exit via the lifetime context), so a send can never
// race a close.
func (r *udpRuntime) dispatch(job udpSendJob) bool {
	if r.lifetime.Err() != nil {
		return false
	}
	r.startOnce.Do(r.startDispatcher)
	shard := r.shards[job.associationID%uint64(len(r.shards))]
	select {
	case shard <- job:
		r.metrics.queueDepth.Add(1)
		return true
	default:
		r.metrics.queueDrops.Add(1)
		return false
	}
}

func (r *udpRuntime) startDispatcher() {
	workers := r.config.SendWorkers
	if workers == 0 {
		workers = runtime.GOMAXPROCS(0) * 2
		if workers < 4 {
			workers = 4
		}
		if workers > 64 {
			workers = 64
		}
	}
	if workers > r.config.SendQueueSize {
		workers = r.config.SendQueueSize
	}
	queuePerShard := r.config.SendQueueSize / workers
	extraQueueSlots := r.config.SendQueueSize % workers
	r.shards = make([]chan udpSendJob, workers)
	for index := range workers {
		capacity := queuePerShard
		if index < extraQueueSlots {
			capacity++
		}
		jobs := make(chan udpSendJob, capacity)
		r.shards[index] = jobs
		r.workerWG.Add(1)
		go func() {
			defer r.workerWG.Done()
			for {
				select {
				case job := <-jobs:
					r.runSendJob(job)
				case <-r.lifetime.Done():
					// Release buffers still queued so the pool is not left holding
					// references, then exit. In-flight sends are abandoned, which is
					// safe for UDP during shutdown.
					for {
						select {
						case job := <-jobs:
							r.metrics.queueDepth.Add(-1)
							r.releaseInboundPacket(job.packet)
						default:
							return
						}
					}
				}
			}
		}()
	}
}

// runSendJob performs one outbound send and releases the packet buffer.
func (r *udpRuntime) runSendJob(job udpSendJob) {
	r.metrics.queueDepth.Add(-1)
	if job.ctx.Err() == nil {
		_, err := job.connector.SendPacket(job.ctx, job.packet.payload, job.target, job.preferred, job.fallback)
		if err != nil {
			r.metrics.errors.Add(1)
			reportUDPError(job.errCh, err)
		}
	}
	r.releaseInboundPacket(job.packet)
}

func (r *udpRuntime) wait(timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		r.workerWG.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

func (r *udpRuntime) logMetrics(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			slog.Info("SOCKS5 UDP metrics",
				"active_associations", r.metrics.activeAssociations.Load(),
				"total_associations", r.metrics.totalAssociations.Load(),
				"in_packets", r.metrics.inPackets.Load(),
				"in_bytes", r.metrics.inBytes.Load(),
				"out_packets", r.metrics.outPackets.Load(),
				"out_bytes", r.metrics.outBytes.Load(),
				"queue_drops", r.metrics.queueDrops.Load(),
				"queue_depth", r.metrics.queueDepth.Load(),
				"queue_capacity", r.config.SendQueueSize,
				"truncated_drops", r.metrics.truncatedDrops.Load(),
				"malformed_drops", r.metrics.malformedDrops.Load(),
				"fragment_drops", r.metrics.fragmentDrops.Load(),
				"unauthorized_drops", r.metrics.unauthorizedDrops.Load(),
				"association_limit_drops", r.metrics.associationDrops.Load(),
				"batch_fallbacks", r.metrics.batchFallbacks.Load(),
				"gro_coalesced_reads", r.metrics.groCoalescedReads.Load(),
				"gro_truncated_reads", r.metrics.groTruncatedReads.Load(),
				"batch_buffers_in_use", len(r.batchSlots),
				"batch_buffer_budget", cap(r.batchSlots),
				"errors", r.metrics.errors.Load(),
			)
		case <-ctx.Done():
			return
		}
	}
}
