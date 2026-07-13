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
}

type udpRuntime struct {
	config           config.UDPConfig
	pool             sync.Pool
	metrics          udpMetrics
	startOnce        sync.Once
	shards           []chan udpSendJob
	sequence         atomic.Uint64
	lifetime         context.Context
	dispatchMu       sync.RWMutex
	closed           bool
	associationSlots chan struct{}
	workerWG         sync.WaitGroup
	batchSlots       chan struct{}
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

func (r *udpRuntime) dispatch(job udpSendJob) bool {
	if r.lifetime.Err() != nil {
		return false
	}
	r.startOnce.Do(r.startDispatcher)
	r.dispatchMu.RLock()
	defer r.dispatchMu.RUnlock()
	if r.closed {
		return false
	}
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
			for job := range jobs {
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
		}()
	}
	go func() {
		<-r.lifetime.Done()
		r.dispatchMu.Lock()
		r.closed = true
		for _, jobs := range r.shards {
			close(jobs)
		}
		r.dispatchMu.Unlock()
	}()
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
				"batch_buffers_in_use", len(r.batchSlots),
				"batch_buffer_budget", cap(r.batchSlots),
				"errors", r.metrics.errors.Load(),
			)
		case <-ctx.Done():
			return
		}
	}
}
