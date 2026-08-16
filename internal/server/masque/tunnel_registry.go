package masque

import (
	"reflect"
	"sync"
	"sync/atomic"
)

const (
	tunnelRegistryShardBits = 5
	tunnelRegistryShards    = 1 << tunnelRegistryShardBits
)

// tunnelRegistry tracks active CONNECT-UDP tunnels. Registrations are sharded
// by tunnel identity so high setup/teardown churn does not serialize on one
// server-wide mutex.
type tunnelRegistry struct {
	closed atomic.Bool
	wg     sync.WaitGroup
	shards [tunnelRegistryShards]tunnelRegistryShard
}

type tunnelRegistryShard struct {
	mu      sync.Mutex
	closed  bool
	tunnels map[*tunnel]struct{}
	// Keep independently hot shard mutexes on separate cache lines, matching
	// serverbase.ConnectionSet's layout.
	_ [40]byte
}

func newTunnelRegistry() *tunnelRegistry {
	r := &tunnelRegistry{}
	for i := range r.shards {
		r.shards[i].tunnels = make(map[*tunnel]struct{})
	}
	return r
}

func (r *tunnelRegistry) shardFor(t *tunnel) *tunnelRegistryShard {
	h := uint64(reflect.ValueOf(t).Pointer()) * 0x9e3779b97f4a7c15
	return &r.shards[h>>(64-tunnelRegistryShardBits)]
}

// Add registers a tunnel. It returns false once shutdown has started. The
// WaitGroup increment happens while holding the shard lock so CloseAll cannot
// finish its registration barrier before the increment becomes visible.
func (r *tunnelRegistry) Add(t *tunnel) bool {
	if r.closed.Load() {
		return false
	}
	shard := r.shardFor(t)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if r.closed.Load() || shard.closed {
		return false
	}
	if _, exists := shard.tunnels[t]; exists {
		return true
	}
	shard.tunnels[t] = struct{}{}
	r.wg.Add(1)
	return true
}

// Remove unregisters a tunnel and releases its shutdown wait slot.
func (r *tunnelRegistry) Remove(t *tunnel) {
	shard := r.shardFor(t)
	shard.mu.Lock()
	if _, exists := shard.tunnels[t]; exists {
		delete(shard.tunnels, t)
		shard.mu.Unlock()
		r.wg.Done()
		return
	}
	shard.mu.Unlock()
}

// CloseAll prevents new registrations and returns a snapshot of all active
// tunnels. Callers must tear the tunnels down outside the shard locks and then
// call Wait. Entries remain registered until their serving goroutines return,
// ensuring each Add has exactly one matching Done.
func (r *tunnelRegistry) CloseAll() []*tunnel {
	r.closed.Store(true)
	var tunnels []*tunnel
	for i := range r.shards {
		shard := &r.shards[i]
		shard.mu.Lock()
		shard.closed = true
		for t := range shard.tunnels {
			tunnels = append(tunnels, t)
		}
		shard.mu.Unlock()
	}
	return tunnels
}

func (r *tunnelRegistry) Wait() {
	r.wg.Wait()
}
