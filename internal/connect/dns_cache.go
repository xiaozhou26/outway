package connect

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	defaultDNSCacheTTL         = 30 * time.Second
	defaultDNSNegativeCacheTTL = 3 * time.Second
	defaultDNSCacheSize        = 4096
	defaultMaxDNSLookups       = 128

	// dnsCacheShards splits entries across independently locked sub-maps so
	// cache hits on different hosts never contend, mirroring the sharded
	// connection registry.
	dnsCacheShards = 16
)

type dnsLookupFunc func(context.Context, string) ([]netip.Addr, error)

type dnsCacheEntry struct {
	addrs     []netip.Addr
	err       error
	expiresAt time.Time
}

type dnsLookupCall struct {
	done  chan struct{}
	addrs []netip.Addr
	err   error
}

// dnsCacheShard holds one lock over a subset of cache entries. It also owns a
// share of the resolver-concurrency budget so a miss storm on one shard cannot
// starve or serialize lookups on the others.
type dnsCacheShard struct {
	mu          sync.RWMutex
	entries     map[string]dnsCacheEntry
	inflight    map[string]*dnsLookupCall
	lookupSlots chan struct{}
}

// dnsCache is a bounded TTL cache that also merges concurrent lookups for the
// same hostname. It prevents connection bursts from creating matching DNS
// bursts against the system resolver. Entries, in-flight lookups, and resolver
// concurrency slots are sharded by hostname hash so lookups on different hosts
// proceed under different locks.
type dnsCache struct {
	shards      [dnsCacheShards]dnsCacheShard
	ttl         time.Duration
	negativeTTL time.Duration
	maxEntries  int
	lookup      dnsLookupFunc
}

func newDNSCache(ttl, negativeTTL time.Duration, maxEntries, maxConcurrent int, lookup dnsLookupFunc) *dnsCache {
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	c := &dnsCache{
		ttl:         ttl,
		negativeTTL: negativeTTL,
		maxEntries:  maxEntries,
		lookup:      lookup,
	}
	// Each shard gets an equal share of the budget (at least one slot); the
	// process-wide ceiling becomes shards × slots.
	slotsPerShard := maxConcurrent / dnsCacheShards
	if slotsPerShard < 1 {
		slotsPerShard = 1
	}
	for i := range c.shards {
		c.shards[i].entries = make(map[string]dnsCacheEntry)
		c.shards[i].inflight = make(map[string]*dnsLookupCall)
		c.shards[i].lookupSlots = make(chan struct{}, slotsPerShard)
	}
	return c
}

// shardIndexOf maps a normalized hostname to a shard via FNV-1a.
func shardIndexOf(key string) int {
	h := uint32(2166136261)
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return int(h % dnsCacheShards)
}

func (c *dnsCache) shardFor(key string) *dnsCacheShard {
	return &c.shards[shardIndexOf(key)]
}

var defaultDNSCache = newDNSCache(
	defaultDNSCacheTTL,
	defaultDNSNegativeCacheTTL,
	defaultDNSCacheSize,
	defaultMaxDNSLookups,
	func(ctx context.Context, host string) ([]netip.Addr, error) {
		addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		for i := range addrs {
			addrs[i] = addrs[i].Unmap()
		}
		return addrs, nil
	},
)

// LookupCached returns cached, still-valid addresses for host without ever
// triggering a resolution. ok is false on a cache miss or a cached failure, so
// the caller can fall back to a resolving path.
func (c *dnsCache) LookupCached(host string) ([]netip.Addr, bool) {
	key := normalizeDNSName(host)
	now := time.Now()
	shard := c.shardFor(key)
	shard.mu.RLock()
	defer shard.mu.RUnlock()
	entry, ok := shard.entries[key]
	if !ok || entry.err != nil || len(entry.addrs) == 0 || !now.Before(entry.expiresAt) {
		return nil, false
	}
	return entry.addrs, true
}

// Lookup returns immutable cached addresses or resolves the host. Callers must
// not modify the returned slice.
func (c *dnsCache) Lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	key := normalizeDNSName(host)
	now := time.Now()
	shard := c.shardFor(key)

	// Fast path: a valid cached entry needs only a read lock, so concurrent
	// hits resolve in parallel instead of serializing.
	shard.mu.RLock()
	if entry, ok := shard.entries[key]; ok && now.Before(entry.expiresAt) {
		shard.mu.RUnlock()
		return entry.addrs, entry.err
	}
	shard.mu.RUnlock()

	shard.mu.Lock()
	// Re-check under the write lock: another goroutine may have resolved this
	// key (or started an in-flight lookup) between the read unlock and here.
	if entry, ok := shard.entries[key]; ok {
		if now.Before(entry.expiresAt) {
			shard.mu.Unlock()
			return entry.addrs, entry.err
		}
		delete(shard.entries, key)
	}
	if call, ok := shard.inflight[key]; ok {
		shard.mu.Unlock()
		select {
		case <-call.done:
			return call.addrs, call.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	call := &dnsLookupCall{done: make(chan struct{})}
	shard.inflight[key] = call
	shard.mu.Unlock()

	addrs, err := shard.resolve(ctx, c.lookup, key)

	shard.mu.Lock()
	call.addrs = addrs
	call.err = err
	delete(shard.inflight, key)
	if ctx.Err() == nil {
		ttl := c.ttl
		if err != nil {
			ttl = c.negativeTTL
		}
		if ttl > 0 && c.maxEntries > 0 {
			c.evictLocked(shard, now)
			shard.entries[key] = dnsCacheEntry{
				addrs:     addrs,
				err:       err,
				expiresAt: time.Now().Add(ttl),
			}
		}
	}
	close(call.done)
	shard.mu.Unlock()

	return addrs, err
}

func (s *dnsCacheShard) resolve(ctx context.Context, lookup dnsLookupFunc, host string) ([]netip.Addr, error) {
	select {
	case s.lookupSlots <- struct{}{}:
		defer func() { <-s.lookupSlots }()
		return lookup(ctx, host)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *dnsCache) evictLocked(shard *dnsCacheShard, now time.Time) {
	perShardMax := c.maxEntries / dnsCacheShards
	if len(shard.entries) < perShardMax {
		return
	}
	for key, entry := range shard.entries {
		if !now.Before(entry.expiresAt) {
			delete(shard.entries, key)
		}
	}
	if len(shard.entries) < perShardMax {
		return
	}
	// The cache is deliberately small and DNS lookups are relatively expensive;
	// arbitrary eviction is sufficient here and avoids a global LRU hot lock.
	for key := range shard.entries {
		delete(shard.entries, key)
		break
	}
}

func normalizeDNSName(host string) string {
	return strings.ToLower(strings.TrimSuffix(host, "."))
}
