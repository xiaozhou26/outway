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

// dnsCache is a bounded TTL cache that also merges concurrent lookups for the
// same hostname. It prevents connection bursts from creating matching DNS
// bursts against the system resolver.
type dnsCache struct {
	mu          sync.Mutex
	entries     map[string]dnsCacheEntry
	inflight    map[string]*dnsLookupCall
	ttl         time.Duration
	negativeTTL time.Duration
	maxEntries  int
	lookup      dnsLookupFunc
	lookupSlots chan struct{}
}

func newDNSCache(ttl, negativeTTL time.Duration, maxEntries, maxConcurrent int, lookup dnsLookupFunc) *dnsCache {
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	return &dnsCache{
		entries:     make(map[string]dnsCacheEntry),
		inflight:    make(map[string]*dnsLookupCall),
		ttl:         ttl,
		negativeTTL: negativeTTL,
		maxEntries:  maxEntries,
		lookup:      lookup,
		lookupSlots: make(chan struct{}, maxConcurrent),
	}
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
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
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

	c.mu.Lock()
	if entry, ok := c.entries[key]; ok {
		if now.Before(entry.expiresAt) {
			c.mu.Unlock()
			return entry.addrs, entry.err
		}
		delete(c.entries, key)
	}
	if call, ok := c.inflight[key]; ok {
		c.mu.Unlock()
		select {
		case <-call.done:
			return call.addrs, call.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	call := &dnsLookupCall{done: make(chan struct{})}
	c.inflight[key] = call
	c.mu.Unlock()

	addrs, err := c.resolve(ctx, key)

	c.mu.Lock()
	call.addrs = addrs
	call.err = err
	delete(c.inflight, key)
	if ctx.Err() == nil {
		ttl := c.ttl
		if err != nil {
			ttl = c.negativeTTL
		}
		if ttl > 0 && c.maxEntries > 0 {
			c.evictLocked(now)
			c.entries[key] = dnsCacheEntry{
				addrs:     addrs,
				err:       err,
				expiresAt: time.Now().Add(ttl),
			}
		}
	}
	close(call.done)
	c.mu.Unlock()

	return addrs, err
}

func (c *dnsCache) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	select {
	case c.lookupSlots <- struct{}{}:
		defer func() { <-c.lookupSlots }()
		return c.lookup(ctx, host)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *dnsCache) evictLocked(now time.Time) {
	if len(c.entries) < c.maxEntries {
		return
	}
	for key, entry := range c.entries {
		if !now.Before(entry.expiresAt) {
			delete(c.entries, key)
		}
	}
	if len(c.entries) < c.maxEntries {
		return
	}
	// The cache is deliberately small and DNS lookups are relatively expensive;
	// arbitrary eviction is sufficient here and avoids a global LRU hot lock.
	for key := range c.entries {
		delete(c.entries, key)
		break
	}
}

func normalizeDNSName(host string) string {
	return strings.ToLower(strings.TrimSuffix(host, "."))
}
