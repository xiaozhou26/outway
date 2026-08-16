package connect

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDNSCacheMergesConcurrentLookups(t *testing.T) {
	var calls atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	cache := newDNSCache(time.Minute, time.Second, 16, 4, func(context.Context, string) ([]netip.Addr, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
	})

	var wg sync.WaitGroup
	wg.Add(2)
	results := make(chan []netip.Addr, 2)
	for range 2 {
		go func() {
			defer wg.Done()
			addrs, err := cache.Lookup(context.Background(), "EXAMPLE.COM.")
			if err != nil {
				t.Errorf("lookup failed: %v", err)
				return
			}
			results <- addrs
		}()
	}
	<-started
	close(release)
	wg.Wait()
	close(results)

	if got := calls.Load(); got != 1 {
		t.Fatalf("resolver called %d times, want 1", got)
	}
	for addrs := range results {
		if len(addrs) != 1 || addrs[0] != netip.MustParseAddr("192.0.2.1") {
			t.Fatalf("unexpected addresses: %v", addrs)
		}
	}
}

func TestDNSCacheExpiresEntries(t *testing.T) {
	var calls atomic.Int32
	cache := newDNSCache(10*time.Millisecond, time.Second, 16, 4, func(context.Context, string) ([]netip.Addr, error) {
		calls.Add(1)
		return []netip.Addr{netip.MustParseAddr("192.0.2.2")}, nil
	})

	if _, err := cache.Lookup(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Lookup(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("resolver called %d times before expiry, want 1", got)
	}

	time.Sleep(20 * time.Millisecond)
	if _, err := cache.Lookup(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("resolver called %d times after expiry, want 2", got)
	}
}

func TestDNSCacheBoundsConcurrentLookups(t *testing.T) {
	// Concurrency slots are per shard: with 16 shards and a budget of 16, each
	// shard gets one slot. Collect hostnames that land in the same shard so the
	// per-shard bound is directly observable.
	buckets := make(map[int][]string)
	for i := 0; len(buckets[0]) < 4; i++ {
		host := fmt.Sprintf("host-%d.example", i)
		shard := shardIndexOf(host)
		buckets[shard] = append(buckets[shard], host)
	}

	var active atomic.Int32
	var maximum atomic.Int32
	cache := newDNSCache(time.Minute, time.Second, 16, 16, func(context.Context, string) ([]netip.Addr, error) {
		current := active.Add(1)
		defer active.Add(-1)
		for {
			old := maximum.Load()
			if current <= old || maximum.CompareAndSwap(old, current) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		return []netip.Addr{netip.MustParseAddr("192.0.2.3")}, nil
	})

	var wg sync.WaitGroup
	for _, host := range buckets[0] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := cache.Lookup(context.Background(), host); err != nil {
				t.Errorf("lookup failed: %v", err)
			}
		}()
	}
	wg.Wait()
	if got := maximum.Load(); got > 1 {
		t.Fatalf("observed %d concurrent lookups within one shard, want at most 1", got)
	}
}

func TestDNSCacheLookupCached(t *testing.T) {
	cache := newDNSCache(time.Minute, time.Second, 16, 4, func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.0.2.9")}, nil
	})
	// Miss before any resolution; LookupCached never resolves.
	if _, ok := cache.LookupCached("example.com"); ok {
		t.Fatal("expected a miss before the first resolve")
	}
	if _, err := cache.Lookup(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	// Now a hit, including via the normalized (upper-case, trailing dot) key.
	addrs, ok := cache.LookupCached("EXAMPLE.COM.")
	if !ok || len(addrs) != 1 || addrs[0] != netip.MustParseAddr("192.0.2.9") {
		t.Fatalf("expected cached hit, got %v ok=%v", addrs, ok)
	}
}

func TestLookupCachedHostLiteral(t *testing.T) {
	got, ok := LookupCachedHost("192.0.2.7")
	if !ok || len(got) != 1 || got[0] != netip.MustParseAddr("192.0.2.7") {
		t.Fatalf("IPv4 literal: got %v ok=%v", got, ok)
	}
	if got, ok := LookupCachedHost("2001:db8::5"); !ok || len(got) != 1 || got[0] != netip.MustParseAddr("2001:db8::5") {
		t.Fatalf("IPv6 literal: got %v ok=%v", got, ok)
	}
	if _, ok := LookupCachedHost("uncached.example.invalid."); ok {
		t.Fatal("uncached domain should report a miss")
	}
}

func BenchmarkDNSCacheHit(b *testing.B) {
	cache := newDNSCache(time.Minute, time.Second, 16, 4, func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("2001:db8::1")}, nil
	})
	if _, err := cache.Lookup(context.Background(), "example.com"); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := cache.Lookup(context.Background(), "example.com"); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDNSCacheHitParallel measures the concurrent cache-hit path, which is
// the contended case for the single process-wide defaultDNSCache: many goroutines
// resolving already-cached domains at once.
func BenchmarkDNSCacheHitParallel(b *testing.B) {
	cache := newDNSCache(time.Minute, time.Second, 4096, 128, func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("2001:db8::1")}, nil
	})
	hosts := []string{"a.example", "b.example", "c.example", "d.example", "e.example", "f.example", "g.example", "h.example"}
	for _, h := range hosts {
		if _, err := cache.Lookup(context.Background(), h); err != nil {
			b.Fatal(err)
		}
	}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if _, err := cache.Lookup(ctx, hosts[i%len(hosts)]); err != nil {
				b.Fatal(err)
			}
			i++
		}
	})
}

// BenchmarkDNSCacheMiss exercises the miss path: shard write lock, in-flight
// registration, resolver call, and store.
func BenchmarkDNSCacheMiss(b *testing.B) {
	cache := newDNSCache(time.Minute, time.Second, 4096, 128, func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
	})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := cache.Lookup(context.Background(), fmt.Sprintf("miss-%d.example", i)); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDNSCacheSingleflight measures coalesced lookups: many goroutines
// resolving the same host share one resolver call.
func BenchmarkDNSCacheSingleflight(b *testing.B) {
	cache := newDNSCache(time.Minute, time.Second, 16, 128, func(context.Context, string) ([]netip.Addr, error) {
		time.Sleep(50 * time.Microsecond)
		return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
	})
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := cache.Lookup(context.Background(), "shared.example"); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func TestDNSCacheStatsCounters(t *testing.T) {
	cache := newDNSCache(time.Minute, time.Minute, 16, 16, func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
	})
	stats := cache.Stats()
	if stats != (DNSCacheStatsSnapshot{}) {
		t.Fatalf("fresh cache has non-zero stats: %+v", stats)
	}

	// A lookup on an absent host is a miss; the second one is a hit.
	if _, err := cache.Lookup(context.Background(), "stats.example"); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.LookupCached("stats.example"); !ok {
		t.Fatal("expected cached hit after resolution")
	}
	stats = cache.Stats()
	if stats.Misses != 1 || stats.Hits != 1 {
		t.Fatalf("after one resolve + one hit: %+v", stats)
	}
	if stats.HitRate() != 0.5 {
		t.Fatalf("hit rate = %f, want 0.5", stats.HitRate())
	}
}

func TestDNSCacheStatsNegativeHits(t *testing.T) {
	cache := newDNSCache(time.Minute, time.Minute, 16, 16, func(context.Context, string) ([]netip.Addr, error) {
		return nil, fmt.Errorf("NXDOMAIN")
	})
	if _, err := cache.Lookup(context.Background(), "negative.example"); err == nil {
		t.Fatal("expected resolution error")
	}
	// The failure is cached; a fresh Lookup must be served as a negative hit.
	if _, err := cache.Lookup(context.Background(), "negative.example"); err == nil {
		t.Fatal("expected cached error")
	}
	stats := cache.Stats()
	if stats.Misses != 1 || stats.NegativeHits != 1 {
		t.Fatalf("negative caching counters: %+v", stats)
	}
}

func TestDNSCacheStatsCapacityDrops(t *testing.T) {
	// maxEntries 16 across 16 shards = one entry per shard; two hosts sharing
	// a shard force an arbitrary (capacity) eviction on the second insert.
	cache := newDNSCache(time.Minute, time.Minute, 16, 16, func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.0.2.2")}, nil
	})
	first := "cap-0.example"
	shard := shardIndexOf(first)
	second := ""
	for i := 1; ; i++ {
		if candidate := fmt.Sprintf("cap-%d.example", i); shardIndexOf(candidate) == shard {
			second = candidate
			break
		}
	}
	if _, err := cache.Lookup(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Lookup(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	stats := cache.Stats()
	if stats.CapacityDrops != 1 {
		t.Fatalf("capacity drops = %d, want 1 (stats: %+v)", stats.CapacityDrops, stats)
	}
	// The arbitrarily evicted host is gone; the newest one survives.
	survived := 0
	for _, host := range []string{first, second} {
		if _, ok := cache.LookupCached(host); ok {
			survived++
		}
	}
	if survived != 1 {
		t.Fatalf("expected exactly one survivor after capacity eviction, got %d", survived)
	}
}
