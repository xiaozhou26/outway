package connect

import (
	"context"
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
	var active atomic.Int32
	var maximum atomic.Int32
	cache := newDNSCache(time.Minute, time.Second, 16, 2, func(context.Context, string) ([]netip.Addr, error) {
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
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := cache.Lookup(context.Background(), "host-"+string(rune('a'+i))+".example"); err != nil {
				t.Errorf("lookup failed: %v", err)
			}
		}()
	}
	wg.Wait()
	if got := maximum.Load(); got > 2 {
		t.Fatalf("observed %d concurrent lookups, want at most 2", got)
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
