package ndp

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
)

// fakeKernel records proxy-neighbor installs and removals.
type fakeKernel struct {
	mu        sync.Mutex
	installed map[netip.Addr]bool
	installs  int
	removes   int
	failAdd   error
	failDel   error
}

func newFakeKernel() *fakeKernel { return &fakeKernel{installed: map[netip.Addr]bool{}} }

func (k *fakeKernel) add(addr netip.Addr) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.failAdd != nil {
		return k.failAdd
	}
	k.installs++
	k.installed[addr] = true
	return nil
}

func (k *fakeKernel) del(addr netip.Addr) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.failDel != nil {
		return k.failDel
	}
	k.removes++
	delete(k.installed, addr)
	return nil
}

func (k *fakeKernel) has(addr netip.Addr) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.installed[addr]
}

func addr(i int) netip.Addr {
	return netip.MustParseAddr(fmt.Sprintf("2001:db8::%x", i+1))
}

func newTestCache(t *testing.T, maxEntries int) (*Cache, *fakeKernel) {
	t.Helper()
	k := newFakeKernel()
	c, err := NewCache(maxEntries, k.add, k.del)
	if err != nil {
		t.Fatal(err)
	}
	return c, k
}

func TestNewCacheRejectsBadArguments(t *testing.T) {
	k := newFakeKernel()
	if _, err := NewCache(0, k.add, k.del); err == nil {
		t.Fatal("expected max 0 to be rejected")
	}
	if _, err := NewCache(1, nil, k.del); err == nil {
		t.Fatal("expected nil install to be rejected")
	}
}

func TestEnsureInstallsOnceAndHitsAfterwards(t *testing.T) {
	c, k := newTestCache(t, 4)
	a := addr(0)
	for range 5 {
		c.Ensure(a)
	}
	if k.installs != 1 {
		t.Fatalf("installs = %d, want 1 (hits must not reinstall)", k.installs)
	}
	if !k.has(a) || !c.Contains(a) || c.Len() != 1 {
		t.Fatalf("entry missing: kernel=%v cache=%v len=%d", k.has(a), c.Contains(a), c.Len())
	}
}

func TestEnsureIgnoresIPv4(t *testing.T) {
	c, k := newTestCache(t, 4)
	c.Ensure(netip.MustParseAddr("192.0.2.1"))
	c.Ensure(netip.MustParseAddr("::ffff:192.0.2.1"))
	if k.installs != 0 || c.Len() != 0 {
		t.Fatalf("IPv4 addresses were installed: installs=%d len=%d", k.installs, c.Len())
	}
}

func TestEnsureEvictsAndRemovesWhenFull(t *testing.T) {
	const max = 8
	c, k := newTestCache(t, max)
	for i := range 3 * max {
		c.Ensure(addr(i))
		if c.Len() > max {
			t.Fatalf("cache grew to %d entries, max %d", c.Len(), max)
		}
	}
	if c.Len() != max {
		t.Fatalf("len = %d, want %d", c.Len(), max)
	}
	if len(k.installed) != max {
		t.Fatalf("kernel holds %d entries, want %d (evictions must be removed)", len(k.installed), max)
	}
	if k.removes != 2*max {
		t.Fatalf("removes = %d, want %d", k.removes, 2*max)
	}
	// The kernel and the cache agree on what is installed.
	for a := range k.installed {
		if !c.Contains(a) {
			t.Fatalf("kernel entry %s is not tracked by the cache", a)
		}
	}
}

func TestEnsureKeepsRecentlyUsedEntries(t *testing.T) {
	const max = 4
	c, _ := newTestCache(t, max)
	hot := addr(0)
	for i := range max {
		c.Ensure(addr(i))
	}
	// Keep touching hot while a stream of cold addresses churns through.
	for i := max; i < 10*max; i++ {
		c.Ensure(hot)
		c.Ensure(addr(i))
		if !c.Contains(hot) {
			t.Fatalf("hot entry evicted after inserting %s", addr(i))
		}
	}
}

func TestEnsureInstallFailureIsNotCached(t *testing.T) {
	c, k := newTestCache(t, 4)
	k.failAdd = errors.New("netlink: operation not permitted")
	a := addr(0)
	c.Ensure(a) // must not panic or block
	if c.Contains(a) {
		t.Fatal("failed install was recorded as installed")
	}
	k.failAdd = nil
	c.Ensure(a)
	if !c.Contains(a) || !k.has(a) {
		t.Fatal("install was not retried after a failure")
	}
}

func TestCloseRemovesEverythingAndStopsInstalls(t *testing.T) {
	c, k := newTestCache(t, 16)
	for i := range 10 {
		c.Ensure(addr(i))
	}
	closed := false
	c.onClose = func() error { closed = true; return nil }
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if len(k.installed) != 0 || c.Len() != 0 || !closed {
		t.Fatalf("after Close: kernel=%d cache=%d onClose=%v", len(k.installed), c.Len(), closed)
	}
	c.Ensure(addr(99))
	if k.has(addr(99)) {
		t.Fatal("Ensure installed an entry after Close")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestCloseReportsRemovalFailures(t *testing.T) {
	c, k := newTestCache(t, 4)
	c.Ensure(addr(0))
	c.Ensure(addr(1))
	k.failDel = errors.New("boom")
	if err := c.Close(); err == nil {
		t.Fatal("expected Close to report removal failures")
	}
}

func TestEnsureConcurrent(t *testing.T) {
	const max = 64
	c, k := newTestCache(t, max)
	var wg sync.WaitGroup
	for g := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 2000 {
				c.Ensure(addr((g*31 + i) % (3 * max)))
			}
		}()
	}
	wg.Wait()
	if c.Len() > max || len(k.installed) != c.Len() {
		t.Fatalf("len=%d kernel=%d max=%d", c.Len(), len(k.installed), max)
	}
}

func BenchmarkEnsureHit(b *testing.B) {
	k := newFakeKernel()
	c, _ := NewCache(1024, k.add, k.del)
	a := addr(0)
	c.Ensure(a)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c.Ensure(a)
		}
	})
}
