// Package ndp keeps kernel proxy-NDP entries for the IPv6 source addresses the
// connector picks from its CIDR.
//
// When a provider puts a prefix on-link, its router sends a Neighbor
// Solicitation for every source address before it delivers the replies. The
// loopback local route outway installs makes those addresses bindable but does
// not answer the solicitations. A proxy-neighbor entry
// (`ip -6 neigh add proxy <addr> dev <iface>`) makes the kernel answer for the
// address, as ndppd would.
//
// Cache is the platform-neutral part: a bounded set of installed addresses
// with injected install and delete functions, so it can be unit tested
// anywhere. The Linux netlink backend lives in ndp_linux.go.
package ndp

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultMaxEntries is the default bound on installed proxy-neighbor entries.
const DefaultMaxEntries = 65536

// warnInterval rate-limits install/delete failure warnings, which would
// otherwise repeat on every dial while the kernel keeps refusing.
const warnInterval = 10 * time.Second

// Func installs or removes one proxy-neighbor entry.
type Func func(netip.Addr) error

// slot holds one installed address. used is the CLOCK reference bit: a hit
// sets it under the read lock, and the eviction hand clears it, giving the
// entry a second chance before it is evicted.
type slot struct {
	addr netip.Addr
	used atomic.Bool
}

// Cache tracks the proxy-neighbor entries outway installed. It evicts with
// CLOCK (second chance), an approximation of LRU that keeps the hit path to a
// read lock, one map lookup, and at most one atomic store. Misses, evictions,
// and Close serialize on the write lock, so kernel install/delete calls for
// one address never interleave.
type Cache struct {
	install Func
	remove  Func
	max     int
	onClose func() error

	mu     sync.RWMutex
	index  map[netip.Addr]int
	slots  []slot
	hand   int
	closed bool

	lastWarn atomic.Int64
}

// NewCache returns a cache that installs entries with install, removes evicted
// entries with remove, and holds at most maxEntries addresses.
func NewCache(maxEntries int, install, remove Func) (*Cache, error) {
	if maxEntries < 1 {
		return nil, fmt.Errorf("proxy NDP entry limit must be at least 1, got %d", maxEntries)
	}
	if install == nil || remove == nil {
		return nil, errors.New("proxy NDP cache requires install and remove functions")
	}
	return &Cache{
		install: install,
		remove:  remove,
		max:     maxEntries,
		index:   make(map[netip.Addr]int),
	}, nil
}

// Ensure installs a proxy-neighbor entry for addr unless one is already
// present. Non-IPv6 addresses are ignored. Failures are logged (rate-limited)
// and otherwise swallowed: a missing entry must never fail the dial.
func (c *Cache) Ensure(addr netip.Addr) {
	if !addr.Is6() || addr.Is4In6() {
		return
	}
	c.mu.RLock()
	if i, ok := c.index[addr]; ok {
		if s := &c.slots[i]; !s.used.Load() {
			s.used.Store(true)
		}
		c.mu.RUnlock()
		return
	}
	closed := c.closed
	c.mu.RUnlock()
	if closed {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	if i, ok := c.index[addr]; ok {
		c.slots[i].used.Store(true)
		return
	}
	if err := c.install(addr); err != nil {
		c.warn("install proxy NDP entry", addr, err)
		return
	}
	// New entries start with a clear reference bit, so only a later hit earns
	// the second chance. The hand needs about max more misses to come back to
	// this slot, so a fresh entry cannot be evicted before its dial runs.
	if len(c.slots) < c.max {
		c.slots = append(c.slots, slot{addr: addr})
		c.index[addr] = len(c.slots) - 1
		return
	}
	c.replaceVictim(addr)
}

// replaceVictim advances the CLOCK hand to the first entry whose reference bit
// is clear, removes that entry from the kernel, and reuses its slot for addr.
// It runs at most two sweeps. The caller holds the write lock.
func (c *Cache) replaceVictim(addr netip.Addr) {
	for {
		s := &c.slots[c.hand]
		if s.used.Load() {
			s.used.Store(false)
			c.hand = (c.hand + 1) % len(c.slots)
			continue
		}
		victim := s.addr
		if err := c.remove(victim); err != nil {
			c.warn("remove evicted proxy NDP entry", victim, err)
		}
		delete(c.index, victim)
		s.addr = addr
		c.index[addr] = c.hand
		c.hand = (c.hand + 1) % len(c.slots)
		return
	}
}

// Len reports how many entries are installed.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.index)
}

// Contains reports whether addr has an installed entry.
func (c *Cache) Contains(addr netip.Addr) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.index[addr]
	return ok
}

// Close removes every installed entry and stops further installs. It is
// idempotent.
func (c *Cache) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	var errs error
	failed := 0
	for addr := range c.index {
		if err := c.remove(addr); err != nil {
			failed++
			if failed == 1 {
				errs = fmt.Errorf("remove proxy NDP entry %s: %w", addr, err)
			}
		}
	}
	if failed > 1 {
		errs = fmt.Errorf("%w (and %d more)", errs, failed-1)
	}
	removed := len(c.index) - failed
	clear(c.index)
	c.slots = nil
	if c.onClose != nil {
		errs = errors.Join(errs, c.onClose())
	}
	slog.Info("Removed proxy NDP entries", "removed", removed, "failed", failed)
	return errs
}

func (c *Cache) warn(action string, addr netip.Addr, err error) {
	now := time.Now().UnixNano()
	last := c.lastWarn.Load()
	if now-last < int64(warnInterval) || !c.lastWarn.CompareAndSwap(last, now) {
		return
	}
	slog.Warn("Proxy NDP failure (further failures suppressed for 10s)", "action", action, "address", addr, "error", err)
}
