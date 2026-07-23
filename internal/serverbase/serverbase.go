// Package serverbase holds shared types and helpers used by the server package
// and its sub-packages (http, socks), breaking what would otherwise be an
// import cycle.
package serverbase

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"reflect"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/xiaozhou26/outway/internal/config"
	"github.com/xiaozhou26/outway/internal/connect"
)

const (
	DefaultHalfCloseGrace = 30 * time.Second
	DefaultShutdownWait   = 5 * time.Second
)

var bufferedReaderPool = sync.Pool{
	New: func() any { return bufio.NewReader(nil) },
}

var bufferedWriterPool = sync.Pool{
	New: func() any { return bufio.NewWriter(io.Discard) },
}

// Context holds all configuration and runtime state shared by the proxy
// servers.
type Context struct {
	Bind           netip.AddrPort
	Concurrent     uint32
	ConnectTimeout uint64
	Auth           config.AuthMode
	Connector      *connect.Connector
	UDP            config.UDPConfig
	ReusePort      bool
}

// AcceptShards returns how many SO_REUSEPORT listeners/accept loops to run.
// It is one unless reuse-port is enabled and supported, in which case it scales
// with the CPU count (capped) to spread accept across cores.
func AcceptShards(reusePort bool) int {
	if !reusePort || !reusePortSupported {
		return 1
	}
	shards := runtime.GOMAXPROCS(0)
	if shards < 1 {
		return 1
	}
	if shards > 16 {
		return 16
	}
	return shards
}

// TuneTCPConnection applies low-latency and dead-peer detection settings to an
// accepted TCP connection. Keepalive prevents abandoned clients from holding
// file descriptors indefinitely under large connection counts.
func TuneTCPConnection(conn net.Conn) {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(60 * time.Second)
	}
}

// AddrPortOf returns the netip.AddrPort for a connection address without the
// net.Addr.String() -> netip.ParseAddrPort round-trip, which allocates a string
// and reparses it on every accepted connection. The result is unmapped so an
// IPv4-in-IPv6 address matches what parsing the string would have produced; a
// nil or unrecognized address yields the zero (invalid) AddrPort.
func AddrPortOf(a net.Addr) netip.AddrPort {
	switch v := a.(type) {
	case *net.TCPAddr:
		ap := v.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	case *net.UDPAddr:
		ap := v.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	default:
		if a == nil {
			return netip.AddrPort{}
		}
		ap, _ := netip.ParseAddrPort(a.String())
		return ap
	}
}

// ListenTCPShards binds one or more TCP listeners for addr. When shards > 1 and
// the platform supports it, each listener sets SO_REUSEPORT so the kernel
// spreads incoming connections across them and a separate accept goroutine can
// run per shard. It falls back to a single listener when sharding is off or
// unsupported. A tcp6 network retries as tcp to allow dual-stack binds.
func ListenTCPShards(ctx context.Context, network, addr string, shards int) ([]net.Listener, error) {
	sharded := shards > 1 && reusePortSupported
	var control func(string, string, syscall.RawConn) error
	if sharded {
		control = controlReusePort
	}
	lc := net.ListenConfig{Control: control}

	first, err := lc.Listen(ctx, network, addr)
	if err != nil {
		if network == "tcp6" {
			first, err = lc.Listen(ctx, "tcp", addr)
		}
		if err != nil {
			return nil, err
		}
	}
	listeners := []net.Listener{first}
	if !sharded {
		return listeners, nil
	}

	// Bind the remaining shards on the concrete address the first listener
	// resolved, so SO_REUSEPORT shares one port instead of each shard taking a
	// fresh ephemeral port.
	resolved := first.Addr().String()
	for range shards - 1 {
		ln, err := lc.Listen(ctx, first.Addr().Network(), resolved)
		if err != nil {
			for _, existing := range listeners {
				_ = existing.Close()
			}
			return nil, err
		}
		listeners = append(listeners, ln)
	}
	return listeners, nil
}

// AcquireBufferedReader obtains a reusable default-sized buffered reader.
func AcquireBufferedReader(reader io.Reader) *bufio.Reader {
	buffered := bufferedReaderPool.Get().(*bufio.Reader)
	buffered.Reset(reader)
	return buffered
}

// ReleaseBufferedReader removes references to the connection and returns the
// reader to the pool.
func ReleaseBufferedReader(reader *bufio.Reader) {
	reader.Reset(nil)
	bufferedReaderPool.Put(reader)
}

// AcquireBufferedWriter obtains a reusable default-sized buffered writer.
func AcquireBufferedWriter(writer io.Writer) *bufio.Writer {
	buffered := bufferedWriterPool.Get().(*bufio.Writer)
	buffered.Reset(writer)
	return buffered
}

// ReleaseBufferedWriter removes references to the connection and returns the
// writer to the pool. Callers must flush before releasing it.
func ReleaseBufferedWriter(writer *bufio.Writer) {
	writer.Reset(io.Discard)
	bufferedWriterPool.Put(writer)
}

// ConnectionGate limits the number of concurrently handled client
// connections. A zero limit means unlimited connections.
type ConnectionGate struct {
	tokens chan struct{}
}

// connSetShardBits selects the number of lock shards (1<<bits) in a
// ConnectionSet. Connections register on every open and deregister on every
// close, so sharding that registry keeps high connection churn off a single
// process-wide mutex.
const (
	connSetShardBits = 5
	connSetShards    = 1 << connSetShardBits
)

// ConnectionSet tracks accepted client connections so a server can close all of
// them during shutdown. It is sharded by connection identity so concurrent
// opens and closes rarely contend on the same lock.
type ConnectionSet struct {
	done      chan struct{}
	closeOnce sync.Once
	shards    [connSetShards]connSetShard
}

type connSetShard struct {
	mu     sync.Mutex
	closed bool
	conns  map[net.Conn]struct{}
	// Pad to a cache line so hot shard mutexes on different cores don't
	// false-share.
	_ [40]byte
}

// NewConnectionSet creates an empty connection registry.
func NewConnectionSet() *ConnectionSet {
	s := &ConnectionSet{done: make(chan struct{})}
	for i := range s.shards {
		s.shards[i].conns = make(map[net.Conn]struct{})
	}
	return s
}

// shardFor maps a connection to its lock shard. It Fibonacci-hashes the
// connection's identity pointer and takes the high bits so that pointer
// alignment does not cluster connections into a handful of shards.
func (s *ConnectionSet) shardFor(conn net.Conn) *connSetShard {
	h := uint64(reflect.ValueOf(conn).Pointer()) * 0x9e3779b97f4a7c15
	return &s.shards[h>>(64-connSetShardBits)]
}

// Add registers a connection. It returns false after shutdown has started.
func (s *ConnectionSet) Add(conn net.Conn) bool {
	shard := s.shardFor(conn)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if shard.closed {
		return false
	}
	shard.conns[conn] = struct{}{}
	return true
}

// Remove unregisters a connection.
func (s *ConnectionSet) Remove(conn net.Conn) {
	shard := s.shardFor(conn)
	shard.mu.Lock()
	delete(shard.conns, conn)
	shard.mu.Unlock()
}

// CloseAll prevents new registrations and closes all tracked connections.
func (s *ConnectionSet) CloseAll() error {
	s.closeOnce.Do(func() { close(s.done) })

	var errs []error
	for i := range s.shards {
		shard := &s.shards[i]
		shard.mu.Lock()
		shard.closed = true
		conns := make([]net.Conn, 0, len(shard.conns))
		for conn := range shard.conns {
			conns = append(conns, conn)
		}
		shard.conns = nil
		shard.mu.Unlock()

		// Close outside the shard lock: a slow Close must not block Add/Remove
		// on other connections in the same shard.
		for _, conn := range conns {
			if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// Done is closed when shutdown starts.
func (s *ConnectionSet) Done() <-chan struct{} { return s.done }

// NewConnectionGate creates a connection concurrency gate.
func NewConnectionGate(max uint32) *ConnectionGate {
	if max == 0 {
		return &ConnectionGate{}
	}
	return &ConnectionGate{tokens: make(chan struct{}, int(max))}
}

// NewTLSHandshakeGate limits concurrent CPU-heavy TLS handshakes while still
// allowing a much larger number of established proxy connections.
func NewTLSHandshakeGate(maxConnections uint32) *ConnectionGate {
	limit := runtime.GOMAXPROCS(0) * 32
	if limit < 64 {
		limit = 64
	}
	if limit > 1024 {
		limit = 1024
	}
	if maxConnections > 0 && uint32(limit) > maxConnections {
		limit = int(maxConnections)
	}
	if limit < 1 {
		limit = 1
	}
	return NewConnectionGate(uint32(limit))
}

// Acquire waits until a connection slot is available.
func (g *ConnectionGate) Acquire() {
	if g != nil && g.tokens != nil {
		g.tokens <- struct{}{}
	}
}

// AcquireUntil waits for a connection slot or returns false when shutdown
// starts. If shutdown races with a successful acquire, the slot is returned.
func (g *ConnectionGate) AcquireUntil(done <-chan struct{}) bool {
	if g == nil || g.tokens == nil {
		select {
		case <-done:
			return false
		default:
			return true
		}
	}
	select {
	case g.tokens <- struct{}{}:
		select {
		case <-done:
			<-g.tokens
			return false
		default:
			return true
		}
	case <-done:
		return false
	}
}

// Release returns a previously acquired connection slot.
func (g *ConnectionGate) Release() {
	if g != nil && g.tokens != nil {
		<-g.tokens
	}
}

// CopyBidirectional copies data in both directions between two connections.
//
// On Linux, io.Copy uses splice(2) for TCP-to-TCP copies, providing
// kernel-space zero-copy behavior equivalent to the Rust realm_io
// bidi_zero_copy path. On other platforms it falls back to userspace copying.
//
// When one direction completes (EOF), the write side of the peer is half-closed
// so the EOF propagates cleanly to the remote.
func CopyBidirectional(a, b net.Conn) (int64, int64, error) {
	return CopyBidirectionalContext(context.Background(), a, b, 0)
}

// CopyBidirectionalContext copies in both directions. Cancellation interrupts
// blocked reads immediately. When one side half-closes, halfCloseGrace bounds
// how long the reverse direction may remain open; zero preserves unlimited
// half-close behavior.
func CopyBidirectionalContext(ctx context.Context, a, b net.Conn, halfCloseGrace time.Duration) (int64, int64, error) {
	var n1, n2 int64
	var wg sync.WaitGroup
	wg.Add(1)
	var firstDone sync.Once
	var graceTimer *time.Timer
	interrupt := func() {
		now := time.Now()
		_ = a.SetDeadline(now)
		_ = b.SetDeadline(now)
	}
	cancelStop := context.AfterFunc(ctx, interrupt)
	finishDirection := func(dst net.Conn) {
		_ = CloseWrite(dst)
		firstDone.Do(func() {
			if halfCloseGrace > 0 {
				graceTimer = time.AfterFunc(halfCloseGrace, interrupt)
			}
		})
	}

	go func() {
		defer wg.Done()
		n1, _ = copyStream(b, a)
		finishDirection(b)
	}()

	// The caller's existing connection goroutine handles the reverse direction;
	// only one additional goroutine is needed for full duplex copying.
	n2, _ = copyStream(a, b)
	finishDirection(a)

	wg.Wait()
	cancelStop()
	if graceTimer != nil {
		graceTimer.Stop()
	}
	return n1, n2, nil
}

// WaitGroupTimeout waits for handlers to exit without allowing shutdown to
// block forever. It returns true when all handlers completed.
func WaitGroupTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// CloseWrite half-closes the write side of a connection if the underlying type
// supports it.
func CloseWrite(c net.Conn) error {
	if tc, ok := c.(*net.TCPConn); ok {
		return tc.CloseWrite()
	}
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
