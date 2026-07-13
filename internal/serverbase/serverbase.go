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
	"runtime"
	"sync"
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

// ConnectionSet tracks accepted client connections so a server can close all
// of them during shutdown.
type ConnectionSet struct {
	mu     sync.Mutex
	closed bool
	conns  map[net.Conn]struct{}
	done   chan struct{}
}

// NewConnectionSet creates an empty connection registry.
func NewConnectionSet() *ConnectionSet {
	return &ConnectionSet{
		conns: make(map[net.Conn]struct{}),
		done:  make(chan struct{}),
	}
}

// Add registers a connection. It returns false after shutdown has started.
func (s *ConnectionSet) Add(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conns[conn] = struct{}{}
	return true
}

// Remove unregisters a connection.
func (s *ConnectionSet) Remove(conn net.Conn) {
	s.mu.Lock()
	delete(s.conns, conn)
	s.mu.Unlock()
}

// CloseAll prevents new registrations and closes all tracked connections.
func (s *ConnectionSet) CloseAll() error {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.done)
	}
	conns := make([]net.Conn, 0, len(s.conns))
	for conn := range s.conns {
		conns = append(conns, conn)
	}
	s.mu.Unlock()

	var errs []error
	for _, conn := range conns {
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
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
