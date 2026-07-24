package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	nethttp "net/http"
	"sync"
	"time"

	"github.com/xiaozhou26/outway/internal/server/http"
	"github.com/xiaozhou26/outway/internal/server/socks"
	"github.com/xiaozhou26/outway/internal/serverbase"
)

// AutoDetectServer listens on a single port and routes each connection to the
// appropriate protocol handler (SOCKS5, HTTP, or HTTPS) based on the first
// byte of the connection.
type AutoDetectServer struct {
	listener       net.Listener
	extraListeners []net.Listener
	socksAcc       socks.Socks5Acceptor
	httpHdl        http.Handler
	httpsHdl       http.Handler
	tlsConfig      *tls.Config
	timeout        time.Duration
	gate           *serverbase.ConnectionGate
	tlsGate        *serverbase.ConnectionGate
	conns          *serverbase.ConnectionSet
	lifetimes      *serverbase.LifetimeShards
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	closeOnce      sync.Once
	closeErr       error
}

// NewAutoDetectServer binds one or more TCP listeners (SO_REUSEPORT shards when
// enabled) and prepares the three handlers (SOCKS5, HTTP, HTTPS) for protocol
// auto-detection.
func NewAutoDetectServer(ctx Context, certPath, keyPath string) (*AutoDetectServer, error) {
	network := "tcp4"
	if ctx.Bind.Addr().Is6() {
		network = "tcp6"
	}
	lifetime, cancel := context.WithCancel(context.Background())
	listeners, err := serverbase.ListenTCPShards(lifetime, network, ctx.Bind.String(), serverbase.AcceptShards(ctx.ReusePort))
	if err != nil {
		cancel()
		return nil, err
	}
	closeListeners := func() {
		for _, ln := range listeners {
			_ = ln.Close()
		}
	}

	// Build the TLS config for HTTPS connections.
	var tlsCfg *tls.Config
	if certPath != "" && keyPath != "" {
		cfg, err := http.NewTLSConfigFromFiles(certPath, keyPath)
		if err != nil {
			closeListeners()
			cancel()
			return nil, err
		}
		tlsCfg = cfg.Config()
	} else {
		cfg, err := http.NewSelfSignedTLSConfig()
		if err != nil {
			closeListeners()
			cancel()
			return nil, err
		}
		tlsCfg = cfg.Config()
	}

	handler := http.NewHandler(ctx)
	return &AutoDetectServer{
		listener:       listeners[0],
		extraListeners: listeners[1:],
		socksAcc:       socks.NewAcceptor(ctx, lifetime),
		httpHdl:        handler,
		httpsHdl:       handler,
		tlsConfig:      tlsCfg,
		timeout:        time.Duration(ctx.ConnectTimeout) * time.Second,
		gate:           serverbase.NewConnectionGate(ctx.Concurrent),
		tlsGate:        serverbase.NewTLSHandshakeGate(ctx.Concurrent),
		conns:          serverbase.NewConnectionSet(),
		lifetimes:      serverbase.NewLifetimeShards(lifetime),
		cancel:         cancel,
	}, nil
}

// Start runs the accept loops until the server is shut down.
func (s *AutoDetectServer) Start() error {
	slog.Info(fmt.Sprintf("Http(s)/Socks5 proxy server listening on %s", s.listener.Addr()))
	for _, ln := range s.extraListeners {
		listener := ln
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			_ = s.acceptLoop(listener)
		}()
	}
	// The main accept loop holds a WaitGroup slot too, so handler goroutines can
	// wg.Add from inside any accept loop without racing a concurrent wg.Wait
	// (the counter cannot reach zero while an accept loop is still running).
	s.wg.Add(1)
	defer s.wg.Done()
	return s.acceptLoop(s.listener)
}

func (s *AutoDetectServer) acceptLoop(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if isClosedErr(err) {
				return nil
			}
			slog.Debug("Failed to accept connection", "error", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		// Acquire a connection slot before registering: a saturated gate applies
		// backpressure to this accept loop alone and must not block shutdown or
		// other SO_REUSEPORT accept shards.
		if !s.gate.AcquireUntil(s.conns.Done()) {
			_ = conn.Close()
			return nil
		}
		// A connection registered before CloseAll marked its shard is closed by
		// CloseAll, so the handler's blocked I/O cannot outlive shutdown; one
		// that lost the race is refused here.
		if !s.conns.Add(conn) {
			s.gate.Release()
			_ = conn.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.gate.Release()
			defer s.conns.Remove(conn)
			s.accept(conn)
		}()
	}
}

// Close stops the listeners.
func (s *AutoDetectServer) Close() error {
	s.closeOnce.Do(func() {
		s.cancel()
		connectionErr := s.conns.CloseAll()
		listenerErr := s.listener.Close()
		if errors.Is(listenerErr, net.ErrClosed) {
			listenerErr = nil
		}
		for _, ln := range s.extraListeners {
			if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				listenerErr = errors.Join(listenerErr, err)
			}
		}
		s.httpHdl.CloseIdleConnections()
		var waitErr error
		if !serverbase.WaitGroupTimeout(&s.wg, serverbase.DefaultShutdownWait) {
			waitErr = errors.New("auto-detect handlers did not stop before shutdown timeout")
		}
		if !s.socksAcc.WaitUDPWorkers(serverbase.DefaultShutdownWait) {
			waitErr = errors.Join(waitErr, errors.New("SOCKS5 UDP workers did not stop before shutdown timeout"))
		}
		s.closeErr = errors.Join(connectionErr, listenerErr, waitErr)
	})
	return s.closeErr
}

// accept peeks at the first byte of the connection to determine the protocol
// and dispatches to the appropriate handler.
func (s *AutoDetectServer) accept(conn net.Conn) {
	serverbase.TuneTCPConnection(conn)

	// Peek the first byte to determine the protocol:
	//   0x05         -> SOCKS5
	//   0x00..=0x40  -> HTTPS (TLS starts with a binary byte < 0x41)
	//   >= 0x41      -> HTTP (ASCII method: GET, POST, CONNECT, etc.)
	br := serverbase.AcquireBufferedReader(conn)
	defer serverbase.ReleaseBufferedReader(br)
	_ = conn.SetReadDeadline(time.Now().Add(s.timeout))
	first, err := br.Peek(1)
	if err != nil {
		slog.Debug("Protocol detection failed", "error", err)
		_ = conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	peer := serverbase.AddrPortOf(conn.RemoteAddr())
	ctx := s.lifetimes.For(conn)

	switch {
	case first[0] == 0x05:
		// SOCKS5: pass the connection (with buffered reader) to the SOCKS5
		// acceptor.
		s.socksAcc.WithLifetime(ctx).Accept(&bufferedConn{Conn: conn, br: br}, peer)
	case first[0] < 0x41:
		// HTTPS: wrap with TLS and serve HTTP.
		s.serveHTTPS(ctx, &bufferedConn{Conn: conn, br: br})
	default:
		// HTTP: serve plain HTTP.
		s.serveHTTP(ctx, conn, br)
	}
}

// serveHTTPS wraps the connection with TLS and serves HTTP over it.
func (s *AutoDetectServer) serveHTTPS(ctx context.Context, conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(s.timeout))
	tlsConn := tls.Server(conn, s.tlsConfig)
	if !s.tlsGate.AcquireUntil(s.conns.Done()) {
		_ = conn.Close()
		return
	}
	err := tlsConn.Handshake()
	s.tlsGate.Release()
	if err != nil {
		slog.Debug("Auto-detected TLS handshake failed", "error", err)
		_ = conn.Close()
		return
	}
	_ = conn.SetDeadline(time.Time{})
	br := serverbase.AcquireBufferedReader(tlsConn)
	defer serverbase.ReleaseBufferedReader(br)
	bw := serverbase.AcquireBufferedWriter(tlsConn)
	defer serverbase.ReleaseBufferedWriter(bw)
	for {
		_ = tlsConn.SetReadDeadline(time.Now().Add(s.timeout))
		req, err := nethttp.ReadRequest(br)
		if err != nil {
			break
		}
		_ = tlsConn.SetReadDeadline(time.Time{})
		keepAlive, _ := s.httpsHdl.Proxy(ctx, tlsConn, br, req, bw)
		if !keepAlive {
			break
		}
	}
	_ = tlsConn.Close()
}

// serveHTTP serves plain HTTP on the connection.
func (s *AutoDetectServer) serveHTTP(ctx context.Context, conn net.Conn, br *bufio.Reader) {
	bw := serverbase.AcquireBufferedWriter(conn)
	defer serverbase.ReleaseBufferedWriter(bw)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(s.timeout))
		req, err := nethttp.ReadRequest(br)
		if err != nil {
			break
		}
		_ = conn.SetReadDeadline(time.Time{})
		keepAlive, _ := s.httpHdl.Proxy(ctx, conn, br, req, bw)
		if !keepAlive {
			break
		}
	}
	_ = conn.Close()
}

// bufferedConn wraps a net.Conn with a bufio.Reader so that peeked bytes are
// not lost.
type bufferedConn struct {
	net.Conn
	br *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.br.Read(p) }

// isClosedErr reports whether the error indicates a closed listener.
func isClosedErr(err error) bool {
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Err != nil && opErr.Err.Error() == "use of closed network connection" {
			return true
		}
	}
	return false
}
