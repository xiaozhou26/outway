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
	"net/netip"
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
	listener  net.Listener
	socksAcc  socks.Socks5Acceptor
	httpHdl   http.Handler
	httpsHdl  http.Handler
	tlsConfig *tls.Config
	timeout   time.Duration
	gate      *serverbase.ConnectionGate
	tlsGate   *serverbase.ConnectionGate
	conns     *serverbase.ConnectionSet
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	launchMu  sync.Mutex
	closeOnce sync.Once
	closeErr  error
}

// NewAutoDetectServer binds a TCP listener and prepares the three handlers
// (SOCKS5, HTTP, HTTPS) for protocol auto-detection.
func NewAutoDetectServer(ctx Context, certPath, keyPath string) (*AutoDetectServer, error) {
	network := "tcp4"
	if ctx.Bind.Addr().Is6() {
		network = "tcp6"
	}
	ln, err := net.Listen(network, ctx.Bind.String())
	if err != nil {
		if network == "tcp6" {
			if ln2, err2 := net.Listen("tcp", ctx.Bind.String()); err2 == nil {
				ln = ln2
				err = nil
			}
		}
		if err != nil {
			return nil, err
		}
	}

	// Build the TLS config for HTTPS connections.
	var tlsCfg *tls.Config
	if certPath != "" && keyPath != "" {
		cfg, err := http.NewTLSConfigFromFiles(certPath, keyPath)
		if err != nil {
			_ = ln.Close()
			return nil, err
		}
		tlsCfg = cfg.Config()
	} else {
		cfg, err := http.NewSelfSignedTLSConfig()
		if err != nil {
			_ = ln.Close()
			return nil, err
		}
		tlsCfg = cfg.Config()
	}

	handler := http.NewHandler(ctx)
	lifetime, cancel := context.WithCancel(context.Background())
	return &AutoDetectServer{
		listener:  ln,
		socksAcc:  socks.NewAcceptor(ctx, lifetime),
		httpHdl:   handler,
		httpsHdl:  handler,
		tlsConfig: tlsCfg,
		timeout:   time.Duration(ctx.ConnectTimeout) * time.Second,
		gate:      serverbase.NewConnectionGate(ctx.Concurrent),
		tlsGate:   serverbase.NewTLSHandshakeGate(ctx.Concurrent),
		conns:     serverbase.NewConnectionSet(),
		ctx:       lifetime,
		cancel:    cancel,
	}, nil
}

// Start runs the accept loop until the server is shut down.
func (s *AutoDetectServer) Start() error {
	slog.Info(fmt.Sprintf("Http(s)/Socks5 proxy server listening on %s", s.listener.Addr()))

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if isClosedErr(err) {
				return nil
			}
			slog.Debug("Failed to accept connection", "error", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		s.launchMu.Lock()
		if !s.conns.Add(conn) {
			s.launchMu.Unlock()
			_ = conn.Close()
			continue
		}
		if !s.gate.AcquireUntil(s.conns.Done()) {
			s.conns.Remove(conn)
			s.launchMu.Unlock()
			_ = conn.Close()
			return nil
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.gate.Release()
			defer s.conns.Remove(conn)
			s.accept(conn)
		}()
		s.launchMu.Unlock()
	}
}

// Close stops the listener.
func (s *AutoDetectServer) Close() error {
	s.closeOnce.Do(func() {
		s.cancel()
		connectionErr := s.conns.CloseAll()
		listenerErr := s.listener.Close()
		if errors.Is(listenerErr, net.ErrClosed) {
			listenerErr = nil
		}
		s.launchMu.Lock()
		s.launchMu.Unlock()
		s.httpHdl.CloseIdleConnections()
		var waitErr error
		if !serverbase.WaitGroupTimeout(&s.wg, serverbase.DefaultShutdownWait) {
			waitErr = errors.New("auto-detect handlers did not stop before shutdown timeout")
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

	var peer netip.AddrPort
	if ra, rerr := netip.ParseAddrPort(conn.RemoteAddr().String()); rerr == nil {
		peer = ra
	}

	switch {
	case first[0] == 0x05:
		// SOCKS5: pass the connection (with buffered reader) to the SOCKS5
		// acceptor.
		s.socksAcc.Accept(&bufferedConn{Conn: conn, br: br}, peer)
	case first[0] < 0x41:
		// HTTPS: wrap with TLS and serve HTTP.
		s.serveHTTPS(&bufferedConn{Conn: conn, br: br})
	default:
		// HTTP: serve plain HTTP.
		s.serveHTTP(conn, br)
	}
}

// serveHTTPS wraps the connection with TLS and serves HTTP over it.
func (s *AutoDetectServer) serveHTTPS(conn net.Conn) {
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
		keepAlive, _ := s.httpsHdl.Proxy(s.ctx, tlsConn, br, req, bw)
		if !keepAlive {
			break
		}
	}
	_ = tlsConn.Close()
}

// serveHTTP serves plain HTTP on the connection.
func (s *AutoDetectServer) serveHTTP(conn net.Conn, br *bufio.Reader) {
	bw := serverbase.AcquireBufferedWriter(conn)
	defer serverbase.ReleaseBufferedWriter(bw)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(s.timeout))
		req, err := nethttp.ReadRequest(br)
		if err != nil {
			break
		}
		_ = conn.SetReadDeadline(time.Time{})
		keepAlive, _ := s.httpHdl.Proxy(s.ctx, conn, br, req, bw)
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
