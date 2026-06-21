package server

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	nethttp "net/http"
	"net"
	"net/netip"
	"time"

	"github.com/xiaozhou26/outway/internal/server/http"
	"github.com/xiaozhou26/outway/internal/server/socks"
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
			return nil, err
		}
		tlsCfg = cfg.Config()
	} else {
		cfg, err := http.NewSelfSignedTLSConfig()
		if err != nil {
			return nil, err
		}
		tlsCfg = cfg.Config()
	}

	return &AutoDetectServer{
		listener:  ln,
		socksAcc:  socks.NewAcceptor(ctx),
		httpHdl:   http.NewHandler(ctx),
		httpsHdl:  http.NewHandler(ctx),
		tlsConfig: tlsCfg,
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
			slog.Debug(fmt.Sprintf("Failed to accept connection: %v", err))
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go s.accept(conn)
	}
}

// Close stops the listener.
func (s *AutoDetectServer) Close() error { return s.listener.Close() }

// accept peeks at the first byte of the connection to determine the protocol
// and dispatches to the appropriate handler.
func (s *AutoDetectServer) accept(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}

	// Peek the first byte to determine the protocol:
	//   0x05         -> SOCKS5
	//   0x00..=0x40  -> HTTPS (TLS starts with a binary byte < 0x41)
	//   >= 0x41      -> HTTP (ASCII method: GET, POST, CONNECT, etc.)
	br := bufio.NewReader(conn)
	first, err := br.Peek(1)
	if err != nil {
		slog.Debug(fmt.Sprintf("[AUTO] peek failed: %v", err))
		_ = conn.Close()
		return
	}

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
		s.serveHTTP(&bufferedConn{Conn: conn, br: br})
	}
}

// serveHTTPS wraps the connection with TLS and serves HTTP over it.
func (s *AutoDetectServer) serveHTTPS(conn net.Conn) {
	tlsConn := tls.Server(conn, s.tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		slog.Debug(fmt.Sprintf("[AUTO] TLS handshake failed: %v", err))
		_ = conn.Close()
		return
	}
	br := bufio.NewReader(tlsConn)
	bw := bufio.NewWriter(tlsConn)
	for {
		req, err := nethttp.ReadRequest(br)
		if err != nil {
			break
		}
		keepAlive, _ := s.httpsHdl.Proxy(tlsConn, br, req, bw)
		if !keepAlive {
			break
		}
	}
	_ = tlsConn.Close()
}

// serveHTTP serves plain HTTP on the connection.
func (s *AutoDetectServer) serveHTTP(conn net.Conn) {
	br := bufio.NewReader(conn)
	bw := bufio.NewWriter(conn)
	for {
		req, err := nethttp.ReadRequest(br)
		if err != nil {
			break
		}
		keepAlive, _ := s.httpHdl.Proxy(conn, br, req, bw)
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
	if err == nil {
		return false
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Err != nil && opErr.Err.Error() == "use of closed network connection" {
			return true
		}
	}
	return false
}
