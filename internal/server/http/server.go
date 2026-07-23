package http

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xiaozhou26/outway/internal/connect"
	"github.com/xiaozhou26/outway/internal/ext"
	"github.com/xiaozhou26/outway/internal/serverbase"
)

// HttpServer listens for HTTP/HTTPS proxy connections and dispatches them to
// the handler.
type HttpServer struct {
	listener       net.Listener
	extraListeners []net.Listener
	handler        Handler
	tlsConfig      *tls.Config
	timeout        time.Duration
	gate           *serverbase.ConnectionGate
	tlsGate        *serverbase.ConnectionGate
	conns          *serverbase.ConnectionSet
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	launchMu       sync.Mutex
	closeOnce      sync.Once
	closeErr       error
}

// Handler holds the authenticator and outbound connector for HTTP proxying.
type Handler struct {
	auth       Authenticator
	connector  *connect.Connector
	transports *transportPool
}

const maxTransportEntries = 128

type transportPool struct {
	mu               sync.Mutex
	connector        *connect.Connector
	entries          map[ext.Extension]*transportEntry
	clock            uint64
	defaultTransport *http.Transport
}

type transportEntry struct {
	transport *http.Transport
	lastUsed  uint64
}

// NewHandler builds a Handler from a server Context.
func NewHandler(ctx serverbase.Context) Handler {
	var auth Authenticator
	if ctx.Auth.HasAuth() {
		auth = PasswordAuth(ctx.Auth.Username, ctx.Auth.Password)
	} else {
		auth = NoAuth()
	}
	return Handler{
		auth:       auth,
		connector:  ctx.Connector,
		transports: newTransportPool(ctx.Connector),
	}
}

// NewServer binds one or more TCP listeners (SO_REUSEPORT shards when enabled)
// and returns an HTTP server.
func NewServer(ctx serverbase.Context) (*HttpServer, error) {
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
	return &HttpServer{
		listener:       listeners[0],
		extraListeners: listeners[1:],
		handler:        NewHandler(ctx),
		timeout:        time.Duration(ctx.ConnectTimeout) * time.Second,
		gate:           serverbase.NewConnectionGate(ctx.Concurrent),
		tlsGate:        serverbase.NewTLSHandshakeGate(ctx.Concurrent),
		conns:          serverbase.NewConnectionSet(),
		ctx:            lifetime,
		cancel:         cancel,
	}, nil
}

// WithHTTPS enables TLS using the provided certificate/key paths, or generates
// a self-signed certificate when both paths are empty.
func (s *HttpServer) WithHTTPS(certPath, keyPath string) (*HttpServer, error) {
	var cfg *TLSConfig
	var err error
	if certPath != "" && keyPath != "" {
		cfg, err = NewTLSConfigFromFiles(certPath, keyPath)
	} else {
		cfg, err = NewSelfSignedTLSConfig()
	}
	if err != nil {
		return nil, err
	}
	s.tlsConfig = cfg.Config()
	return s, nil
}

// Handler returns the server's handler (used by the auto-detect server).
func (s *HttpServer) Handler() Handler { return s.handler }

// TLSConfig returns the server's TLS config (used by the auto-detect server).
func (s *HttpServer) TLSConfig() *tls.Config { return s.tlsConfig }

// Start runs the accept loop until the server is shut down.
func (s *HttpServer) Start() error {
	scheme := "HTTP"
	if s.tlsConfig != nil {
		scheme = "HTTPS"
	}
	slog.Info(fmt.Sprintf("%s proxy server listening on %s", scheme, s.listener.Addr()))

	for _, ln := range s.extraListeners {
		listener := ln
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			_ = s.acceptLoop(listener)
		}()
	}
	return s.acceptLoop(s.listener)
}

func (s *HttpServer) acceptLoop(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if isClosed(err) {
				return nil
			}
			slog.Debug("Failed to accept connection", "error", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		// Acquire a connection slot before taking launchMu: a saturated gate must
		// apply backpressure to this accept loop without holding the mutex, which
		// would otherwise serialize every SO_REUSEPORT accept shard (and Close's
		// launch barrier) behind a single blocked waiter.
		if !s.gate.AcquireUntil(s.conns.Done()) {
			_ = conn.Close()
			return nil
		}
		s.launchMu.Lock()
		if !s.conns.Add(conn) {
			s.launchMu.Unlock()
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
		s.launchMu.Unlock()
	}
}

// Close stops the listeners.
func (s *HttpServer) Close() error {
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
		s.launchMu.Lock()
		s.launchMu.Unlock()
		s.handler.CloseIdleConnections()
		var waitErr error
		if !serverbase.WaitGroupTimeout(&s.wg, serverbase.DefaultShutdownWait) {
			waitErr = errors.New("HTTP handlers did not stop before shutdown timeout")
		}
		s.closeErr = errors.Join(connectionErr, listenerErr, waitErr)
	})
	return s.closeErr
}

// accept handles a single accepted connection, optionally performing a TLS
// handshake, then serving HTTP requests on it.
func (s *HttpServer) accept(conn net.Conn) {
	serverbase.TuneTCPConnection(conn)

	var stream net.Conn = conn
	if s.tlsConfig != nil {
		_ = conn.SetDeadline(time.Now().Add(s.timeout))
		tlsConn := tls.Server(conn, s.tlsConfig)
		if !s.tlsGate.AcquireUntil(s.conns.Done()) {
			_ = conn.Close()
			return
		}
		err := tlsConn.Handshake()
		s.tlsGate.Release()
		if err != nil {
			slog.Debug("HTTP TLS handshake failed", "error", err)
			_ = conn.Close()
			return
		}
		_ = conn.SetDeadline(time.Time{})
		stream = tlsConn
	}

	br := serverbase.AcquireBufferedReader(stream)
	defer serverbase.ReleaseBufferedReader(br)
	bw := serverbase.AcquireBufferedWriter(stream)
	defer serverbase.ReleaseBufferedWriter(bw)

	for {
		_ = stream.SetReadDeadline(time.Now().Add(s.timeout))
		req, err := http.ReadRequest(br)
		if err != nil {
			if err != io.EOF {
				slog.Debug("HTTP request read failed", "error", err)
			}
			break
		}
		_ = stream.SetReadDeadline(time.Time{})
		keepAlive, err := s.handler.Proxy(s.ctx, stream, br, req, bw)
		if err != nil {
			slog.Debug("HTTP connection failed", "error", err)
			break
		}
		if !keepAlive {
			break
		}
	}
	_ = stream.Close()
}

// Proxy handles a single HTTP request. It returns true if the connection can
// be kept alive for further requests.
func (h Handler) Proxy(ctx context.Context, conn net.Conn, br *bufio.Reader, req *http.Request, bw *bufio.Writer) (bool, error) {
	// Authenticate the client.
	extension, err := h.auth.Authenticate(req.Header)
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case IsProxyAuthRequired(err):
			status = http.StatusProxyAuthRequired
		case IsForbidden(err):
			status = http.StatusForbidden
		}
		writeResponse(bw, status, "")
		return false, nil
	}

	if req.Method == http.MethodConnect {
		return h.handleConnect(ctx, conn, br, req, extension, bw)
	}
	return h.forwardRequest(ctx, req, extension, bw)
}

// handleConnect implements the HTTP CONNECT method: establish a TCP tunnel
// between the client and the target.
func (h Handler) handleConnect(ctx context.Context, client net.Conn, br *bufio.Reader, req *http.Request, extension ext.Extension, bw *bufio.Writer) (bool, error) {
	target := req.URL.Host
	if target == "" {
		target = req.Host
	}
	if target == "" {
		writeResponse(bw, http.StatusBadRequest, "CONNECT must be to a socket address")
		return false, nil
	}

	host, port, err := splitHostPort(target)
	if err != nil {
		writeResponse(bw, http.StatusBadRequest, "CONNECT must be to a socket address")
		return false, nil
	}

	slog.Debug("HTTP tunnel forwarding", "client", client.RemoteAddr(), "target", target)

	connector := h.connector.TCP(extension)
	outbound, err := connector.Connect(ctx, connect.FromHost(host, port))
	if err != nil {
		writeResponse(bw, http.StatusBadGateway, "")
		return false, err
	}

	// Send 200 OK and flush.
	writeResponse(bw, http.StatusOK, "")
	_ = bw.Flush()

	// If the bufio.Reader has buffered bytes from the client, forward them to
	// the outbound before entering the bidirectional copy.
	if n := br.Buffered(); n > 0 {
		if _, err := io.CopyN(outbound, br, int64(n)); err != nil {
			_ = outbound.Close()
			return false, err
		}
	}

	// Tunnel raw bytes between client and outbound.
	fromClient, fromServer, _ := serverbase.CopyBidirectionalContext(ctx, client, outbound, serverbase.DefaultHalfCloseGrace)
	slog.Debug("HTTP tunnel closed", "sent", fromClient, "received", fromServer)
	_ = outbound.CloseWrite()
	_ = outbound.Close()
	_ = serverbase.CloseWrite(client)
	return false, nil
}

// forwardRequest forwards a non-CONNECT HTTP request to the target server and
// writes the response back to the client.
func (h Handler) forwardRequest(ctx context.Context, req *http.Request, extension ext.Extension, bw *bufio.Writer) (bool, error) {
	// The request URL for a proxy request is absolute; for a direct request it
	// is relative. We need to build the outbound URL.
	outURL := *req.URL
	if !outURL.IsAbs() {
		if req.Host != "" {
			outURL.Host = req.Host
		}
		outURL.Scheme = "http"
	}

	// Strip hop-by-hop headers.
	outReq := req.Clone(ctx)
	outReq.URL = &outURL
	outReq.RequestURI = ""
	removeHopHeaders(outReq.Header)

	resp, err := h.transports.Get(extension).RoundTrip(outReq)
	if err != nil {
		writeResponse(bw, http.StatusBadGateway, "")
		return false, err
	}
	defer resp.Body.Close()
	removeHopHeaders(resp.Header)
	if err := resp.Write(bw); err != nil {
		return false, err
	}
	_ = bw.Flush()
	keepAlive := req.ProtoAtLeast(1, 1) && resp.ProtoAtLeast(1, 1) && !req.Close && !resp.Close
	return keepAlive, nil
}

func newTransportPool(connector *connect.Connector) *transportPool {
	pool := &transportPool{
		connector: connector,
		entries:   make(map[ext.Extension]*transportEntry),
	}
	pool.defaultTransport = pool.newTransport(ext.None)
	return pool
}

func (p *transportPool) Get(extension ext.Extension) *http.Transport {
	if extension.Type == ext.ExtNone {
		return p.defaultTransport
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clock++
	if entry := p.entries[extension]; entry != nil {
		entry.lastUsed = p.clock
		return entry.transport
	}

	if len(p.entries) >= maxTransportEntries {
		var oldestExtension ext.Extension
		var oldestEntry *transportEntry
		for candidate, entry := range p.entries {
			if oldestEntry == nil || entry.lastUsed < oldestEntry.lastUsed {
				oldestExtension = candidate
				oldestEntry = entry
			}
		}
		if oldestEntry != nil {
			delete(p.entries, oldestExtension)
			oldestEntry.transport.CloseIdleConnections()
		}
	}

	transport := p.newTransport(extension)
	p.entries[extension] = &transportEntry{transport: transport, lastUsed: p.clock}
	return transport
}

func (p *transportPool) newTransport(extension ext.Extension) *http.Transport {
	maxIdle := 16
	maxIdlePerHost := 8
	if extension.Type == ext.ExtNone {
		maxIdle = 1024
		maxIdlePerHost = 128
	}
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           p.dialContext(extension),
		ForceAttemptHTTP2:     false,
		DisableCompression:    true,
		MaxIdleConns:          maxIdle,
		MaxIdleConnsPerHost:   maxIdlePerHost,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   p.connector.ConnectTimeout,
		ResponseHeaderTimeout: p.connector.ConnectTimeout,
		ExpectContinueTimeout: time.Second,
	}
}

func (p *transportPool) dialContext(extension ext.Extension) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, _, address string) (net.Conn, error) {
		host, portString, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		port, err := strconv.ParseUint(portString, 10, 16)
		if err != nil || port == 0 {
			return nil, fmt.Errorf("invalid target port %q", portString)
		}
		return p.connector.TCP(extension).Connect(ctx, connect.FromHost(host, uint16(port)))
	}
}

func (p *transportPool) CloseIdleConnections() {
	p.mu.Lock()
	transports := make([]*http.Transport, 0, len(p.entries)+1)
	transports = append(transports, p.defaultTransport)
	for _, entry := range p.entries {
		transports = append(transports, entry.transport)
	}
	p.mu.Unlock()
	for _, transport := range transports {
		transport.CloseIdleConnections()
	}
}

func (h Handler) CloseIdleConnections() {
	if h.transports != nil {
		h.transports.CloseIdleConnections()
	}
}

// hop-by-hop headers (RFC 7230 搂6.1).
var hopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func removeHopHeaders(h http.Header) {
	// Connection may name additional hop-by-hop fields. Capture those tokens
	// before deleting the Connection header itself.
	var connectionTokens []string
	if conn := h.Get("Connection"); conn != "" {
		connectionTokens = strings.Split(conn, ",")
	}
	for _, k := range hopHeaders {
		h.Del(k)
	}
	for _, tok := range connectionTokens {
		h.Del(strings.TrimSpace(tok))
	}
}

// writeResponse writes a simple HTTP response to the buffered writer.
func writeResponse(bw *bufio.Writer, status int, body string) {
	resp := &http.Response{
		StatusCode: status,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{},
		Body:       http.NoBody,
	}
	if status == http.StatusProxyAuthRequired {
		resp.Header.Set("Proxy-Authenticate", `Basic realm="Proxy"`)
	}
	if body != "" {
		resp.Body = io.NopCloser(strings.NewReader(body))
		resp.ContentLength = int64(len(body))
		resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	}
	_ = resp.Write(bw)
	_ = bw.Flush()
}

// splitHostPort splits a host:port string, returning the host and port number.
func splitHostPort(target string) (string, uint16, error) {
	if !strings.Contains(target, ":") {
		return "", 0, errors.New("missing port")
	}
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return "", 0, err
	}
	port, err := parsePort(portStr)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

func parsePort(s string) (uint16, error) {
	p, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, err
	}
	return uint16(p), nil
}

// isClosed reports whether the error indicates a closed listener.
func isClosed(err error) bool {
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
