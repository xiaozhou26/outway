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
	"strings"
	"time"

	"github.com/xiaozhou26/outway/internal/connect"
	"github.com/xiaozhou26/outway/internal/ext"
	"github.com/xiaozhou26/outway/internal/serverbase"
)

// HttpServer listens for HTTP/HTTPS proxy connections and dispatches them to
// the handler.
type HttpServer struct {
	listener  net.Listener
	handler   Handler
	tlsConfig *tls.Config
	timeout   time.Duration
}

// Handler holds the authenticator and outbound connector for HTTP proxying.
type Handler struct {
	auth      Authenticator
	connector *connect.Connector
}

// NewHandler builds a Handler from a server Context.
func NewHandler(ctx serverbase.Context) Handler {
	var auth Authenticator
	if ctx.Auth.HasAuth() {
		auth = PasswordAuth(ctx.Auth.Username, ctx.Auth.Password)
	} else {
		auth = NoAuth()
	}
	return Handler{auth: auth, connector: ctx.Connector}
}

// NewServer binds a TCP listener and returns an HTTP server.
func NewServer(ctx serverbase.Context) (*HttpServer, error) {
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
	return &HttpServer{
		listener: ln,
		handler:  NewHandler(ctx),
		timeout:  time.Duration(ctx.ConnectTimeout) * time.Second,
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

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if isClosed(err) {
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
func (s *HttpServer) Close() error { return s.listener.Close() }

// accept handles a single accepted connection, optionally performing a TLS
// handshake, then serving HTTP requests on it.
func (s *HttpServer) accept(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}

	var stream net.Conn = conn
	if s.tlsConfig != nil {
		tlsConn := tls.Server(conn, s.tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			slog.Debug(fmt.Sprintf("[HTTP] TLS handshake failed: %v", err))
			_ = conn.Close()
			return
		}
		stream = tlsConn
	}

	br := bufio.NewReader(stream)
	bw := bufio.NewWriter(stream)

	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			if err != io.EOF {
				slog.Debug(fmt.Sprintf("[HTTP] read request: %v", err))
			}
			break
		}
		keepAlive, err := s.handler.Proxy(stream, br, req, bw)
		if err != nil {
			slog.Debug(fmt.Sprintf("[HTTP] serve connection: %v", err))
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
func (h Handler) Proxy(conn net.Conn, br *bufio.Reader, req *http.Request, bw *bufio.Writer) (bool, error) {
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
		return h.handleConnect(conn, br, req, extension, bw)
	}
	return h.forwardRequest(req, extension, bw)
}

// handleConnect implements the HTTP CONNECT method: establish a TCP tunnel
// between the client and the target.
func (h Handler) handleConnect(client net.Conn, br *bufio.Reader, req *http.Request, extension ext.Extension, bw *bufio.Writer) (bool, error) {
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

	slog.Info(fmt.Sprintf("[HTTP] %s -> %s forwarding connection", client.RemoteAddr(), target))

	connector := h.connector.TCP(extension)
	outbound, err := connector.Connect(context.Background(), connect.FromHost(host, port))
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
		buf := make([]byte, n)
		_, _ = io.ReadFull(br, buf)
		_, _ = outbound.Write(buf)
	}

	// Tunnel raw bytes between client and outbound.
	fromClient, fromServer, _ := serverbase.CopyBidirectional(client, outbound)
	slog.Info(fmt.Sprintf("[HTTP] client wrote %d bytes and received %d bytes", fromClient, fromServer))
	_ = outbound.CloseWrite()
	_ = outbound.Close()
	_ = serverbase.CloseWrite(client)
	return false, nil
}

// forwardRequest forwards a non-CONNECT HTTP request to the target server and
// writes the response back to the client.
func (h Handler) forwardRequest(req *http.Request, extension ext.Extension, bw *bufio.Writer) (bool, error) {
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
	outReq := req.Clone(context.Background())
	outReq.URL = &outURL
	outReq.RequestURI = ""
	removeHopHeaders(outReq.Header)

	// Connect to the target.
	host := outURL.Hostname()
	port := outURL.Port()
	if port == "" {
		port = "80"
	}
	portNum, err := parsePort(port)
	if err != nil {
		portNum = 80
	}

	connector := h.connector.TCP(extension)
	outbound, err := connector.Connect(context.Background(), connect.FromHost(host, portNum))
	if err != nil {
		writeResponse(bw, http.StatusBadGateway, "")
		return false, err
	}
	defer outbound.Close()

	// Write the request to the outbound connection.
	if err := outReq.Write(outbound); err != nil {
		return false, err
	}
	if outReq.Body != nil {
		_, _ = io.Copy(outbound, outReq.Body)
		_ = outReq.Body.Close()
	}
	_ = outbound.CloseWrite()

	// Read the response from the outbound and write it back to the client.
	resp, err := http.ReadResponse(bufio.NewReader(outbound), outReq)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	removeHopHeaders(resp.Header)
	if err := resp.Write(bw); err != nil {
		return false, err
	}
	if _, err := io.Copy(bw, resp.Body); err != nil {
		return false, err
	}
	_ = bw.Flush()
	keepAlive := req.ProtoAtLeast(1, 1) && resp.ProtoAtLeast(1, 1) && !req.Close && !resp.Close
	return keepAlive, nil
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
	for _, k := range hopHeaders {
		h.Del(k)
	}
	if conn := h.Get("Connection"); conn != "" {
		for _, tok := range strings.Split(conn, ",") {
			h.Del(strings.TrimSpace(tok))
		}
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
		resp.Body = stringBody(body)
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
	var p int
	if _, err := fmt.Sscanf(s, "%d", &p); err != nil {
		return 0, err
	}
	if p < 0 || p > 65535 {
		return 0, errors.New("invalid port")
	}
	return uint16(p), nil
}

// stringBody wraps a string as an io.ReadCloser for use as a response body.
type stringBody string

func (s stringBody) Read(p []byte) (int, error) {
	if len(s) == 0 {
		return 0, io.EOF
	}
	n := copy(p, []byte(s))
	return n, io.EOF
}
func (s stringBody) Close() error { return nil }

// isClosed reports whether the error indicates a closed listener.
func isClosed(err error) bool {
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
