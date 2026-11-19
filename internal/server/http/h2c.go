package http

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"

	"github.com/xiaozhou26/outway/internal/config"
	"github.com/xiaozhou26/outway/internal/connect"
	"github.com/xiaozhou26/outway/internal/serverbase"
)

// h2PrefaceMethod is the method token that opens the HTTP/2 client connection
// preface ("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"). No HTTP/1 proxy request uses it,
// so three peeked bytes are enough to route a connection to the HTTP/2 server;
// the HTTP/2 server then validates the full preface.
const h2PrefaceMethod = "PRI"

const (
	// h2cPingInterval is how long a client connection may stay silent before
	// outway sends a PING, so dead peers holding idle multiplexed connections
	// are detected without waiting for TCP keepalive.
	h2cPingInterval = 30 * time.Second
	h2cPingTimeout  = 15 * time.Second
	// h2cMaxFrameSize is the SETTINGS_MAX_FRAME_SIZE outway advertises: the
	// largest DATA frame a client may send. It is the RFC 9113 default, not
	// x/net's 1 MiB. Go's client writes each DATA frame while holding its
	// connection write lock, and that write blocks while the socket is full.
	// So the HEADERS of a new tunnel waits behind one frame from every busy
	// upload stream on the connection. With 1 MiB frames and 64 uploading
	// streams that wait reached seconds; 16 KiB frames keep it short at the
	// same throughput.
	h2cMaxFrameSize = 16 << 10
	// h2cCopyBufferSize matches the userspace TCP copy buffer.
	h2cCopyBufferSize = 32 * 1024
)

var h2cBufferPool = sync.Pool{New: func() any { return new([h2cCopyBufferSize]byte) }}

// h2cServer serves HTTP/2 cleartext (prior knowledge) connections whose streams
// are CONNECT tunnels (RFC 9113 §8.5). One client connection carries many
// tunnels, so opening a tunnel costs no TCP handshake and the client may send
// its first tunnel bytes (a TLS ClientHello) right behind the HEADERS frame.
type h2cServer struct {
	server *http2.Server
	base   *http.Server
}

func newH2CServer(cfg config.H2CConfig) *h2cServer {
	if !cfg.Enabled {
		return nil
	}
	return &h2cServer{
		server: &http2.Server{
			MaxConcurrentStreams:         cfg.MaxStreams,
			MaxReadFrameSize:             h2cMaxFrameSize,
			MaxUploadBufferPerConnection: cfg.ConnWindow,
			MaxUploadBufferPerStream:     cfg.StreamWindow,
			ReadIdleTimeout:              h2cPingInterval,
			PingTimeout:                  h2cPingTimeout,
		},
		base: &http.Server{ErrorLog: slog.NewLogLogger(slog.Default().Handler(), slog.LevelDebug)},
	}
}

// H2CEnabled reports whether the handler accepts HTTP/2 cleartext tunnels.
func (h Handler) H2CEnabled() bool { return h.h2c != nil }

// IsH2CPreface reports whether the buffered connection starts with the HTTP/2
// client preface. It peeks at most three bytes, which every HTTP/1 request
// line exceeds, so it never waits on a well-formed HTTP/1 client.
func IsH2CPreface(br *bufio.Reader) bool {
	b, err := br.Peek(len(h2PrefaceMethod))
	return err == nil && string(b) == h2PrefaceMethod
}

// ServeH2C serves an HTTP/2 cleartext connection whose preface is buffered in
// br. It returns when the connection ends. ctx is the connection's lifetime:
// cancelling it tears down every tunnel on the connection.
func (h Handler) ServeH2C(ctx context.Context, conn net.Conn, br *bufio.Reader) {
	h.h2c.server.ServeConn(&prefacedConn{Conn: conn, br: br}, &http2.ServeConnOpts{
		Context:    ctx,
		BaseConfig: h.h2c.base,
		Handler:    h2cTunnelHandler{h},
	})
}

// prefacedConn reads through the bufio.Reader that peeked the preface, so the
// HTTP/2 server sees the bytes the protocol detection consumed.
type prefacedConn struct {
	net.Conn
	br *bufio.Reader
}

func (c *prefacedConn) Read(p []byte) (int, error) { return c.br.Read(p) }

// NetConn returns the wrapped connection.
func (c *prefacedConn) NetConn() net.Conn { return c.Conn }

type h2cTunnelHandler struct{ h Handler }

func (t h2cTunnelHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	extension, err := t.h.auth.Authenticate(r.Header)
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case IsProxyAuthRequired(err):
			status = http.StatusProxyAuthRequired
			w.Header().Set("Proxy-Authenticate", `Basic realm="Proxy"`)
		case IsForbidden(err):
			status = http.StatusForbidden
		}
		w.WriteHeader(status)
		return
	}
	if r.Method != http.MethodConnect {
		w.Header().Set("Allow", http.MethodConnect)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	host, port, err := splitHostPort(r.Host)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if serverbase.DebugEnabled() {
		slog.Debug("h2c tunnel forwarding", "target", r.Host)
	}

	// The client may already have sent tunnel data; it waits in the stream's
	// receive buffer (bounded by the stream window) until the copy below
	// reads it, so it is forwarded in order right after the dial.
	outbound, err := t.h.connector.TCP(extension).Connect(r.Context(), connect.FromHost(host, port))
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		slog.Debug("h2c tunnel dial failed", "target", r.Host, "error", err)
		return
	}
	defer func() { _ = outbound.Close() }()

	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	if err := rc.Flush(); err != nil {
		return
	}
	up, down := tunnelH2C(r.Context(), r.Body, w, rc, outbound, serverbase.DefaultHalfCloseGrace)
	if serverbase.DebugEnabled() {
		slog.Debug("h2c tunnel closed", "target", r.Host, "sent", up, "received", down)
	}
}

// tunnelH2C relays one CONNECT stream. Client DATA is written to the target as
// it is read; target bytes are written and flushed as DATA frames immediately,
// with no batching. When the client ends its stream the target's write side
// is half-closed and the reverse direction may continue for halfCloseGrace.
// When the target finishes, the function returns so the handler ends the
// response stream (END_STREAM) at once.
func tunnelH2C(ctx context.Context, body io.ReadCloser, w io.Writer, rc *http.ResponseController, outbound *net.TCPConn, halfCloseGrace time.Duration) (up, down int64) {
	interrupt := func() { _ = outbound.SetDeadline(time.Now()) }
	stop := context.AfterFunc(ctx, interrupt)
	defer stop()

	var grace atomic.Pointer[time.Timer]
	upDone := make(chan struct{})
	go func() {
		defer close(upDone)
		buf := h2cBufferPool.Get().(*[h2cCopyBufferSize]byte)
		defer h2cBufferPool.Put(buf)
		up, _ = io.CopyBuffer(struct{ io.Writer }{outbound}, struct{ io.Reader }{body}, buf[:])
		_ = outbound.CloseWrite()
		if halfCloseGrace > 0 {
			grace.Store(time.AfterFunc(halfCloseGrace, interrupt))
		}
	}()

	buf := h2cBufferPool.Get().(*[h2cCopyBufferSize]byte)
	for {
		n, err := outbound.Read(buf[:])
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				break
			}
			if rc.Flush() != nil {
				break
			}
			down += int64(n)
		}
		if err != nil {
			break
		}
	}
	h2cBufferPool.Put(buf)

	// Unblock the upstream copy (a body read or an outbound write) and wait
	// for it, so nothing touches the stream after the handler returns.
	_ = body.Close()
	_ = outbound.SetDeadline(time.Now())
	<-upDone
	if t := grace.Load(); t != nil {
		t.Stop()
	}
	return up, down
}
