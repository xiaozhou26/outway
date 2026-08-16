package masque

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/xiaozhou26/outway/internal/serverbase"
)

// contextIDZero is the RFC 9298 context ID (a QUIC variable-length integer 0)
// prefixed to every tunneled datagram in both directions. This proxy only
// forwards UDP payloads, so the context ID is always zero.
var contextIDZero = quicvarint.Append([]byte{}, 0)

// tunnel relays datagrams between one CONNECT-UDP request stream and one
// connected outbound UDP socket. It replaces masque-go's
// ProxyConnectedSocket: sizing comes from the UDP configuration instead of a
// hardcoded MTU, response buffers are pooled across tunnels, and diagnostics
// go through slog behind the debug gate instead of one log.Printf per error
// and per skipped capsule.
type tunnel struct {
	server       *Server
	stream       *http3.Stream
	conn         *net.UDPConn
	lastActivity atomic.Int64
}

func (t *tunnel) idleTimeout() time.Duration {
	seconds := t.server.ctx.UDP.AssociationIdleTimeoutSecs
	if seconds == 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

func (t *tunnel) touch() {
	t.lastActivity.Store(time.Now().UnixNano())
}

func (t *tunnel) isIdle(now time.Time, timeout time.Duration) bool {
	last := time.Unix(0, t.lastActivity.Load())
	return now.Sub(last) >= timeout
}

// maxPayload is the largest tunneled datagram accepted in either direction.
func (t *tunnel) maxPayload() int {
	return t.server.ctx.UDP.MaxPacketSize
}

// serveTunnel takes over the request stream and relays datagrams until either
// side closes. It blocks until both directions have drained.
func (s *Server) serveTunnel(w http.ResponseWriter, conn *net.UDPConn) {
	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		_ = conn.Close()
		http.Error(w, "CONNECT-UDP requires HTTP/3 stream takeover", http.StatusInternalServerError)
		return
	}
	stream := streamer.HTTPStream()

	t := &tunnel{server: s, stream: stream, conn: conn}
	t.touch()
	if !s.tunnels.Add(t) {
		_ = conn.Close()
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	defer s.tunnels.Remove(t)

	w.Header().Set(http3.CapsuleProtocolHeader, "?1")
	w.WriteHeader(http.StatusOK)

	var pumps sync.WaitGroup
	pumps.Add(2)
	go func() { defer pumps.Done(); t.pumpToTarget() }()
	go func() { defer pumps.Done(); t.pumpToClient() }()

	idleDone := make(chan struct{})
	var idleWG sync.WaitGroup
	if timeout := t.idleTimeout(); timeout > 0 {
		idleWG.Add(1)
		go func() {
			defer idleWG.Done()
			ticker := time.NewTicker(min(timeout/2, time.Second))
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					if t.isIdle(time.Now(), timeout) {
						t.teardown()
						return
					}
				case <-idleDone:
					return
				}
			}
		}()
	}

	// The request stream itself only carries capsules; reading it to EOF is
	// how the server learns that the client closed the tunnel.
	t.discardCapsules()

	t.teardown()
	pumps.Wait()
	close(idleDone)
	idleWG.Wait()
}

// pumpToTarget forwards QUIC datagrams from the client to the outbound socket.
// The receive API delivers one datagram at a time, so sends stay scalar.
func (t *tunnel) pumpToTarget() {
	for {
		data, err := t.stream.ReceiveDatagram(context.Background())
		if err != nil {
			if !errors.Is(err, io.EOF) {
				t.logDebug("MASQUE datagram receive ended", "error", err)
			}
			return
		}
		contextID, n, err := quicvarint.Parse(data)
		if err != nil || contextID != 0 {
			// Malformed frames and non-zero context IDs are dropped: only UDP
			// payload proxying (context ID 0) is supported.
			t.logDebug("dropping non-payload MASQUE datagram", "contextID", contextID, "error", err)
			continue
		}
		payload := data[n:]
		if len(payload) > t.maxPayload() {
			t.logDebug("dropping oversized MASQUE datagram", "size", len(payload))
			continue
		}
		if _, err := t.conn.Write(payload); err != nil {
			t.logDebug("MASQUE outbound write ended", "error", err)
			return
		}
		t.touch()
	}
}

// pumpToClient forwards packets read from the outbound socket back to the
// client as QUIC datagrams. SendDatagram copies its input, so the buffer is
// safe to reuse and pool.
func (t *tunnel) pumpToClient() {
	buffer := t.server.getDatagramBuffer()
	defer t.server.putDatagramBuffer(buffer)
	offset := len(contextIDZero)
	for {
		n, err := t.conn.Read(buffer[offset:])
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				t.logDebug("MASQUE inbound read ended", "error", err)
			}
			return
		}
		if n > t.maxPayload() {
			t.logDebug("dropping oversized UDP packet", "size", n)
			continue
		}
		if err := t.stream.SendDatagram(buffer[:offset+n]); err != nil {
			t.logDebug("MASQUE datagram send ended", "error", err)
			return
		}
		t.touch()
	}
}

// discardCapsules drains capsules on the request stream until the client
// closes it, discarding unknown capsule types.
func (t *tunnel) discardCapsules() {
	reader := quicvarint.NewReader(t.stream)
	for {
		capsuleType, r, err := http3.ParseCapsule(reader)
		if err != nil {
			// EOF or a stream reset both mean the client is done.
			return
		}
		if serverbase.DebugEnabled() {
			slog.Debug("discarding MASQUE capsule", "type", capsuleType)
		}
		if _, err := io.Copy(io.Discard, r); err != nil {
			return
		}
	}
}

// teardown unblocks both pumps and releases the socket and stream.
func (t *tunnel) teardown() {
	t.stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeConnectError))
	_ = t.stream.Close()
	_ = t.conn.Close()
}

func (t *tunnel) logDebug(msg string, args ...any) {
	if !serverbase.DebugEnabled() || t.server.closedQuietly() {
		return
	}
	slog.Debug(msg, args...)
}
