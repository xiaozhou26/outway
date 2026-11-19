// Package socks implements the SOCKS5 proxy server, including the acceptor,
// connection handler, and the CONNECT / UDP ASSOCIATE / BIND command handlers.
package socks

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xiaozhou26/outway/internal/config"
	"github.com/xiaozhou26/outway/internal/connect"
	"github.com/xiaozhou26/outway/internal/server/socks/proto"
	"github.com/xiaozhou26/outway/internal/serverbase"
)

// MaxUDPRelayPacketSize is retained as the default for callers and tests. The
// running server uses the configurable value in config.UDPConfig.
const MaxUDPRelayPacketSize = config.DefaultUDPMaxPacketSize

const maxUDPResponseHeaderLen = 3 + 1 + 16 + 2

// Socks5Acceptor handles a single accepted SOCKS5 connection.
type Socks5Acceptor struct {
	auth      AuthAdaptor
	connector *connect.Connector
	timeout   time.Duration
	ctx       context.Context
	udp       *udpRuntime
}

// NewAcceptor builds a Socks5Acceptor from a server Context.
func NewAcceptor(ctx serverbase.Context, lifetime context.Context) Socks5Acceptor {
	var auth AuthAdaptor
	if ctx.Auth.HasAuth() {
		auth = PasswordConfig(ctx.Auth.Username, ctx.Auth.Password)
	} else {
		auth = NoAuthConfig()
	}
	return Socks5Acceptor{
		auth:      auth,
		connector: ctx.Connector,
		timeout:   time.Duration(ctx.ConnectTimeout) * time.Second,
		ctx:       lifetime,
		udp:       newUDPRuntime(ctx.UDP, ctx.Concurrent, lifetime),
	}
}

// WaitUDPWorkers waits for the server-scoped UDP send workers to stop after
// the acceptor lifetime is canceled.
func (a Socks5Acceptor) WaitUDPWorkers(timeout time.Duration) bool {
	return a.udp.wait(timeout)
}

// UDPStats returns the current SOCKS5 UDP relay counters.
func (a Socks5Acceptor) UDPStats() UDPStatsSnapshot {
	return a.udp.statsSnapshot()
}

// WithLifetime returns a copy of the acceptor whose handlers derive request
// contexts from ctx (typically a serverbase.LifetimeShards shard) instead of
// the root lifetime.
func (a Socks5Acceptor) WithLifetime(ctx context.Context) Socks5Acceptor {
	a.ctx = ctx
	return a
}

// Accept drives a single SOCKS5 connection to completion.
func (a Socks5Acceptor) Accept(stream net.Conn, socketAddr netip.AddrPort) {
	defer func() { _ = stream.Close() }()
	if err := handle(a.ctx, stream, a.auth, socketAddr, a.connector, a.timeout, a.udp); err != nil {
		if serverbase.DebugEnabled() {
			slog.Debug("SOCKS5 connection failed", "error", err)
		}
	}
}

// Socks5Server listens for SOCKS5 connections and dispatches them to acceptors.
type Socks5Server struct {
	listener       net.Listener
	extraListeners []net.Listener
	acceptor       Socks5Acceptor
	gate           *serverbase.ConnectionGate
	conns          *serverbase.ConnectionSet
	lifetimes      *serverbase.LifetimeShards
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	closeOnce      sync.Once
	closeErr       error
}

// NewServer binds one or more TCP listeners (SO_REUSEPORT shards when enabled)
// and returns a Socks5Server.
func NewServer(ctx serverbase.Context) (*Socks5Server, error) {
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
	return &Socks5Server{
		listener:       listeners[0],
		extraListeners: listeners[1:],
		acceptor:       NewAcceptor(ctx, lifetime),
		gate:           serverbase.NewConnectionGate(ctx.Concurrent),
		conns:          serverbase.NewConnectionSet(),
		lifetimes:      serverbase.NewLifetimeShards(lifetime),
		cancel:         cancel,
	}, nil
}

// Start runs the accept loops until the server is shut down.
func (s *Socks5Server) Start() error {
	slog.Info(fmt.Sprintf("Socks5 proxy server listening on %s", s.listener.Addr()))
	for _, ln := range s.extraListeners {
		listener := ln
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := s.acceptLoop(listener); err != nil && !serverbase.IsConnClosed(err) {
				slog.Error("SOCKS5 accept shard stopped", "error", err)
			}
		}()
	}
	// The main accept loop holds a WaitGroup slot too, so handler goroutines can
	// wg.Add from inside any accept loop without racing a concurrent wg.Wait
	// (the counter cannot reach zero while an accept loop is still running).
	s.wg.Add(1)
	defer s.wg.Done()
	return s.acceptLoop(s.listener)
}

// UDPStats returns the current SOCKS5 UDP relay counters.
func (s *Socks5Server) UDPStats() UDPStatsSnapshot {
	return s.acceptor.UDPStats()
}

func (s *Socks5Server) acceptLoop(ln net.Listener) error {
	return serverbase.AcceptLoop(ln, &s.wg, s.gate, s.conns, func(conn net.Conn) {
		serverbase.TuneTCPConnection(conn)
		peer := serverbase.AddrPortOf(conn.RemoteAddr())
		acceptor := s.acceptor.WithLifetime(s.lifetimes.For(conn))
		acceptor.Accept(conn, peer)
	})
}

// Close stops the listeners.
func (s *Socks5Server) Close() error {
	s.closeOnce.Do(func() {
		s.cancel()
		connectionErr := s.conns.CloseAll()
		listenerErr := serverbase.CloseListeners(s.listener, s.extraListeners)
		var waitErr error
		if !serverbase.WaitGroupTimeout(&s.wg, serverbase.DefaultShutdownWait) {
			waitErr = errors.New("SOCKS5 handlers did not stop before shutdown timeout")
		}
		if !s.acceptor.WaitUDPWorkers(serverbase.DefaultShutdownWait) {
			waitErr = errors.Join(waitErr, errors.New("SOCKS5 UDP workers did not stop before shutdown timeout"))
		}
		s.closeErr = errors.Join(connectionErr, listenerErr, waitErr)
	})
	return s.closeErr
}

// handle authenticates the incoming connection, reads its request, and
// dispatches to the appropriate command handler.
func handle(ctx context.Context, stream net.Conn, auth AuthAdaptor, socketAddr netip.AddrPort, connector *connect.Connector, timeout time.Duration, udp *udpRuntime) error {
	// Read the handshake and request through a pooled buffered reader so the
	// multi-field negotiation costs one recv per client flight instead of one
	// syscall per field. Replies are written straight to the raw stream, and the
	// CONNECT/BIND data path splices the raw stream after draining any bytes the
	// reader pulled ahead, preserving kernel zero-copy.
	br := serverbase.AcquireBufferedReader(stream)
	defer serverbase.ReleaseBufferedReader(br)

	_ = stream.SetDeadline(time.Now().Add(timeout))
	authed, extension, err := NewIncomingConnection(stream, br, auth).Authenticate()
	if err != nil {
		if err == errNoAcceptableMethods {
			return nil
		}
		if authed != nil {
			slog.Debug("SOCKS5 authentication failed", "error", err, "client", socketAddr)
			_ = authed.Close()
			return nil
		}
		return err
	}

	req, err := proto.ReadRequest(br)
	if err != nil {
		_ = stream.Close()
		return err
	}
	_ = stream.SetDeadline(time.Time{})

	switch req.Command {
	case proto.CmdUDPAssociate:
		return handleUDP(ctx, stream, req.Address, connector.UDP(extension), udp)
	case proto.CmdConnect:
		return handleConnect(ctx, stream, br, req.Address, connector.TCP(extension))
	case proto.CmdBind:
		return handleBind(ctx, stream, br, req.Address, connector.TCP(extension), timeout)
	default:
		_ = proto.NewResponse(proto.ReplyCommandNotSupported, proto.Unspecified()).MarshalTo(stream)
		_ = stream.Close()
		return fmt.Errorf("unsupported command %#x", req.Command)
	}
}

// handleConnect implements the SOCKS5 CONNECT command: establish a TCP tunnel
// between the client and the target.
func handleConnect(ctx context.Context, client net.Conn, br *bufio.Reader, address proto.Address, connector connect.TcpConnector) error {
	var outbound *net.TCPConn
	var dialErr error

	if address.Socket != nil {
		ap := *address.Socket
		if serverbase.DebugEnabled() {
			slog.Debug("SOCKS5 connection forwarding", "client", client.RemoteAddr(), "target", ap)
		}
		outbound, dialErr = connector.Connect(ctx, connect.FromAddr(ap))
	} else {
		if serverbase.DebugEnabled() {
			slog.Debug("SOCKS5 connection forwarding", "client", client.RemoteAddr(), "host", address.Domain, "port", address.Port)
		}
		outbound, dialErr = connector.Connect(ctx, connect.FromHost(address.Domain, address.Port))
	}

	if dialErr != nil {
		_ = proto.NewResponse(proto.ReplyHostUnreachable, proto.Unspecified()).MarshalTo(client)
		_ = serverbase.CloseWrite(client)
		_ = client.Close()
		return dialErr
	}

	if err := proto.NewResponse(proto.ReplySucceeded, proto.Unspecified()).MarshalTo(client); err != nil {
		_ = outbound.Close()
		_ = client.Close()
		return err
	}

	// Forward any client bytes the buffered handshake reader pulled ahead of the
	// request before splicing the raw connection. SOCKS5 clients normally wait
	// for this reply, so this is almost always a no-op; performing it keeps the
	// subsequent copy on the raw stream so io.Copy can use splice(2).
	if n := br.Buffered(); n > 0 {
		if _, err := io.CopyN(outbound, br, int64(n)); err != nil {
			_ = outbound.Close()
			_ = client.Close()
			return err
		}
	}

	fromClient, fromServer, _ := serverbase.CopyBidirectionalContext(ctx, client, outbound, serverbase.DefaultHalfCloseGrace)
	if serverbase.DebugEnabled() {
		slog.Debug("SOCKS5 connection closed", "sent", fromClient, "received", fromServer)
	}
	_ = outbound.CloseWrite()
	_ = outbound.Close()
	_ = serverbase.CloseWrite(client)
	_ = client.Close()
	return nil
}

// handleBind implements the SOCKS5 BIND command: listen for an inbound
// connection from the target and forward data between client and target.
func handleBind(ctx context.Context, client net.Conn, br *bufio.Reader, _ proto.Address, connector connect.TcpConnector, timeout time.Duration) error {
	listenIP, err := connector.SocketAddr(func() (netip.Addr, error) {
		if ap := serverbase.AddrPortOf(client.LocalAddr()); ap.IsValid() {
			return ap.Addr(), nil
		}
		return netip.IPv4Unspecified(), nil
	})
	if err != nil {
		_ = proto.NewResponse(proto.ReplyGeneralFailure, proto.Unspecified()).MarshalTo(client)
		_ = client.Close()
		return err
	}

	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IP(listenIP.Addr().AsSlice()), Port: 0})
	if err != nil {
		_ = proto.NewResponse(proto.ReplyGeneralFailure, proto.Unspecified()).MarshalTo(client)
		_ = client.Close()
		return err
	}
	defer func() { _ = ln.Close() }()
	if timeout > 0 {
		_ = ln.SetDeadline(time.Now().Add(timeout))
	}
	slog.Debug("SOCKS5 bind listening", "address", ln.Addr())

	bndAddr := serverbase.AddrPortOf(ln.Addr())
	if err := proto.NewResponse(proto.ReplySucceeded, proto.SocketAddress(bndAddr)).MarshalTo(client); err != nil {
		_ = client.Close()
		return err
	}

	type acceptResult struct {
		conn *net.TCPConn
		err  error
	}
	acceptCh := make(chan acceptResult, 1)
	go func() {
		conn, err := ln.AcceptTCP()
		acceptCh <- acceptResult{conn: conn, err: err}
	}()
	var outbound *net.TCPConn
	select {
	case result := <-acceptCh:
		outbound, err = result.conn, result.err
	case <-ctx.Done():
		_ = ln.Close()
		result := <-acceptCh
		if result.conn != nil {
			_ = result.conn.Close()
		}
		_ = client.Close()
		return ctx.Err()
	}
	if err != nil {
		_ = proto.NewResponse(proto.ReplyGeneralFailure, proto.Unspecified()).MarshalTo(client)
		_ = client.Close()
		return err
	}
	defer func() { _ = outbound.Close() }()
	slog.Debug("SOCKS5 bind accepted connection", "remote", outbound.RemoteAddr())

	outboundAddr := serverbase.AddrPortOf(outbound.RemoteAddr())
	if err := proto.NewResponse(proto.ReplySucceeded, proto.SocketAddress(outboundAddr)).MarshalTo(client); err != nil {
		_ = client.Close()
		return err
	}

	// Forward any client bytes buffered ahead of the request before splicing.
	if n := br.Buffered(); n > 0 {
		if _, err := io.CopyN(outbound, br, int64(n)); err != nil {
			_ = client.Close()
			return err
		}
	}

	fromClient, fromServer, _ := serverbase.CopyBidirectionalContext(ctx, client, outbound, serverbase.DefaultHalfCloseGrace)
	slog.Debug("SOCKS5 bind connection closed", "sent", fromClient, "received", fromServer)
	_ = serverbase.CloseWrite(client)
	_ = outbound.CloseWrite()
	_ = client.Close()
	return nil
}

// udpResponder relays target responses on one outbound socket back to the
// client. On Linux it is driven one readable event at a time from the shared
// reactor (pumpOnce); elsewhere the caller pumps it on a dedicated goroutine,
// so associations need not each hold a read goroutine.
type udpResponder struct {
	ctx          context.Context
	clientIP     netip.Addr
	clientPort   *atomic.Uint32
	runtime      *udpRuntime
	errCh        chan<- error
	lastActivity *atomic.Int64
	reader       udpBatchReader
	writer       udpBatchWriter
	batches      *udpBatchSlices
}

func newUDPResponder(
	ctx context.Context,
	inbound, outbound *net.UDPConn,
	clientIP netip.Addr,
	clientPort *atomic.Uint32,
	runtime *udpRuntime,
	errCh chan<- error,
	lastActivity *atomic.Int64,
	batches *udpBatchSlices,
) *udpResponder {
	return &udpResponder{
		ctx:          ctx,
		clientIP:     clientIP,
		clientPort:   clientPort,
		runtime:      runtime,
		errCh:        errCh,
		lastActivity: lastActivity,
		reader:       newUDPBatchReader(outbound, runtime, proto.UdpHeaderMaxLen, runtime.config.MaxPacketSize-maxUDPResponseHeaderLen),
		writer:       newUDPBatchWriter(inbound, runtime),
		batches:      batches,
	}
}

// pumpOnce reads one batch of target responses and forwards them to the client.
// It returns false when the outbound socket is closed or errors, so the caller
// stops driving it. The slices are reused to keep the hot path allocation-free.
func (p *udpResponder) pumpOnce() bool {
	packets, err := p.reader.Read()
	if err != nil {
		if p.ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
			p.runtime.metrics.errors.Add(1)
			reportUDPError(p.errCh, err)
		}
		return false
	}
	clientAddr := netip.AddrPortFrom(p.clientIP, uint16(p.clientPort.Load()))
	p.batches.writes = p.batches.writes[:0]
	p.batches.payloads = p.batches.payloads[:0]
	for _, packet := range packets {
		if packet.truncated {
			p.runtime.metrics.truncatedDrops.Add(1)
			p.runtime.releaseReadPacket(packet)
			continue
		}
		if clientAddr.Port() == 0 {
			p.runtime.releaseReadPacket(packet)
			continue
		}
		payload := packet.buffer.data[proto.UdpHeaderMaxLen : proto.UdpHeaderMaxLen+packet.n]
		response := prepareUDPResponse(outboundPacket{
			payload: payload,
			buffer:  packet.buffer,
			remote:  packet.addr,
		})
		p.batches.writes = append(p.batches.writes, udpWritePacket{buffer: response, owner: packet.buffer, addr: clientAddr, batchSlot: packet.batchSlot})
		p.batches.payloads = append(p.batches.payloads, packet.n)
	}
	written, writeErr := p.writer.Write(p.batches.writes)
	var outPackets, outBytes uint64
	for i, write := range p.batches.writes {
		if i < written {
			outPackets++
			outBytes += uint64(p.batches.payloads[i])
		}
		// Every response is backed by one independently pooled buffer.
		p.runtime.releaseBuffer(write.owner, write.batchSlot)
	}
	// One atomic add per batch instead of one per datagram (identical totals).
	if outPackets > 0 {
		p.runtime.metrics.outPackets.Add(outPackets)
		p.runtime.metrics.outBytes.Add(outBytes)
	}
	if writeErr != nil || written != len(p.batches.writes) {
		p.runtime.metrics.errors.Add(1)
		if writeErr == nil {
			writeErr = io.ErrShortWrite
		}
		reportUDPError(p.errCh, writeErr)
	}
	if written > 0 {
		p.lastActivity.Store(time.Now().UnixNano())
	}
	return true
}

func prepareUDPResponse(pkt outboundPacket) []byte {
	if pkt.buffer != nil && len(pkt.buffer.data) >= proto.UdpHeaderMaxLen+len(pkt.payload) {
		remote := netip.AddrPortFrom(pkt.remote.Addr().Unmap(), pkt.remote.Port())
		headerLength := 3 + 1 + 16 + 2
		if remote.Addr().Is4() {
			headerLength = 3 + 1 + 4 + 2
		}
		start := proto.UdpHeaderMaxLen - headerLength
		header := pkt.buffer.data[start:proto.UdpHeaderMaxLen]
		header[0], header[1], header[2] = 0, 0, 0
		if remote.Addr().Is4() {
			header[3] = byte(proto.AddrIPv4)
			ip := remote.Addr().As4()
			copy(header[4:8], ip[:])
			binary.BigEndian.PutUint16(header[8:10], remote.Port())
		} else {
			header[3] = byte(proto.AddrIPv6)
			ip := remote.Addr().As16()
			copy(header[4:20], ip[:])
			binary.BigEndian.PutUint16(header[20:22], remote.Port())
		}
		return pkt.buffer.data[start : proto.UdpHeaderMaxLen+len(pkt.payload)]
	}
	return proto.BuildUdpPacket(0, proto.SocketAddress(pkt.remote), pkt.payload)
}

// inboundPacket is a parsed SOCKS5 UDP relay packet from the client.
type inboundPacket struct {
	payload   []byte
	buffer    *udpBuffer
	frag      uint8
	dst       proto.Address
	src       netip.AddrPort
	batchSlot bool
}

type udpSendJob struct {
	associationID uint64
	ctx           context.Context
	connector     connect.UdpConnector
	packet        inboundPacket
	target        connect.TargetAddr
	preferred     *net.UDPConn
	fallback      *net.UDPConn
	errCh         chan<- error
}

// outboundPacket is a UDP packet received from a remote target.
type outboundPacket struct {
	payload []byte
	buffer  *udpBuffer
	remote  netip.AddrPort
}

func reportUDPError(errCh chan<- error, err error) {
	select {
	case errCh <- err:
	default:
	}
}

// isAuthorized reports whether the source IP of a UDP packet matches the
// expected IP, considering IPv4-mapped IPv6 addresses.
func isAuthorized(src netip.AddrPort, expected netip.Addr) bool {
	srcIP := src.Addr()
	expIP := expected

	if srcIP == expIP {
		return true
	}

	// IPv4-mapped IPv6 to IPv4 match.
	if srcIP.Is4In6() && expIP.Is4() {
		if s4 := srcIP.Unmap(); s4 == expIP {
			return true
		}
	}
	// IPv4 to IPv4-mapped IPv6 match.
	if srcIP.Is4() && expIP.Is4In6() {
		if e4 := expIP.Unmap(); e4 == srcIP {
			return true
		}
	}
	return false
}

// cachedTargetForFamily returns a resolved target for a domain from the DNS
// cache, choosing a resolved address whose family has an outbound socket. ok is
// false on a cache miss or when no resolved address matches an available
// family, so the caller falls back to the resolving worker path. With
// preferPrimary (--strict-source), an address in the preferred socket's family
// wins whenever one was resolved, so traffic never leaks out the fallback.
func cachedTargetForFamily(domain string, port uint16, preferredV4, hasFallback, fallbackV4, preferPrimary bool) (netip.AddrPort, bool) {
	// Literal-IP fast path: parse inline to avoid the per-packet slice
	// allocation that a cache lookup on an IP literal would cost.
	if ip, err := netip.ParseAddr(domain); err == nil {
		unmapped := ip.Unmap()
		if preferredV4 == unmapped.Is4() || (hasFallback && fallbackV4 == unmapped.Is4()) {
			return netip.AddrPortFrom(unmapped, port), true
		}
		return netip.AddrPort{}, false
	}
	addrs, ok := connect.LookupCachedHost(domain)
	if !ok {
		return netip.AddrPort{}, false
	}
	return pickFamilyTarget(addrs, port, preferredV4, hasFallback, fallbackV4, preferPrimary)
}

// pickFamilyTarget chooses the resolved address cachedTargetForFamily sends to:
// the first one with an outbound socket of its family, or with preferPrimary
// the first one in the preferred socket's family when any exists.
func pickFamilyTarget(addrs []netip.Addr, port uint16, preferredV4, hasFallback, fallbackV4, preferPrimary bool) (netip.AddrPort, bool) {
	if preferPrimary {
		for _, addr := range addrs {
			if unmapped := addr.Unmap(); preferredV4 == unmapped.Is4() {
				return netip.AddrPortFrom(unmapped, port), true
			}
		}
	}
	for _, addr := range addrs {
		unmapped := addr.Unmap()
		if preferredV4 == unmapped.Is4() || (hasFallback && fallbackV4 == unmapped.Is4()) {
			return netip.AddrPortFrom(unmapped, port), true
		}
	}
	return netip.AddrPort{}, false
}

// udpSocketIsV4 reports whether the UDP socket is bound to an IPv4 address,
// used to route a target datagram to the matching-family outbound socket.
func udpSocketIsV4(conn *net.UDPConn) bool {
	if ua, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return ua.IP.To4() != nil
	}
	return false
}

// gsoEligible reports the UDP_SEGMENT size to use when the whole batch can be
// sent as a single GSO super-datagram: at least two packets, all to the same
// destination, every packet but the last exactly the first packet's size, and
// the last no larger. It returns false when GSO is disabled or the batch is not
// uniform, so the caller uses sendmmsg instead.
func gsoEligible(enabled bool, batch []udpWritePacket) (int, bool) {
	if !enabled || len(batch) < 2 {
		return 0, false
	}
	dst := batch[0].addr
	size := len(batch[0].buffer)
	if size == 0 {
		return 0, false
	}
	last := len(batch) - 1
	for i := 1; i < len(batch); i++ {
		if batch[i].addr != dst {
			return 0, false
		}
		length := len(batch[i].buffer)
		if i < last && length != size {
			return 0, false
		}
		if i == last && length > size {
			return 0, false
		}
	}
	return size, true
}
