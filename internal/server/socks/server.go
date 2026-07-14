// Package socks implements the SOCKS5 proxy server, including the acceptor,
// connection handler, and the CONNECT / UDP ASSOCIATE / BIND command handlers.
package socks

import (
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

// Accept drives a single SOCKS5 connection to completion.
func (a Socks5Acceptor) Accept(stream net.Conn, socketAddr netip.AddrPort) {
	defer stream.Close()
	if err := handle(a.ctx, NewIncomingConnection(stream, a.auth), socketAddr, a.connector, a.timeout, a.udp); err != nil {
		slog.Debug("SOCKS5 connection failed", "error", err)
	}
}

// Socks5Server listens for SOCKS5 connections and dispatches them to acceptors.
type Socks5Server struct {
	listener       net.Listener
	extraListeners []net.Listener
	acceptor       Socks5Acceptor
	gate           *serverbase.ConnectionGate
	conns          *serverbase.ConnectionSet
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	launchMu       sync.Mutex
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
			_ = s.acceptLoop(listener)
		}()
	}
	return s.acceptLoop(s.listener)
}

func (s *Socks5Server) acceptLoop(ln net.Listener) error {
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
		serverbase.TuneTCPConnection(conn)
		var peer netip.AddrPort
		if ra, rerr := netip.ParseAddrPort(conn.RemoteAddr().String()); rerr == nil {
			peer = ra
		}
		acceptor := s.acceptor
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
			acceptor.Accept(conn, peer)
		}()
		s.launchMu.Unlock()
	}
}

// Close stops the listeners.
func (s *Socks5Server) Close() error {
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
func handle(ctx context.Context, conn IncomingConnection, socketAddr netip.AddrPort, connector *connect.Connector, timeout time.Duration, udp *udpRuntime) error {
	_ = conn.stream.SetDeadline(time.Now().Add(timeout))
	stream, extension, err := conn.Authenticate()
	if err != nil {
		if err == errNoAcceptableMethods {
			return nil
		}
		if stream != nil {
			slog.Debug("SOCKS5 authentication failed", "error", err, "client", socketAddr)
			_ = stream.Close()
			return nil
		}
		return err
	}

	req, err := proto.ReadRequest(stream)
	if err != nil {
		_ = stream.Close()
		return err
	}
	_ = stream.SetDeadline(time.Time{})

	switch req.Command {
	case proto.CmdUDPAssociate:
		return handleUDP(ctx, stream, req.Address, connector.UDP(extension), udp)
	case proto.CmdConnect:
		return handleConnect(ctx, stream, req.Address, connector.TCP(extension))
	case proto.CmdBind:
		return handleBind(ctx, stream, req.Address, connector.TCP(extension), timeout)
	default:
		_ = proto.NewResponse(proto.ReplyCommandNotSupported, proto.Unspecified()).MarshalTo(stream)
		_ = stream.Close()
		return fmt.Errorf("unsupported command %#x", req.Command)
	}
}

// handleConnect implements the SOCKS5 CONNECT command: establish a TCP tunnel
// between the client and the target.
func handleConnect(ctx context.Context, client net.Conn, address proto.Address, connector *connect.TcpConnector) error {
	var outbound *net.TCPConn
	var dialErr error

	if address.Socket != nil {
		ap := *address.Socket
		slog.Debug("SOCKS5 connection forwarding", "client", client.RemoteAddr(), "target", ap)
		outbound, dialErr = connector.Connect(ctx, connect.FromAddr(ap))
	} else {
		slog.Debug("SOCKS5 connection forwarding", "client", client.RemoteAddr(), "host", address.Domain, "port", address.Port)
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

	fromClient, fromServer, _ := serverbase.CopyBidirectionalContext(ctx, client, outbound, serverbase.DefaultHalfCloseGrace)
	slog.Debug("SOCKS5 connection closed", "sent", fromClient, "received", fromServer)
	_ = outbound.CloseWrite()
	_ = outbound.Close()
	_ = serverbase.CloseWrite(client)
	_ = client.Close()
	return nil
}

// handleBind implements the SOCKS5 BIND command: listen for an inbound
// connection from the target and forward data between client and target.
func handleBind(ctx context.Context, client net.Conn, _ proto.Address, connector *connect.TcpConnector, timeout time.Duration) error {
	listenIP, err := connector.SocketAddr(func() (netip.Addr, error) {
		if la := client.LocalAddr(); la != nil {
			if ap, perr := netip.ParseAddrPort(la.String()); perr == nil {
				return ap.Addr(), nil
			}
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
	defer ln.Close()
	if timeout > 0 {
		_ = ln.SetDeadline(time.Now().Add(timeout))
	}
	slog.Debug("SOCKS5 bind listening", "address", ln.Addr())

	bndAddr, _ := netip.ParseAddrPort(ln.Addr().String())
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
	defer outbound.Close()
	slog.Debug("SOCKS5 bind accepted connection", "remote", outbound.RemoteAddr())

	outboundAddr, _ := netip.ParseAddrPort(outbound.RemoteAddr().String())
	if err := proto.NewResponse(proto.ReplySucceeded, proto.SocketAddress(outboundAddr)).MarshalTo(client); err != nil {
		_ = client.Close()
		return err
	}

	fromClient, fromServer, _ := serverbase.CopyBidirectionalContext(ctx, client, outbound, serverbase.DefaultHalfCloseGrace)
	slog.Debug("SOCKS5 bind connection closed", "sent", fromClient, "received", fromServer)
	_ = serverbase.CloseWrite(client)
	_ = outbound.CloseWrite()
	_ = client.Close()
	return nil
}

// handleUDP implements the SOCKS5 UDP ASSOCIATE command: relay UDP packets
// between the client and remote targets, with source-IP authorization.
func handleUDP(parentCtx context.Context, client net.Conn, address proto.Address, connector *connect.UdpConnector, runtime *udpRuntime) error {
	associationID, opened := runtime.beginAssociation()
	if !opened {
		_ = proto.NewResponse(proto.ReplyConnectionNotAllowed, proto.Unspecified()).MarshalTo(client)
		return errors.New("SOCKS5 UDP association limit reached")
	}
	defer runtime.endAssociation()

	// Bind the inbound UDP socket on the same IP family as the TCP control
	// connection's local address.
	localIP := netip.IPv4Unspecified()
	if la := client.LocalAddr(); la != nil {
		if ap, perr := netip.ParseAddrPort(la.String()); perr == nil {
			localIP = ap.Addr()
		}
	}
	inbound, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IP(localIP.AsSlice()), Port: 0})
	if err != nil {
		_ = proto.NewResponse(proto.ReplyGeneralFailure, proto.Unspecified()).MarshalTo(client)
		_ = client.Close()
		return err
	}
	connect.TuneUDPBuffers(inbound, runtime.config.SocketBufferBytes)
	listenAddr, _ := netip.ParseAddrPort(inbound.LocalAddr().String())
	slog.Debug("SOCKS5 UDP association listening", "address", listenAddr)

	if err := proto.NewResponse(proto.ReplySucceeded, proto.SocketAddress(listenAddr)).MarshalTo(client); err != nil {
		_ = inbound.Close()
		_ = client.Close()
		return err
	}

	preferredOutbound, fallbackOutbound, err := connector.CreateSocketDualStack()
	if err != nil {
		_ = inbound.Close()
		_ = client.Close()
		return err
	}
	connect.TuneUDPBuffers(preferredOutbound, runtime.config.SocketBufferBytes)
	connect.TuneUDPBuffers(fallbackOutbound, runtime.config.SocketBufferBytes)

	// Determine the authorized source IP for UDP packets. If the client did not
	// specify a non-wildcard IP in the association request, default to the TCP
	// control connection's peer IP (RFC 1928 搂7).
	var srcIP netip.Addr
	if address.Socket != nil && !address.Socket.Addr().IsUnspecified() {
		srcIP = address.Socket.Addr()
	} else {
		if ra, rerr := netip.ParseAddrPort(client.RemoteAddr().String()); rerr == nil {
			srcIP = ra.Addr()
		} else {
			srcIP = netip.IPv4Unspecified()
		}
	}
	var srcPort atomic.Uint32

	ctx, cancel := context.WithCancel(parentCtx)
	errCh := make(chan error, 4)
	// lastActivity (unix nanos) is written by the reactor read handlers and read
	// by this goroutine to enforce the optional idle timeout.
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())
	// The inbound request socket and outbound response sockets are serviced by
	// the shared epoll reactor when available, so a busy association holds no
	// dedicated read goroutine; reactorFds records the registrations to tear down
	// (deregister waits for any in-flight handler) before the sockets are closed.
	// serveWG tracks the fallback blocking read goroutines used off Linux.
	reactor, useReactor := runtime.sharedReactor()
	var reactorFds []int
	var serveWG sync.WaitGroup
	defer func() {
		cancel()
		for _, fd := range reactorFds {
			reactor.deregister(fd)
		}
		_ = client.Close()
		_ = inbound.Close()
		_ = preferredOutbound.Close()
		if fallbackOutbound != nil {
			_ = fallbackOutbound.Close()
		}
		serveWG.Wait()
	}()

	// Request-direction batch senders. Client->target packets that carry a
	// literal IP target are grouped by address family and flushed with one
	// sendmmsg per outbound socket (Linux); domain targets stay on the async
	// worker path so a cold DNS lookup never blocks this loop. Each writer is
	// used only by this goroutine, so it needs no synchronization.
	preferredWriter := newUDPBatchWriter(preferredOutbound, runtime.config.BatchSize)
	preferredV4 := udpSocketIsV4(preferredOutbound)
	var fallbackWriter udpBatchWriter
	var fallbackV4 bool
	if fallbackOutbound != nil {
		fallbackWriter = newUDPBatchWriter(fallbackOutbound, runtime.config.BatchSize)
		fallbackV4 = udpSocketIsV4(fallbackOutbound)
	}
	preferredBatch := make([]udpWritePacket, 0, runtime.config.BatchSize)
	fallbackBatch := make([]udpWritePacket, 0, runtime.config.BatchSize)

	// When enabled and supported by the kernel, a batch that targets a single
	// destination with uniform-size datagrams is sent with one UDP_SEGMENT (GSO)
	// call instead of sendmmsg; anything else falls back to sendmmsg.
	gsoEnabled := runtime.config.GSO && udpGSOSupported()

	flushBatch := func(writer udpBatchWriter, conn *net.UDPConn, batch *[]udpWritePacket) {
		if len(*batch) == 0 {
			return
		}
		var written int
		var writeErr error
		if gsoSize, ok := gsoEligible(gsoEnabled, *batch); ok {
			written, writeErr = sendUDPGSO(conn, *batch, gsoSize)
		} else {
			written, writeErr = writer.Write(*batch)
		}
		for _, write := range *batch {
			runtime.releaseBuffer(write.owner, write.batchSlot)
		}
		if writeErr != nil || written != len(*batch) {
			runtime.metrics.errors.Add(1)
			if writeErr == nil {
				writeErr = io.ErrShortWrite
			}
			reportUDPError(errCh, writeErr)
		}
		*batch = (*batch)[:0]
	}

	// batchInPackets/batchInBytes accumulate the inbound counts for one
	// inboundPump batch; the loop flushes them with a single atomic add per batch
	// instead of one per datagram, cutting shared cache-line contention on the hot
	// path. The totals are identical, just flushed per batch. Drop counters
	// (fragment/unauthorized/etc.) stay per-event since they are rare.
	var batchInPackets, batchInBytes uint64

	// processInbound applies the fragment/authorization checks and metrics to one
	// client packet, then either queues a literal-IP target into its family batch
	// or dispatches a domain target to a send worker. It returns true when the
	// packet counts as association activity.
	processInbound := func(pkt inboundPacket) bool {
		if pkt.frag != 0 {
			slog.Debug("[SOCKS5][UDP] packet fragment is not supported")
			runtime.metrics.fragmentDrops.Add(1)
			runtime.releaseInboundPacket(pkt)
			return false
		}
		if !isAuthorized(pkt.src, srcIP) {
			slog.Debug("SOCKS5 UDP packet from unauthorized IP", "source", pkt.src, "expected", srcIP)
			runtime.metrics.unauthorizedDrops.Add(1)
			runtime.releaseInboundPacket(pkt)
			return false
		}
		srcPort.Store(uint32(pkt.src.Port()))
		batchInPackets++
		batchInBytes += uint64(len(pkt.payload))

		// Resolve the outbound target. Literal IPs and already-cached domains take
		// the fast batch path; an uncached domain is handed to a send worker that
		// resolves it off this loop, so a cold DNS lookup never stalls the batch.
		var target netip.AddrPort
		switch {
		case pkt.dst.Socket != nil:
			target = netip.AddrPortFrom(pkt.dst.Socket.Addr().Unmap(), pkt.dst.Socket.Port())
		default:
			resolved, ok := cachedTargetForFamily(pkt.dst.Domain, pkt.dst.Port, preferredV4, fallbackWriter != nil, fallbackV4)
			if !ok {
				if !runtime.dispatch(udpSendJob{
					associationID: associationID,
					ctx:           ctx,
					connector:     connector,
					packet:        pkt,
					target:        connect.FromHost(pkt.dst.Domain, pkt.dst.Port),
					preferred:     preferredOutbound,
					fallback:      fallbackOutbound,
					errCh:         errCh,
				}) {
					runtime.releaseInboundPacket(pkt)
				}
				return true
			}
			target = resolved
		}

		batch := &preferredBatch
		if preferredV4 != target.Addr().Is4() && fallbackWriter != nil && fallbackV4 == target.Addr().Is4() {
			batch = &fallbackBatch
		}
		*batch = append(*batch, udpWritePacket{
			buffer:    pkt.payload,
			owner:     pkt.buffer,
			addr:      target,
			batchSlot: pkt.batchSlot,
		})
		return true
	}

	// inboundPump reads one batch of client datagrams and forwards them to their
	// targets, merging the old inbound reader and the old main loop. The reactor
	// calls it once per readable event; it returns false when the inbound socket
	// is done.
	inboundReader := newUDPBatchReader(inbound, runtime, 0, runtime.config.MaxPacketSize)
	inboundPump := func() bool {
		packets, rerr := inboundReader.Read()
		if rerr != nil {
			if ctx.Err() == nil && !errors.Is(rerr, net.ErrClosed) {
				runtime.metrics.errors.Add(1)
				reportUDPError(errCh, rerr)
			}
			return false
		}
		active := false
		batchInPackets, batchInBytes = 0, 0
		for _, packet := range packets {
			if packet.truncated {
				runtime.metrics.truncatedDrops.Add(1)
				runtime.releaseReadPacket(packet)
				continue
			}
			hdr, hlen, herr := proto.ParseUdpHeader(packet.buffer[:packet.n])
			if herr != nil {
				runtime.metrics.malformedDrops.Add(1)
				runtime.releaseReadPacket(packet)
				continue
			}
			if processInbound(inboundPacket{
				payload:   packet.buffer[hlen:packet.n],
				buffer:    packet.buffer,
				frag:      hdr.Frag,
				dst:       hdr.Address,
				src:       packet.addr,
				batchSlot: packet.batchSlot,
			}) {
				active = true
			}
		}
		if batchInPackets > 0 {
			runtime.metrics.inPackets.Add(batchInPackets)
			runtime.metrics.inBytes.Add(batchInBytes)
		}
		flushBatch(preferredWriter, preferredOutbound, &preferredBatch)
		if fallbackWriter != nil {
			flushBatch(fallbackWriter, fallbackOutbound, &fallbackBatch)
		}
		if active {
			lastActivity.Store(time.Now().UnixNano())
		}
		return true
	}

	// serveSocket drives a socket's read side from the shared reactor when
	// available (no per-association goroutine), else from a blocking goroutine.
	serveSocket := func(conn *net.UDPConn, pump func() bool) {
		if useReactor {
			if fd, ok := udpConnFd(conn); ok {
				handler := func() {
					if pump() {
						_ = reactor.rearm(fd)
					}
				}
				if reactor.register(fd, handler) == nil {
					reactorFds = append(reactorFds, fd)
					return
				}
			}
		}
		serveWG.Add(1)
		go func() {
			defer serveWG.Done()
			for pump() {
			}
		}()
	}

	startResponder := func(outbound *net.UDPConn) {
		responder := newUDPResponder(ctx, inbound, outbound, srcIP, &srcPort, runtime, errCh, &lastActivity)
		serveSocket(outbound, responder.pumpOnce)
	}
	startResponder(preferredOutbound)
	if fallbackOutbound != nil {
		startResponder(fallbackOutbound)
	}
	serveSocket(inbound, inboundPump)

	// The relay now runs entirely on the reactor; this goroutine only watches the
	// TCP control connection and ends the association when the client closes it,
	// on idle timeout, or on server shutdown. A read deadline polls the idle
	// timeout; an AfterFunc interrupts a blocked read at shutdown.
	stopInterrupt := context.AfterFunc(parentCtx, func() { _ = client.SetReadDeadline(time.Now()) })
	defer stopInterrupt()
	idleTimeout := time.Duration(runtime.config.AssociationIdleTimeoutSecs) * time.Second
	var controlBuf [1]byte
	for {
		if parentCtx.Err() != nil {
			return parentCtx.Err()
		}
		if idleTimeout > 0 {
			_ = client.SetReadDeadline(time.Unix(0, lastActivity.Load()).Add(idleTimeout))
		}
		_, err := client.Read(controlBuf[:])
		if err == nil {
			continue // unexpected data on the control connection; ignored per RFC 1928
		}
		if parentCtx.Err() != nil {
			return parentCtx.Err()
		}
		var netErr net.Error
		if idleTimeout > 0 && errors.As(err, &netErr) && netErr.Timeout() {
			if time.Since(time.Unix(0, lastActivity.Load())) >= idleTimeout {
				slog.Debug("SOCKS5 UDP association idle timeout", "address", listenAddr)
				return nil
			}
			continue // activity happened; re-arm the deadline
		}
		slog.Debug("SOCKS5 UDP association closed", "address", listenAddr)
		return nil
	}
}

// udpResponder relays target responses on one outbound socket back to the
// client. It can be driven either by a dedicated blocking goroutine
// (serveBlocking) or, on Linux, one readable event at a time from the shared
// reactor (pumpOnce), so associations need not each hold a read goroutine.
type udpResponder struct {
	ctx          context.Context
	clientIP     netip.Addr
	clientPort   *atomic.Uint32
	runtime      *udpRuntime
	errCh        chan<- error
	lastActivity *atomic.Int64
	reader       udpBatchReader
	writer       udpBatchWriter
	writes       []udpWritePacket
	payloadBytes []int
}

func newUDPResponder(
	ctx context.Context,
	inbound, outbound *net.UDPConn,
	clientIP netip.Addr,
	clientPort *atomic.Uint32,
	runtime *udpRuntime,
	errCh chan<- error,
	lastActivity *atomic.Int64,
) *udpResponder {
	return &udpResponder{
		ctx:          ctx,
		clientIP:     clientIP,
		clientPort:   clientPort,
		runtime:      runtime,
		errCh:        errCh,
		lastActivity: lastActivity,
		reader:       newUDPBatchReader(outbound, runtime, proto.UdpHeaderMaxLen, runtime.config.MaxPacketSize-maxUDPResponseHeaderLen),
		writer:       newUDPBatchWriter(inbound, runtime.config.BatchSize),
		writes:       make([]udpWritePacket, 0, runtime.config.BatchSize),
		payloadBytes: make([]int, 0, runtime.config.BatchSize),
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
	p.writes = p.writes[:0]
	p.payloadBytes = p.payloadBytes[:0]
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
		payload := packet.buffer[proto.UdpHeaderMaxLen : proto.UdpHeaderMaxLen+packet.n]
		response := prepareUDPResponse(outboundPacket{
			payload: payload,
			buffer:  packet.buffer,
			remote:  net.UDPAddrFromAddrPort(packet.addr),
		})
		p.writes = append(p.writes, udpWritePacket{buffer: response, owner: packet.buffer, addr: clientAddr, batchSlot: packet.batchSlot})
		p.payloadBytes = append(p.payloadBytes, packet.n)
	}
	written, writeErr := p.writer.Write(p.writes)
	var outPackets, outBytes uint64
	for i, write := range p.writes {
		if i < written {
			outPackets++
			outBytes += uint64(p.payloadBytes[i])
		}
		// Every response is backed by one independently pooled buffer.
		p.runtime.releaseBuffer(write.owner, write.batchSlot)
	}
	// One atomic add per batch instead of one per datagram (identical totals).
	if outPackets > 0 {
		p.runtime.metrics.outPackets.Add(outPackets)
		p.runtime.metrics.outBytes.Add(outBytes)
	}
	if writeErr != nil || written != len(p.writes) {
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

// serveBlocking pumps responses in a loop on a dedicated goroutine (the
// non-reactor fallback and non-Linux path).
func (p *udpResponder) serveBlocking() {
	for p.pumpOnce() {
	}
}

func writeUDPResponse(inbound *net.UDPConn, clientAddr netip.AddrPort, pkt outboundPacket) error {
	packet := prepareUDPResponse(pkt)
	_, err := inbound.WriteToUDP(packet, net.UDPAddrFromAddrPort(clientAddr))
	return err
}

func prepareUDPResponse(pkt outboundPacket) []byte {
	if len(pkt.buffer) >= proto.UdpHeaderMaxLen+len(pkt.payload) {
		remote := pkt.remote.AddrPort()
		remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
		headerLength := 3 + 1 + 16 + 2
		if remote.Addr().Is4() {
			headerLength = 3 + 1 + 4 + 2
		}
		start := proto.UdpHeaderMaxLen - headerLength
		header := pkt.buffer[start:proto.UdpHeaderMaxLen]
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
		return pkt.buffer[start : proto.UdpHeaderMaxLen+len(pkt.payload)]
	}
	return proto.BuildUdpPacket(0, proto.SocketAddress(pkt.remote.AddrPort()), pkt.payload)
}

// inboundPacket is a parsed SOCKS5 UDP relay packet from the client.
type inboundPacket struct {
	payload   []byte
	buffer    []byte
	frag      uint8
	dst       proto.Address
	src       netip.AddrPort
	batchSlot bool
}

type udpSendJob struct {
	associationID uint64
	ctx           context.Context
	connector     *connect.UdpConnector
	packet        inboundPacket
	target        connect.TargetAddr
	preferred     *net.UDPConn
	fallback      *net.UDPConn
	errCh         chan<- error
}

// outboundPacket is a UDP packet received from a remote target.
type outboundPacket struct {
	payload []byte
	buffer  []byte
	remote  *net.UDPAddr
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
// family, so the caller falls back to the resolving worker path.
func cachedTargetForFamily(domain string, port uint16, preferredV4, hasFallback, fallbackV4 bool) (netip.AddrPort, bool) {
	addrs, ok := connect.LookupCachedHost(domain)
	if !ok {
		return netip.AddrPort{}, false
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
