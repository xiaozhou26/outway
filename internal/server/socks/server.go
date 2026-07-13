// Package socks implements the SOCKS5 proxy server, including the acceptor,
// connection handler, and the CONNECT / UDP ASSOCIATE / BIND command handlers.
package socks

import (
	"bytes"
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
	listener  net.Listener
	acceptor  Socks5Acceptor
	gate      *serverbase.ConnectionGate
	conns     *serverbase.ConnectionSet
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	launchMu  sync.Mutex
	closeOnce sync.Once
	closeErr  error
}

// NewServer binds a TCP listener and returns a Socks5Server.
func NewServer(ctx serverbase.Context) (*Socks5Server, error) {
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
	lifetime, cancel := context.WithCancel(context.Background())
	return &Socks5Server{
		listener: ln,
		acceptor: NewAcceptor(ctx, lifetime),
		gate:     serverbase.NewConnectionGate(ctx.Concurrent),
		conns:    serverbase.NewConnectionSet(),
		cancel:   cancel,
	}, nil
}

// Start runs the accept loop until the server is shut down.
func (s *Socks5Server) Start() error {
	addr := s.listener.Addr()
	slog.Info(fmt.Sprintf("Socks5 proxy server listening on %s", addr))

	for {
		conn, err := s.listener.Accept()
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

// Close stops the listener.
func (s *Socks5Server) Close() error {
	s.closeOnce.Do(func() {
		s.cancel()
		connectionErr := s.conns.CloseAll()
		listenerErr := s.listener.Close()
		if errors.Is(listenerErr, net.ErrClosed) {
			listenerErr = nil
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
	activityCh := make(chan struct{}, 1)
	// Sized to the batch so a Linux recvmmsg batch drains without a per-packet
	// scheduler round-trip between the inbound reader and this handler.
	inboundPkt := make(chan inboundPacket, runtime.config.BatchSize)
	var readers sync.WaitGroup
	defer func() {
		cancel()
		_ = client.Close()
		_ = inbound.Close()
		_ = preferredOutbound.Close()
		if fallbackOutbound != nil {
			_ = fallbackOutbound.Close()
		}
		readers.Wait()
		for {
			select {
			case packet := <-inboundPkt:
				runtime.releaseInboundPacket(packet)
			default:
				return
			}
		}
	}()

	// Inbound reader: reads SOCKS5 UDP relay packets from the client.
	readers.Add(1)
	go func() {
		defer readers.Done()
		reader := newUDPBatchReader(inbound, runtime, 0, runtime.config.MaxPacketSize)
		for {
			packets, rerr := reader.Read()
			if rerr != nil {
				if ctx.Err() != nil || errors.Is(rerr, net.ErrClosed) {
					return
				}
				runtime.metrics.errors.Add(1)
				reportUDPError(errCh, rerr)
				return
			}
			for packetIndex, packet := range packets {
				if packet.truncated {
					runtime.metrics.truncatedDrops.Add(1)
					runtime.releaseReadPacket(packet)
					continue
				}
				hdr, hlen, herr := proto.ReadUdpHeader(bytes.NewReader(packet.buffer[:packet.n]))
				if herr != nil {
					runtime.metrics.malformedDrops.Add(1)
					runtime.releaseReadPacket(packet)
					continue
				}
				pkt := inboundPacket{
					payload:   packet.buffer[hlen:packet.n],
					buffer:    packet.buffer,
					frag:      hdr.Frag,
					dst:       hdr.Address,
					src:       packet.addr,
					batchSlot: packet.batchSlot,
				}
				select {
				case inboundPkt <- pkt:
				case <-ctx.Done():
					runtime.releaseReadPacket(packet)
					for _, unprocessed := range packets[packetIndex+1:] {
						runtime.releaseReadPacket(unprocessed)
					}
					return
				}
			}
		}
	}()

	// Outbound readers relay complete batches directly to the client. This
	// avoids per-association response channels and lets Linux use sendmmsg.
	startOutboundReader := func(outbound *net.UDPConn) {
		readers.Add(1)
		go func() {
			defer readers.Done()
			relayUDPResponses(ctx, inbound, outbound, srcIP, &srcPort, runtime, errCh, activityCh)
		}()
	}
	startOutboundReader(preferredOutbound)
	if fallbackOutbound != nil {
		startOutboundReader(fallbackOutbound)
	}

	// TCP control-connection closer: signals when the client closes the TCP
	// connection, which terminates the UDP association.
	closedCh := make(chan struct{})
	readers.Add(1)
	go func() {
		defer readers.Done()
		defer close(closedCh)
		var byteBuffer [1]byte
		for {
			if _, err := client.Read(byteBuffer[:]); err != nil {
				return
			}
		}
	}()

	var idleTimer *time.Timer
	var idleC <-chan time.Time
	if seconds := runtime.config.AssociationIdleTimeoutSecs; seconds > 0 {
		idleTimer = time.NewTimer(time.Duration(seconds) * time.Second)
		idleC = idleTimer.C
		defer idleTimer.Stop()
	}
	resetIdle := func() {
		if idleTimer == nil {
			return
		}
		if !idleTimer.Stop() {
			select {
			case <-idleTimer.C:
			default:
			}
		}
		idleTimer.Reset(time.Duration(runtime.config.AssociationIdleTimeoutSecs) * time.Second)
	}

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
		runtime.metrics.inPackets.Add(1)
		runtime.metrics.inBytes.Add(uint64(len(pkt.payload)))

		if pkt.dst.Socket != nil {
			target := netip.AddrPortFrom(pkt.dst.Socket.Addr().Unmap(), pkt.dst.Socket.Port())
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

		target := connect.FromHost(pkt.dst.Domain, pkt.dst.Port)
		if !runtime.dispatch(udpSendJob{
			associationID: associationID,
			ctx:           ctx,
			connector:     connector,
			packet:        pkt,
			target:        target,
			preferred:     preferredOutbound,
			fallback:      fallbackOutbound,
			errCh:         errCh,
		}) {
			runtime.releaseInboundPacket(pkt)
		}
		return true
	}

	for {
		select {
		case pkt := <-inboundPkt:
			// Drain the packets already queued by the inbound batch reader into a
			// single family-grouped send, bounded by BatchSize so no group can
			// exceed the writer's message array.
			active := processInbound(pkt)
		drain:
			for count := 1; count < runtime.config.BatchSize; count++ {
				select {
				case next := <-inboundPkt:
					if processInbound(next) {
						active = true
					}
				default:
					break drain
				}
			}
			flushBatch(preferredWriter, preferredOutbound, &preferredBatch)
			if fallbackWriter != nil {
				flushBatch(fallbackWriter, fallbackOutbound, &fallbackBatch)
			}
			if active {
				resetIdle()
			}

		case err := <-errCh:
			slog.Debug("SOCKS5 UDP proxy error", "error", err)

		case <-activityCh:
			resetIdle()

		case <-closedCh:
			slog.Debug("SOCKS5 UDP association closed", "address", listenAddr)
			return nil

		case <-idleC:
			slog.Debug("SOCKS5 UDP association idle timeout", "address", listenAddr)
			return nil

		case <-parentCtx.Done():
			return parentCtx.Err()
		}
	}
}

func relayUDPResponses(
	ctx context.Context,
	inbound, outbound *net.UDPConn,
	clientIP netip.Addr,
	clientPort *atomic.Uint32,
	runtime *udpRuntime,
	errCh chan<- error,
	activityCh chan<- struct{},
) {
	reader := newUDPBatchReader(
		outbound,
		runtime,
		proto.UdpHeaderMaxLen,
		runtime.config.MaxPacketSize-maxUDPResponseHeaderLen,
	)
	writer := newUDPBatchWriter(inbound, runtime.config.BatchSize)
	// Reused across iterations to keep the response hot path allocation-free;
	// bounded by the batch reader's per-Read packet count.
	writes := make([]udpWritePacket, 0, runtime.config.BatchSize)
	payloadBytes := make([]int, 0, runtime.config.BatchSize)
	for {
		packets, err := reader.Read()
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				runtime.metrics.errors.Add(1)
				reportUDPError(errCh, err)
			}
			return
		}
		clientAddr := netip.AddrPortFrom(clientIP, uint16(clientPort.Load()))
		writes = writes[:0]
		payloadBytes = payloadBytes[:0]
		for _, packet := range packets {
			if packet.truncated {
				runtime.metrics.truncatedDrops.Add(1)
				runtime.releaseReadPacket(packet)
				continue
			}
			if clientAddr.Port() == 0 {
				runtime.releaseReadPacket(packet)
				continue
			}
			payload := packet.buffer[proto.UdpHeaderMaxLen : proto.UdpHeaderMaxLen+packet.n]
			response := prepareUDPResponse(outboundPacket{
				payload: payload,
				buffer:  packet.buffer,
				remote:  net.UDPAddrFromAddrPort(packet.addr),
			})
			writes = append(writes, udpWritePacket{buffer: response, owner: packet.buffer, addr: clientAddr, batchSlot: packet.batchSlot})
			payloadBytes = append(payloadBytes, packet.n)
		}
		written, writeErr := writer.Write(writes)
		for i, write := range writes {
			if i < written {
				runtime.metrics.outPackets.Add(1)
				runtime.metrics.outBytes.Add(uint64(payloadBytes[i]))
			}
			// Every response is backed by one independently pooled buffer.
			runtime.releaseBuffer(write.owner, write.batchSlot)
		}
		if writeErr != nil || written != len(writes) {
			runtime.metrics.errors.Add(1)
			if writeErr == nil {
				writeErr = io.ErrShortWrite
			}
			reportUDPError(errCh, writeErr)
		}
		if written > 0 {
			select {
			case activityCh <- struct{}{}:
			default:
			}
		}
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
