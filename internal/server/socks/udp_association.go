package socks

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xiaozhou26/outway/internal/connect"
	"github.com/xiaozhou26/outway/internal/server/socks/proto"
	"github.com/xiaozhou26/outway/internal/serverbase"
)

// udpAssociation carries the state of one SOCKS5 UDP ASSOCIATE relay. It
// splits what used to be a single 300-line handleUDP closure into named
// phases: setup, the inbound pump, and the TCP control loop.
//
// Reactor invariants preserved here (see CLAUDE.md):
//   - deregistration strictly precedes socket close (teardown order),
//   - a pump returning false is never re-armed,
//   - per-fd reg.mu stays the cross-worker memory barrier around handlers.
type udpAssociation struct {
	parentCtx     context.Context
	ctx           context.Context
	cancel        context.CancelFunc
	client        net.Conn
	connector     connect.UdpConnector
	runtime       *udpRuntime
	associationID uint64

	listenAddr netip.AddrPort
	inbound    *net.UDPConn
	preferred  *net.UDPConn
	fallback   *net.UDPConn
	srcIP      netip.Addr
	srcPort    atomic.Uint32
	errCh      chan error
	// lastActivity (unix nanos) is written by the reactor read handlers and read
	// by the control loop to enforce the optional idle timeout.
	lastActivity atomic.Int64

	reactor    *udpReactor
	useReactor bool
	reactorFds []int
	// serveWG tracks the fallback blocking read goroutines used off Linux.
	serveWG sync.WaitGroup

	inboundReader udpBatchReader

	// Request-direction batch senders, used only by the inbound pump goroutine.
	preferredWriter udpBatchWriter
	fallbackWriter  udpBatchWriter
	preferredV4     bool
	fallbackV4      bool
	batches         *udpBatchSlices
	responderSlices []*udpBatchSlices
	gsoEnabled      bool

	// batchInPackets/batchInBytes accumulate the inbound counts for one pump
	// batch; they flush with a single atomic add per batch instead of one per
	// datagram, cutting shared cache-line contention. The totals are identical.
	batchInPackets uint64
	batchInBytes   uint64
}

// setup binds the inbound socket, replies to the association request, and
// creates the outbound sockets. It owns the client connection on error.
func (a *udpAssociation) setup(address proto.Address) error {
	// Bind the inbound UDP socket on the same IP family as the TCP control
	// connection's local address.
	localIP := netip.IPv4Unspecified()
	if ap := serverbase.AddrPortOf(a.client.LocalAddr()); ap.IsValid() {
		localIP = ap.Addr()
	}
	inbound, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IP(localIP.AsSlice()), Port: 0})
	if err != nil {
		_ = proto.NewResponse(proto.ReplyGeneralFailure, proto.Unspecified()).MarshalTo(a.client)
		_ = a.client.Close()
		return err
	}
	connect.TuneUDPBuffers(inbound, a.runtime.config.SocketBufferBytes)
	a.inbound = inbound
	a.listenAddr = serverbase.AddrPortOf(inbound.LocalAddr())
	slog.Debug("SOCKS5 UDP association listening", "address", a.listenAddr)

	if err := proto.NewResponse(proto.ReplySucceeded, proto.SocketAddress(a.listenAddr)).MarshalTo(a.client); err != nil {
		_ = inbound.Close()
		_ = a.client.Close()
		return err
	}

	preferred, fallback, err := a.connector.CreateSocketDualStack(a.ctx)
	if err != nil {
		_ = inbound.Close()
		_ = a.client.Close()
		return err
	}
	a.preferred = preferred
	a.fallback = fallback
	connect.TuneUDPBuffers(preferred, a.runtime.config.SocketBufferBytes)
	connect.TuneUDPBuffers(fallback, a.runtime.config.SocketBufferBytes)

	// Determine the authorized source IP for UDP packets. If the client did not
	// specify a non-wildcard IP in the association request, default to the TCP
	// control connection's peer IP (RFC 1928 §7).
	if address.Socket != nil && !address.Socket.Addr().IsUnspecified() {
		a.srcIP = address.Socket.Addr()
	} else if ap := serverbase.AddrPortOf(a.client.RemoteAddr()); ap.IsValid() {
		a.srcIP = ap.Addr()
	} else {
		a.srcIP = netip.IPv4Unspecified()
	}

	// The inbound request socket and outbound response sockets are serviced by
	// the shared epoll reactor when available, so a busy association holds no
	// dedicated read goroutine; reactorFds records the registrations to tear
	// down (deregister waits for any in-flight handler) before the sockets are
	// closed.
	a.reactor, a.useReactor = a.runtime.sharedReactor()

	// Client->target packets that carry a literal IP target are grouped by
	// address family and flushed with one sendmmsg per outbound socket
	// (Linux); domain targets stay on the async worker path so a cold DNS
	// lookup never blocks the pump. Each writer is used only by the pump, so
	// it needs no synchronization.
	a.batches = a.runtime.getBatchSlices()
	a.preferredWriter = newUDPBatchWriter(preferred, a.runtime)
	a.preferredV4 = udpSocketIsV4(preferred)
	if fallback != nil {
		a.fallbackWriter = newUDPBatchWriter(fallback, a.runtime)
		a.fallbackV4 = udpSocketIsV4(fallback)
	}

	// When enabled and supported by the kernel, a batch that targets a single
	// destination with uniform-size datagrams is sent with one UDP_SEGMENT (GSO)
	// call instead of sendmmsg; anything else falls back to sendmmsg.
	a.gsoEnabled = a.runtime.config.GSO && udpGSOSupported()

	a.inboundReader = newUDPBatchReader(inbound, a.runtime, 0, a.runtime.config.MaxPacketSize)
	return nil
}

// teardown releases the association's sockets. Deregistration happens strictly
// before the closes so an in-flight reactor handler can never observe a closed
// fd; the fallback goroutines are joined last. Pooled arrays are returned only
// after every pump has stopped.
func (a *udpAssociation) teardown() {
	a.cancel()
	for _, fd := range a.reactorFds {
		a.reactor.deregister(fd)
	}
	_ = a.client.Close()
	_ = a.inbound.Close()
	_ = a.preferred.Close()
	if a.fallback != nil {
		_ = a.fallback.Close()
	}
	a.serveWG.Wait()

	a.preferredWriter.releaseTo(&a.runtime.writerPools)
	if a.fallbackWriter != nil {
		a.fallbackWriter.releaseTo(&a.runtime.writerPools)
	}
	a.runtime.putBatchSlices(a.batches)
	for _, slices := range a.responderSlices {
		a.runtime.putBatchSlices(slices)
	}
}

// handleUDP implements the SOCKS5 UDP ASSOCIATE command: relay UDP packets
// between the client and remote targets, with source-IP authorization.
func handleUDP(parentCtx context.Context, client net.Conn, address proto.Address, connector connect.UdpConnector, runtime *udpRuntime) error {
	associationID, opened := runtime.beginAssociation()
	if !opened {
		_ = proto.NewResponse(proto.ReplyConnectionNotAllowed, proto.Unspecified()).MarshalTo(client)
		return errors.New("SOCKS5 UDP association limit reached")
	}
	defer runtime.endAssociation()

	ctx, cancel := context.WithCancel(parentCtx)
	a := &udpAssociation{
		parentCtx:     parentCtx,
		ctx:           ctx,
		cancel:        cancel,
		client:        client,
		connector:     connector,
		runtime:       runtime,
		associationID: associationID,
		errCh:         make(chan error, 4),
	}
	a.lastActivity.Store(time.Now().UnixNano())

	if err := a.setup(address); err != nil {
		return err
	}
	defer a.teardown()

	a.startResponders()
	a.serveSocket(a.inbound, a.inboundPump)

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
			_ = client.SetReadDeadline(time.Unix(0, a.lastActivity.Load()).Add(idleTimeout))
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
			if time.Since(time.Unix(0, a.lastActivity.Load())) >= idleTimeout {
				slog.Debug("SOCKS5 UDP association idle timeout", "address", a.listenAddr)
				return nil
			}
			continue // activity happened; re-arm the deadline
		}
		slog.Debug("SOCKS5 UDP association closed", "address", a.listenAddr)
		return nil
	}
}

// flushBatch sends one accumulated family batch via GSO when eligible and
// sendmmsg otherwise, releasing every buffer the batch holds.
func (a *udpAssociation) flushBatch(writer udpBatchWriter, conn *net.UDPConn, batch *[]udpWritePacket) {
	if len(*batch) == 0 {
		return
	}
	var written int
	var writeErr error
	if gsoSize, ok := gsoEligible(a.gsoEnabled, *batch); ok {
		written, writeErr = sendUDPGSO(conn, *batch, gsoSize)
	} else {
		written, writeErr = writer.Write(*batch)
	}
	for _, write := range *batch {
		a.runtime.releaseBuffer(write.owner, write.batchSlot)
	}
	if writeErr != nil || written != len(*batch) {
		a.runtime.metrics.errors.Add(1)
		if writeErr == nil {
			writeErr = io.ErrShortWrite
		}
		reportUDPError(a.errCh, writeErr)
	}
	*batch = (*batch)[:0]
}

// processInbound applies the fragment/authorization checks and metrics to one
// client packet, then either queues a literal-IP target into its family batch
// or dispatches a domain target to a send worker. It returns true when the
// packet counts as association activity.
func (a *udpAssociation) processInbound(pkt inboundPacket) bool {
	if pkt.frag != 0 {
		if serverbase.DebugEnabled() {
			slog.Debug("[SOCKS5][UDP] packet fragment is not supported")
		}
		a.runtime.metrics.fragmentDrops.Add(1)
		a.runtime.releaseInboundPacket(pkt)
		return false
	}
	if !isAuthorized(pkt.src, a.srcIP) {
		if serverbase.DebugEnabled() {
			slog.Debug("SOCKS5 UDP packet from unauthorized IP", "source", pkt.src, "expected", a.srcIP)
		}
		a.runtime.metrics.unauthorizedDrops.Add(1)
		a.runtime.releaseInboundPacket(pkt)
		return false
	}
	a.srcPort.Store(uint32(pkt.src.Port()))
	a.batchInPackets++
	a.batchInBytes += uint64(len(pkt.payload))

	// Resolve the outbound target. Literal IPs and already-cached domains take
	// the fast batch path; an uncached domain is handed to a send worker that
	// resolves it off this loop, so a cold DNS lookup never stalls the batch.
	var target netip.AddrPort
	switch {
	case pkt.dst.Socket != nil:
		target = netip.AddrPortFrom(pkt.dst.Socket.Addr().Unmap(), pkt.dst.Socket.Port())
	default:
		resolved, ok := cachedTargetForFamily(pkt.dst.Domain, pkt.dst.Port, a.preferredV4, a.fallbackWriter != nil, a.fallbackV4)
		if !ok {
			if !a.runtime.dispatch(udpSendJob{
				associationID: a.associationID,
				ctx:           a.ctx,
				connector:     a.connector,
				packet:        pkt,
				target:        connect.FromHost(pkt.dst.Domain, pkt.dst.Port),
				preferred:     a.preferred,
				fallback:      a.fallback,
				errCh:         a.errCh,
			}) {
				a.runtime.releaseInboundPacket(pkt)
			}
			return true
		}
		target = resolved
	}

	batch := &a.batches.preferred
	if a.preferredV4 != target.Addr().Is4() && a.fallbackWriter != nil && a.fallbackV4 == target.Addr().Is4() {
		batch = &a.batches.fallback
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
// targets. The reactor calls it once per readable event; it returns false when
// the inbound socket is done (and must then not be re-armed).
func (a *udpAssociation) inboundPump() bool {
	packets, rerr := a.inboundReader.Read()
	if rerr != nil {
		if a.ctx.Err() == nil && !errors.Is(rerr, net.ErrClosed) {
			a.runtime.metrics.errors.Add(1)
			reportUDPError(a.errCh, rerr)
		}
		return false
	}
	active := false
	a.batchInPackets, a.batchInBytes = 0, 0
	for _, packet := range packets {
		if packet.truncated {
			a.runtime.metrics.truncatedDrops.Add(1)
			a.runtime.releaseReadPacket(packet)
			continue
		}
		hdr, hlen, herr := proto.ParseUdpHeader(packet.buffer.data[:packet.n])
		if herr != nil {
			a.runtime.metrics.malformedDrops.Add(1)
			a.runtime.releaseReadPacket(packet)
			continue
		}
		if a.processInbound(inboundPacket{
			payload:   packet.buffer.data[hlen:packet.n],
			buffer:    packet.buffer,
			frag:      hdr.Frag,
			dst:       hdr.Address,
			src:       packet.addr,
			batchSlot: packet.batchSlot,
		}) {
			active = true
		}
	}
	if a.batchInPackets > 0 {
		a.runtime.metrics.inPackets.Add(a.batchInPackets)
		a.runtime.metrics.inBytes.Add(a.batchInBytes)
	}
	a.flushBatch(a.preferredWriter, a.preferred, &a.batches.preferred)
	if a.fallbackWriter != nil {
		a.flushBatch(a.fallbackWriter, a.fallback, &a.batches.fallback)
	}
	if active {
		a.lastActivity.Store(time.Now().UnixNano())
	}
	return true
}

// serveSocket drives a socket's read side from the shared reactor when
// available (no per-association goroutine), else from a blocking goroutine.
func (a *udpAssociation) serveSocket(conn *net.UDPConn, pump func() bool) {
	if a.useReactor {
		if fd, ok := udpConnFd(conn); ok {
			handler := func() {
				if pump() {
					_ = a.reactor.rearm(fd)
				}
			}
			if a.reactor.register(fd, handler) == nil {
				a.reactorFds = append(a.reactorFds, fd)
				return
			}
		}
	}
	a.serveWG.Add(1)
	go func() {
		defer a.serveWG.Done()
		for pump() {
		}
	}()
}

// startResponders wires a responder for each outbound socket.
func (a *udpAssociation) startResponders() {
	startResponder := func(outbound *net.UDPConn) {
		slices := a.runtime.getBatchSlices()
		a.responderSlices = append(a.responderSlices, slices)
		responder := newUDPResponder(a.ctx, a.inbound, outbound, a.srcIP, &a.srcPort, a.runtime, a.errCh, &a.lastActivity, slices)
		a.serveSocket(outbound, responder.pumpOnce)
	}
	startResponder(a.preferred)
	if a.fallback != nil {
		startResponder(a.fallback)
	}
}
