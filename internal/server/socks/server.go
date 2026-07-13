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
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xiaozhou26/outway/internal/connect"
	"github.com/xiaozhou26/outway/internal/ext"
	"github.com/xiaozhou26/outway/internal/server/socks/proto"
	"github.com/xiaozhou26/outway/internal/serverbase"
)

// MaxUDPRelayPacketSize is the maximum size of a SOCKS5 UDP relay packet.
const MaxUDPRelayPacketSize = 1500

const udpGlobalSendQueueSize = 4096

var udpPacketBufferPool = sync.Pool{
	New: func() any { return make([]byte, MaxUDPRelayPacketSize+proto.UdpHeaderMaxLen) },
}

var (
	udpDispatcherOnce      sync.Once
	udpSendShards          []chan udpSendJob
	udpDroppedPackets      atomic.Uint64
	udpAssociationSequence atomic.Uint64
)

// Socks5Acceptor handles a single accepted SOCKS5 connection.
type Socks5Acceptor struct {
	auth      AuthAdaptor
	connector *connect.Connector
	timeout   time.Duration
	ctx       context.Context
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
	}
}

// Accept drives a single SOCKS5 connection to completion.
func (a Socks5Acceptor) Accept(stream net.Conn, socketAddr netip.AddrPort) {
	defer stream.Close()
	if err := handle(a.ctx, NewIncomingConnection(stream, a.auth), socketAddr, a.connector, a.timeout); err != nil {
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
		s.closeErr = errors.Join(connectionErr, listenerErr, waitErr)
	})
	return s.closeErr
}

// handle authenticates the incoming connection, reads its request, and
// dispatches to the appropriate command handler.
func handle(ctx context.Context, conn IncomingConnection, socketAddr netip.AddrPort, connector *connect.Connector, timeout time.Duration) error {
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
		return handleUDP(ctx, stream, req.Address, connector.UDP(extension))
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
func handleUDP(parentCtx context.Context, client net.Conn, address proto.Address, connector *connect.UdpConnector) error {
	const bufSize = MaxUDPRelayPacketSize - proto.UdpHeaderMaxLen
	_ = bufSize

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
	defer inbound.Close()

	listenAddr, _ := netip.ParseAddrPort(inbound.LocalAddr().String())
	slog.Debug("SOCKS5 UDP association listening", "address", listenAddr)

	if err := proto.NewResponse(proto.ReplySucceeded, proto.SocketAddress(listenAddr)).MarshalTo(client); err != nil {
		_ = client.Close()
		return err
	}

	preferredOutbound, fallbackOutbound, err := connector.CreateSocketDualStack()
	if err != nil {
		_ = client.Close()
		return err
	}
	defer preferredOutbound.Close()
	if fallbackOutbound != nil {
		defer fallbackOutbound.Close()
	}

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
	defer cancel()
	associationID := udpAssociationSequence.Add(1)

	errCh := make(chan error, 4)

	// Inbound reader: reads SOCKS5 UDP relay packets from the client.
	inboundPkt := make(chan inboundPacket, 1)
	go func() {
		for {
			buf := udpPacketBufferPool.Get().([]byte)
			n, srcAddr, rerr := inbound.ReadFromUDP(buf[:MaxUDPRelayPacketSize])
			if rerr != nil {
				udpPacketBufferPool.Put(buf)
				reportUDPError(errCh, rerr)
				return
			}
			hdr, hlen, herr := proto.ReadUdpHeader(bytes.NewReader(buf[:n]))
			if herr != nil {
				udpPacketBufferPool.Put(buf)
				reportUDPError(errCh, herr)
				continue
			}
			pkt := inboundPacket{
				payload: buf[hlen:n],
				buffer:  buf,
				frag:    hdr.Frag,
				dst:     hdr.Address,
				src:     srcAddr,
			}
			select {
			case inboundPkt <- pkt:
			case <-ctx.Done():
				udpPacketBufferPool.Put(buf)
				return
			}
		}
	}()

	// Preferred outbound reader.
	prefPkt := make(chan outboundPacket, 1)
	go func() {
		for {
			buf := udpPacketBufferPool.Get().([]byte)
			n, remote, rerr := preferredOutbound.ReadFromUDP(buf[proto.UdpHeaderMaxLen:])
			if rerr != nil {
				udpPacketBufferPool.Put(buf)
				reportUDPError(errCh, rerr)
				return
			}
			pkt := outboundPacket{
				payload: buf[proto.UdpHeaderMaxLen : proto.UdpHeaderMaxLen+n],
				buffer:  buf,
				remote:  remote,
			}
			select {
			case prefPkt <- pkt:
			case <-ctx.Done():
				udpPacketBufferPool.Put(buf)
				return
			}
		}
	}()

	// Fallback outbound reader (may be nil).
	var fbPkt chan outboundPacket
	if fallbackOutbound != nil {
		fbPkt = make(chan outboundPacket, 1)
		go func() {
			for {
				buf := udpPacketBufferPool.Get().([]byte)
				n, remote, rerr := fallbackOutbound.ReadFromUDP(buf[proto.UdpHeaderMaxLen:])
				if rerr != nil {
					udpPacketBufferPool.Put(buf)
					reportUDPError(errCh, rerr)
					return
				}
				pkt := outboundPacket{
					payload: buf[proto.UdpHeaderMaxLen : proto.UdpHeaderMaxLen+n],
					buffer:  buf,
					remote:  remote,
				}
				select {
				case fbPkt <- pkt:
				case <-ctx.Done():
					udpPacketBufferPool.Put(buf)
					return
				}
			}
		}()
	}

	// TCP control-connection closer: signals when the client closes the TCP
	// connection, which terminates the UDP association.
	closedCh := make(chan struct{})
	go func() {
		buf := make([]byte, 1)
		for {
			if _, err := client.Read(buf); err != nil {
				close(closedCh)
				return
			}
		}
	}()

	for {
		select {
		case pkt := <-inboundPkt:
			if pkt.frag != 0 {
				slog.Debug("[SOCKS5][UDP] packet fragment is not supported")
				udpPacketBufferPool.Put(pkt.buffer)
				continue
			}
			if !isAuthorized(pkt.src.AddrPort(), srcIP) {
				slog.Debug("SOCKS5 UDP packet from unauthorized IP", "source", pkt.src, "expected", srcIP)
				udpPacketBufferPool.Put(pkt.buffer)
				continue
			}
			srcPort.Store(uint32(pkt.src.Port))

			var target connect.TargetAddr
			if pkt.dst.Socket != nil {
				target = connect.FromAddr(*pkt.dst.Socket)
			} else {
				target = connect.FromHost(pkt.dst.Domain, pkt.dst.Port)
			}
			if !dispatchUDPSend(udpSendJob{
				associationID: associationID,
				ctx:           ctx,
				connector:     connector,
				packet:        pkt,
				target:        target,
				preferred:     preferredOutbound,
				fallback:      fallbackOutbound,
				errCh:         errCh,
			}) {
				udpPacketBufferPool.Put(pkt.buffer)
				udpDroppedPackets.Add(1)
			}

		case pkt := <-prefPkt:
			port := uint16(srcPort.Load())
			srcAddr := netip.AddrPortFrom(srcIP, port)
			_ = writeUDPResponse(inbound, srcAddr, pkt)
			udpPacketBufferPool.Put(pkt.buffer)

		case pkt := <-fbPkt:
			port := uint16(srcPort.Load())
			srcAddr := netip.AddrPortFrom(srcIP, port)
			_ = writeUDPResponse(inbound, srcAddr, pkt)
			udpPacketBufferPool.Put(pkt.buffer)

		case err := <-errCh:
			slog.Debug("SOCKS5 UDP proxy error", "error", err)

		case <-closedCh:
			slog.Debug("SOCKS5 UDP association closed", "address", listenAddr)
			_ = client.Close()
			return nil
		}
	}
}

func writeUDPResponse(inbound *net.UDPConn, clientAddr netip.AddrPort, pkt outboundPacket) error {
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
		_, err := inbound.WriteToUDP(
			pkt.buffer[start:proto.UdpHeaderMaxLen+len(pkt.payload)],
			net.UDPAddrFromAddrPort(clientAddr),
		)
		return err
	}
	packet := proto.BuildUdpPacket(0, proto.SocketAddress(pkt.remote.AddrPort()), pkt.payload)
	_, err := inbound.WriteToUDP(packet, net.UDPAddrFromAddrPort(clientAddr))
	return err
}

// inboundPacket is a parsed SOCKS5 UDP relay packet from the client.
type inboundPacket struct {
	payload []byte
	buffer  []byte
	frag    uint8
	dst     proto.Address
	src     *net.UDPAddr
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

func dispatchUDPSend(job udpSendJob) bool {
	udpDispatcherOnce.Do(startUDPDispatcher)
	shard := udpSendShards[job.associationID%uint64(len(udpSendShards))]
	select {
	case shard <- job:
		return true
	default:
		return false
	}
}

func startUDPDispatcher() {
	workers := runtime.GOMAXPROCS(0) * 2
	if workers < 4 {
		workers = 4
	}
	if workers > 64 {
		workers = 64
	}
	queuePerShard := (udpGlobalSendQueueSize + workers - 1) / workers
	udpSendShards = make([]chan udpSendJob, workers)
	for index := range workers {
		jobs := make(chan udpSendJob, queuePerShard)
		udpSendShards[index] = jobs
		go func() {
			for job := range jobs {
				if job.ctx.Err() == nil {
					if _, err := job.connector.SendPacket(job.ctx, job.packet.payload, job.target, job.preferred, job.fallback); err != nil {
						reportUDPError(job.errCh, err)
					}
				}
				udpPacketBufferPool.Put(job.packet.buffer)
			}
		}()
	}
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if dropped := udpDroppedPackets.Swap(0); dropped > 0 {
				slog.Warn("SOCKS5 UDP packets dropped because send shards were full", "packets", dropped)
			}
		}
	}()
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

// Ensure imports are used.
var _ = io.EOF
var _ = ext.None
