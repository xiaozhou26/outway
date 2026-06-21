// Package socks implements the SOCKS5 proxy server, including the acceptor,
// connection handler, and the CONNECT / UDP ASSOCIATE / BIND command handlers.
package socks

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/xiaozhou26/outway/internal/connect"
	"github.com/xiaozhou26/outway/internal/ext"
	"github.com/xiaozhou26/outway/internal/serverbase"
	"github.com/xiaozhou26/outway/internal/server/socks/proto"
)

// MaxUDPRelayPacketSize is the maximum size of a SOCKS5 UDP relay packet.
const MaxUDPRelayPacketSize = 1500

// Socks5Acceptor handles a single accepted SOCKS5 connection.
type Socks5Acceptor struct {
	auth      AuthAdaptor
	connector *connect.Connector
}

// NewAcceptor builds a Socks5Acceptor from a server Context.
func NewAcceptor(ctx serverbase.Context) Socks5Acceptor {
	var auth AuthAdaptor
	if ctx.Auth.HasAuth() {
		auth = PasswordConfig(ctx.Auth.Username, ctx.Auth.Password)
	} else {
		auth = NoAuthConfig()
	}
	return Socks5Acceptor{auth: auth, connector: ctx.Connector}
}

// Accept drives a single SOCKS5 connection to completion.
func (a Socks5Acceptor) Accept(stream net.Conn, socketAddr netip.AddrPort) {
	if err := handle(NewIncomingConnection(stream, a.auth), socketAddr, a.connector); err != nil {
		slog.Debug(fmt.Sprintf("[SOCKS5] error: %v", err))
	}
}

// Socks5Server listens for SOCKS5 connections and dispatches them to acceptors.
type Socks5Server struct {
	listener net.Listener
	acceptor Socks5Acceptor
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
	return &Socks5Server{listener: ln, acceptor: NewAcceptor(ctx)}, nil
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
			slog.Debug(fmt.Sprintf("Failed to accept connection: %v", err))
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
		}
		var peer netip.AddrPort
		if ra, rerr := netip.ParseAddrPort(conn.RemoteAddr().String()); rerr == nil {
			peer = ra
		}
		acceptor := s.acceptor
		go acceptor.Accept(conn, peer)
	}
}

// Close stops the listener.
func (s *Socks5Server) Close() error { return s.listener.Close() }

// handle authenticates the incoming connection, reads its request, and
// dispatches to the appropriate command handler.
func handle(conn IncomingConnection, socketAddr netip.AddrPort, connector *connect.Connector) error {
	stream, extension, err := conn.Authenticate()
	if err != nil {
		if err == errNoAcceptableMethods {
			return nil
		}
		if stream != nil {
			slog.Debug(fmt.Sprintf("[SOCKS5] authentication failed: %v, closing connection from %s", err, socketAddr))
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

	switch req.Command {
	case proto.CmdUDPAssociate:
		return handleUDP(stream, req.Address, connector.UDP(extension))
	case proto.CmdConnect:
		return handleConnect(stream, req.Address, connector.TCP(extension))
	case proto.CmdBind:
		return handleBind(stream, req.Address, connector.TCP(extension))
	default:
		_ = proto.NewResponse(proto.ReplyCommandNotSupported, proto.Unspecified()).MarshalTo(stream)
		_ = stream.Close()
		return fmt.Errorf("unsupported command %#x", req.Command)
	}
}

// handleConnect implements the SOCKS5 CONNECT command: establish a TCP tunnel
// between the client and the target.
func handleConnect(client net.Conn, address proto.Address, connector *connect.TcpConnector) error {
	var outbound *net.TCPConn
	var dialErr error

	if address.Socket != nil {
		ap := *address.Socket
		slog.Info(fmt.Sprintf("[SOCKS5][CONNECT] %s -> %s forwarding connection", client.RemoteAddr(), ap))
		outbound, dialErr = connector.Connect(context.Background(), connect.FromAddr(ap))
	} else {
		slog.Info(fmt.Sprintf("[SOCKS5][CONNECT] %s -> %s:%d forwarding connection", client.RemoteAddr(), address.Domain, address.Port))
		outbound, dialErr = connector.Connect(context.Background(), connect.FromHost(address.Domain, address.Port))
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

	fromClient, fromServer, _ := serverbase.CopyBidirectional(client, outbound)
	slog.Info(fmt.Sprintf("[SOCKS5][CONNECT] client wrote %d bytes and received %d bytes", fromClient, fromServer))
	_ = outbound.CloseWrite()
	_ = outbound.Close()
	_ = serverbase.CloseWrite(client)
	_ = client.Close()
	return nil
}

// handleBind implements the SOCKS5 BIND command: listen for an inbound
// connection from the target and forward data between client and target.
func handleBind(client net.Conn, _ proto.Address, connector *connect.TcpConnector) error {
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
	slog.Info(fmt.Sprintf("[SOCKS5][BIND] listening on %s", ln.Addr()))

	bndAddr, _ := netip.ParseAddrPort(ln.Addr().String())
	if err := proto.NewResponse(proto.ReplySucceeded, proto.SocketAddress(bndAddr)).MarshalTo(client); err != nil {
		_ = client.Close()
		return err
	}

	outbound, err := ln.AcceptTCP()
	if err != nil {
		_ = proto.NewResponse(proto.ReplyGeneralFailure, proto.Unspecified()).MarshalTo(client)
		_ = client.Close()
		return err
	}
	defer outbound.Close()
	slog.Info(fmt.Sprintf("[SOCKS5][BIND] accepted connection from %s", outbound.RemoteAddr()))

	outboundAddr, _ := netip.ParseAddrPort(outbound.RemoteAddr().String())
	if err := proto.NewResponse(proto.ReplySucceeded, proto.SocketAddress(outboundAddr)).MarshalTo(client); err != nil {
		_ = client.Close()
		return err
	}

	fromClient, fromServer, _ := serverbase.CopyBidirectional(client, outbound)
	slog.Info(fmt.Sprintf("[SOCKS5][BIND] client wrote %d bytes and received %d bytes", fromClient, fromServer))
	_ = serverbase.CloseWrite(client)
	_ = outbound.CloseWrite()
	_ = client.Close()
	return nil
}

// handleUDP implements the SOCKS5 UDP ASSOCIATE command: relay UDP packets
// between the client and remote targets, with source-IP authorization.
func handleUDP(client net.Conn, address proto.Address, connector *connect.UdpConnector) error {
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
	slog.Info(fmt.Sprintf("[SOCKS5][UDP] listening on: %s", listenAddr))

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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 4)

	// Inbound reader: reads SOCKS5 UDP relay packets from the client.
	inboundPkt := make(chan inboundPacket, 1)
	go func() {
		for {
			buf := make([]byte, MaxUDPRelayPacketSize)
			n, srcAddr, rerr := inbound.ReadFromUDP(buf)
			if rerr != nil {
				errCh <- rerr
				return
			}
			hdr, hlen, herr := proto.ReadUdpHeader(bytes.NewReader(buf[:n]))
			if herr != nil {
				errCh <- herr
				continue
			}
			inboundPkt <- inboundPacket{
				payload: buf[hlen:n],
				frag:    hdr.Frag,
				dst:     hdr.Address,
				src:     srcAddr,
			}
		}
	}()

	// Preferred outbound reader.
	prefPkt := make(chan outboundPacket, 1)
	go func() {
		buf := make([]byte, MaxUDPRelayPacketSize)
		for {
			n, remote, rerr := preferredOutbound.ReadFromUDP(buf)
			if rerr != nil {
				errCh <- rerr
				return
			}
			cp := make([]byte, n)
			copy(cp, buf[:n])
			prefPkt <- outboundPacket{payload: cp, remote: remote}
		}
	}()

	// Fallback outbound reader (may be nil).
	var fbPkt chan outboundPacket
	if fallbackOutbound != nil {
		fbPkt = make(chan outboundPacket, 1)
		go func() {
			buf := make([]byte, MaxUDPRelayPacketSize)
			for {
				n, remote, rerr := fallbackOutbound.ReadFromUDP(buf)
				if rerr != nil {
					errCh <- rerr
					return
				}
				cp := make([]byte, n)
				copy(cp, buf[:n])
				fbPkt <- outboundPacket{payload: cp, remote: remote}
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
				continue
			}
			if !isAuthorized(pkt.src.AddrPort(), srcIP) {
				slog.Debug(fmt.Sprintf("[SOCKS5][UDP] packet from unauthorized IP: %s, expected: %s. Dropped.", pkt.src, srcIP))
				continue
			}
			srcPort.Store(uint32(pkt.src.Port))

			var target connect.TargetAddr
			if pkt.dst.Socket != nil {
				target = connect.FromAddr(*pkt.dst.Socket)
				slog.Info(fmt.Sprintf("[SOCKS5][UDP] %s -> %s forwarding packet, size %d", pkt.src, *pkt.dst.Socket, len(pkt.payload)))
			} else {
				target = connect.FromHost(pkt.dst.Domain, pkt.dst.Port)
				slog.Info(fmt.Sprintf("[SOCKS5][UDP] %s -> %s:%d forwarding packet, size %d", pkt.src, pkt.dst.Domain, pkt.dst.Port, len(pkt.payload)))
			}
			go func() {
				if _, e := connector.SendPacket(ctx, pkt.payload, target, preferredOutbound, fallbackOutbound); e != nil {
					errCh <- e
				}
			}()

		case pkt := <-prefPkt:
			port := uint16(srcPort.Load())
			srcAddr := netip.AddrPortFrom(srcIP, port)
			slog.Info(fmt.Sprintf("[SOCKS5][UDP] %s <- %s feedback to incoming, packet size %d", srcAddr, pkt.remote, len(pkt.payload)))
			packet := proto.BuildUdpPacket(0, proto.SocketAddress(pkt.remote.AddrPort()), pkt.payload)
			_, _ = inbound.WriteToUDP(packet, pkt.remote)

		case pkt := <-fbPkt:
			port := uint16(srcPort.Load())
			srcAddr := netip.AddrPortFrom(srcIP, port)
			slog.Info(fmt.Sprintf("[SOCKS5][UDP] %s <- %s feedback to incoming, packet size %d", srcAddr, pkt.remote, len(pkt.payload)))
			packet := proto.BuildUdpPacket(0, proto.SocketAddress(pkt.remote.AddrPort()), pkt.payload)
			_, _ = inbound.WriteToUDP(packet, pkt.remote)

		case err := <-errCh:
			slog.Debug(fmt.Sprintf("[SOCKS5][UDP] proxy error: %v", err))

		case <-closedCh:
			slog.Info(fmt.Sprintf("[SOCKS5][UDP] %s listener closed", listenAddr))
			_ = client.Close()
			return nil
		}
	}
}

// inboundPacket is a parsed SOCKS5 UDP relay packet from the client.
type inboundPacket struct {
	payload []byte
	frag    uint8
	dst     proto.Address
	src     *net.UDPAddr
}

// outboundPacket is a UDP packet received from a remote target.
type outboundPacket struct {
	payload []byte
	remote  *net.UDPAddr
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

// Ensure imports are used.
var _ = io.EOF
var _ = ext.None
