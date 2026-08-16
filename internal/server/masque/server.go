// Package masque implements an HTTP/3 CONNECT-UDP proxy as specified by
// RFC 9298. It uses the same authentication and outbound source selection as
// the TCP and SOCKS5 servers.
package masque

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	masquego "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"

	"github.com/xiaozhou26/outway/internal/config"
	"github.com/xiaozhou26/outway/internal/connect"
	"github.com/xiaozhou26/outway/internal/ext"
	httpsvr "github.com/xiaozhou26/outway/internal/server/http"
	"github.com/xiaozhou26/outway/internal/serverbase"
)

const proxyPath = "/.well-known/masque/udp/"

// Server serves MASQUE CONNECT-UDP tunnels over HTTP/3.
type Server struct {
	ctx      serverbase.Context
	server   *http3.Server
	template *uritemplate.Template
	limit    chan struct{}
	close    sync.Once

	mu           sync.Mutex
	closed       bool
	tunnels      map[*tunnel]struct{}
	tunnelsWG    sync.WaitGroup
	datagramBufs sync.Pool
}

// NewServer builds a MASQUE server. An empty certificate pair generates and
// persists a self-signed pair using the same state directory as HTTPS mode.
func NewServer(ctx serverbase.Context, certFile, keyFile string) (*Server, error) {
	if ctx.Concurrent == 0 {
		return nil, errors.New("MASQUE concurrent tunnel limit must be greater than zero")
	}
	cert, err := loadTLSCertificate(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	template, err := uritemplate.New(templateURL(ctx.Bind))
	if err != nil {
		return nil, fmt.Errorf("parse MASQUE URI template: %w", err)
	}

	s := &Server{
		ctx:      ctx,
		template: template,
		limit:    make(chan struct{}, ctx.Concurrent),
		tunnels:  make(map[*tunnel]struct{}),
	}
	s.datagramBufs.New = func() any {
		// One extra byte lets an over-limit packet be detected and dropped
		// instead of silently forwarded truncated.
		return make([]byte, len(contextIDZero)+ctx.UDP.MaxPacketSize+1)
	}
	mux := http.NewServeMux()
	mux.HandleFunc(proxyPath, s.handle)
	s.server = &http3.Server{
		Addr:            ctx.Bind.String(),
		Handler:         mux,
		TLSConfig:       http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}),
		QUICConfig:      &quic.Config{HandshakeIdleTimeout: time.Duration(ctx.ConnectTimeout) * time.Second},
		EnableDatagrams: true,
		Logger:          slog.Default(),
	}
	return s, nil
}

// Start listens on the configured UDP endpoint and blocks until closed.
func (s *Server) Start() error {
	err := s.server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// Close stops new HTTP/3 connections and immediately closes active tunnels.
func (s *Server) Close() error {
	var err error
	s.close.Do(func() {
		s.mu.Lock()
		s.closed = true
		tunnels := make([]*tunnel, 0, len(s.tunnels))
		for t := range s.tunnels {
			tunnels = append(tunnels, t)
		}
		s.mu.Unlock()
		for _, t := range tunnels {
			t.teardown()
		}
		s.tunnelsWG.Wait()
		err = s.server.Close()
	})
	return err
}

// closedQuietly reports whether the server is shutting down, so pump errors
// triggered by teardown are not logged.
func (s *Server) closedQuietly() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *Server) getDatagramBuffer() []byte {
	return s.datagramBufs.Get().([]byte)
}

func (s *Server) putDatagramBuffer(buf []byte) {
	s.datagramBufs.Put(buf)
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > 0 || r.Header.Get("Content-Length") != "" || r.Header.Get("Content-Type") != "" || r.Header.Get("Transfer-Encoding") != "" {
		http.Error(w, "CONNECT-UDP requests must not contain HTTP content fields", http.StatusBadRequest)
		return
	}
	extension, ok := authenticate(r, s.ctx.Auth)
	if !ok {
		w.Header().Set("Proxy-Authenticate", `Basic realm="outway"`)
		w.WriteHeader(http.StatusProxyAuthRequired)
		return
	}

	req, err := masquego.ParseProxyRequest(r, s.template)
	if err != nil {
		var parseErr *masquego.ProxyRequestParseError
		if errors.As(err, &parseErr) {
			w.WriteHeader(parseErr.HTTPStatus)
			return
		}
		http.Error(w, "invalid CONNECT-UDP request", http.StatusBadRequest)
		return
	}

	select {
	case s.limit <- struct{}{}:
		defer func() { <-s.limit }()
	default:
		w.Header().Set("Proxy-Status", `outway; error="connection_limit_reached"`)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	conn, err := s.connectUDP(r.Context(), req.Target, extension)
	if err != nil {
		slog.Debug("MASQUE UDP setup failed", "target", req.Target, "error", err)
		w.Header().Set("Proxy-Status", proxyStatus(err))
		w.WriteHeader(proxyErrorStatus(err))
		return
	}
	// serveTunnel owns conn from here and closes it before returning.
	s.serveTunnel(w, conn)
}

func (s *Server) connectUDP(ctx context.Context, target string, extension ext.Extension) (*net.UDPConn, error) {
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	portValue, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || portValue == 0 {
		return nil, &net.AddrError{Err: "invalid port", Addr: target}
	}
	conn, err := s.ctx.Connector.UDP(extension).Connect(ctx, connect.FromHost(host, uint16(portValue)))
	if err != nil {
		return nil, err
	}
	// Match the SOCKS5 path: outbound sockets get the configured kernel buffer
	// sizes so bursts are not dropped before the datagram pump reads them.
	connect.TuneUDPBuffers(conn, s.ctx.UDP.SocketBufferBytes)
	return conn, nil
}

func templateURL(bind netip.AddrPort) string {
	return "https://" + bind.String() + proxyPath + "{target_host}/{target_port}/"
}

func proxyStatus(err error) string {
	code := "destination_unavailable"
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		code = "dns_error"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		code = "dns_timeout"
	}
	return `outway; error="` + code + `"; details="` + strings.ReplaceAll(err.Error(), `"`, `'`) + `"`
}

func proxyErrorStatus(err error) int {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return http.StatusGatewayTimeout
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return http.StatusBadGateway
	}
	var addrErr *net.AddrError
	if errors.As(err, &addrErr) {
		return http.StatusBadRequest
	}
	return http.StatusServiceUnavailable
}

func authenticate(r *http.Request, auth config.AuthMode) (ext.Extension, bool) {
	if !auth.HasAuth() {
		return ext.Extension{}, true
	}
	value := r.Header.Get("Proxy-Authorization")
	// Decode the Basic credentials directly instead of cloning the request
	// into an Authorization header for Request.BasicAuth; the scheme match
	// and first-colon split mirror net/http's parseBasicAuth.
	const prefix = "Basic "
	if len(value) < len(prefix) || !strings.EqualFold(value[:len(prefix)], prefix) {
		return ext.None, false
	}
	credentials, err := base64.StdEncoding.DecodeString(value[len(prefix):])
	if err != nil {
		return ext.None, false
	}
	idx := bytes.IndexByte(credentials, ':')
	if idx < 0 {
		return ext.None, false
	}
	username := string(credentials[:idx])
	password := credentials[idx+1:]
	if !strings.HasPrefix(username, auth.Username) ||
		subtle.ConstantTimeCompare(password, []byte(auth.Password)) != 1 {
		return ext.None, false
	}
	return ext.TryFrom(auth.Username, username), true
}

func loadTLSCertificate(certFile, keyFile string) (tls.Certificate, error) {
	if certFile != "" && keyFile != "" {
		return tls.LoadX509KeyPair(certFile, keyFile)
	}
	certPEM, keyPEM, err := httpsvr.GetSelfSignedCert()
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}
