// Package serverbase holds shared types and helpers used by the server package
// and its sub-packages (http, socks), breaking what would otherwise be an
// import cycle.
package serverbase

import (
	"io"
	"net"
	"net/netip"
	"sync"

	"github.com/xiaozhou26/outway/internal/config"
	"github.com/xiaozhou26/outway/internal/connect"
)

// Context holds all configuration and runtime state shared by the proxy
// servers.
type Context struct {
	Bind           netip.AddrPort
	Concurrent     uint32
	ConnectTimeout uint64
	Auth           config.AuthMode
	Connector      *connect.Connector
}

// CopyBidirectional copies data in both directions between two connections.
//
// On Linux, io.Copy uses splice(2) for TCP-to-TCP copies, providing
// kernel-space zero-copy behavior equivalent to the Rust realm_io
// bidi_zero_copy path. On other platforms it falls back to userspace copying.
//
// When one direction completes (EOF), the write side of the peer is half-closed
// so the EOF propagates cleanly to the remote.
func CopyBidirectional(a, b net.Conn) (int64, int64, error) {
	var n1, n2 int64
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n1, _ = io.Copy(b, a)
		_ = CloseWrite(b)
	}()

	go func() {
		defer wg.Done()
		n2, _ = io.Copy(a, b)
		_ = CloseWrite(a)
	}()

	wg.Wait()
	return n1, n2, nil
}

// CloseWrite half-closes the write side of a connection if the underlying type
// supports it.
func CloseWrite(c net.Conn) error {
	if tc, ok := c.(*net.TCPConn); ok {
		return tc.CloseWrite()
	}
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
