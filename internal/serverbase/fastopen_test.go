package serverbase

import (
	"context"
	"net"
	"testing"
)

// Fast Open must not break listening on any platform: it is applied on Linux
// and ignored with a warning elsewhere, and shards still share one port.
func TestListenTCPShardsWithFastOpenAccepts(t *testing.T) {
	listeners, err := ListenTCPShards(context.Background(), "tcp4", "127.0.0.1:0", AcceptShards(true), 16)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = CloseListeners(listeners[0], listeners[1:]) }()
	for _, ln := range listeners[1:] {
		if ln.Addr().String() != listeners[0].Addr().String() {
			t.Fatalf("shard bound %s, want %s", ln.Addr(), listeners[0].Addr())
		}
	}
	go func() {
		c, err := listeners[0].Accept()
		if err == nil {
			_ = c.Close()
		}
	}()
	if len(listeners) > 1 {
		// Another shard may receive the connection; accept on all of them.
		for _, ln := range listeners[1:] {
			go func(ln net.Listener) {
				if c, err := ln.Accept(); err == nil {
					_ = c.Close()
				}
			}(ln)
		}
	}
	c, err := net.Dial("tcp4", listeners[0].Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
}
