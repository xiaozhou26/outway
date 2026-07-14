package serverbase

import (
	"context"
	"net"
	"testing"
)

func TestListenTCPShardsSinglePort(t *testing.T) {
	single, err := ListenTCPShards(context.Background(), "tcp4", "127.0.0.1:0", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(single) != 1 {
		t.Fatalf("shards=1 gave %d listeners, want 1", len(single))
	}
	single[0].Close()

	const shards = 4
	listeners, err := ListenTCPShards(context.Background(), "tcp4", "127.0.0.1:0", shards)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, ln := range listeners {
			_ = ln.Close()
		}
	}()

	if !reusePortSupported {
		if len(listeners) != 1 {
			t.Fatalf("without SO_REUSEPORT support, got %d listeners, want 1", len(listeners))
		}
		return
	}

	if len(listeners) != shards {
		t.Fatalf("got %d listeners, want %d", len(listeners), shards)
	}
	// All shards must share the same port for the kernel to load-balance.
	port := listeners[0].Addr().(*net.TCPAddr).Port
	for i, ln := range listeners {
		if got := ln.Addr().(*net.TCPAddr).Port; got != port {
			t.Fatalf("shard %d bound port %d, want shared %d", i, got, port)
		}
	}

	// A connection to the shared port must be accepted by some shard.
	type accepted struct {
		conn net.Conn
		err  error
	}
	results := make(chan accepted, shards)
	for _, ln := range listeners {
		go func(l net.Listener) {
			conn, err := l.Accept()
			results <- accepted{conn, err}
		}(ln)
	}
	client, err := net.Dial("tcp4", listeners[0].Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	got := <-results
	if got.err != nil {
		t.Fatalf("no shard accepted the connection: %v", got.err)
	}
	got.conn.Close()
}
