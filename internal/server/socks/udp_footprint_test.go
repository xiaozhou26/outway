package socks

import (
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/xiaozhou26/outway/internal/config"
	"github.com/xiaozhou26/outway/internal/connect"
	"github.com/xiaozhou26/outway/internal/server/socks/proto"
	"github.com/xiaozhou26/outway/internal/serverbase"
)

// TestUDPAssociationFootprint measures how many goroutines and how much stack
// memory each live UDP association costs. It is the baseline for the UDP reactor
// work: the current goroutine-per-socket model spends ~4 goroutines per
// association, and this test records that so later reactor stages can show the
// reduction. It logs the numbers and only fails if the per-association cost is
// implausibly high (a goroutine leak) — it does not pin the exact count, so it
// keeps passing as the reactor drives the count down.
func TestUDPAssociationFootprint(t *testing.T) {
	if testing.Short() {
		t.Skip("footprint measurement skipped in -short mode")
	}

	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	_ = echo.SetReadBuffer(4 << 20)
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, remote, err := echo.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			_, _ = echo.WriteToUDP(buffer[:n], remote)
		}
	}()

	proxy, err := NewServer(serverbase.Context{
		Bind:           netip.MustParseAddrPort("127.0.0.1:0"),
		Concurrent:     4096,
		ConnectTimeout: 10,
		Connector:      connect.New(nil, nil, nil, 10, nil, nil),
		UDP:            config.DefaultBootArgs().UDP,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	go func() { _ = proxy.Start() }()

	// Let the proxy's own goroutines (accept loop, send workers, metrics) settle
	// before taking the baseline so the delta is purely per-association cost.
	time.Sleep(200 * time.Millisecond)
	runtime.GC()
	baseGoroutines := runtime.NumGoroutine()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	const associations = 500
	const payloadSize = 200
	target := echo.LocalAddr().(*net.UDPAddr).AddrPort()
	live := make([]udpStressAssociation, 0, associations)
	response := make([]byte, 2048)
	for i := 0; i < associations; i++ {
		a, err := openSOCKS5UDPAssociation(proxy.listener.Addr().String())
		if err != nil {
			t.Fatalf("open association %d: %v", i, err)
		}
		live = append(live, a)
		// One round trip so the full relay (inbound reader, outbound reader, TCP
		// close watcher) is spawned and running for this association.
		_ = a.client.SetDeadline(time.Now().Add(5 * time.Second))
		payload := make([]byte, payloadSize)
		if _, err := a.client.WriteToUDP(proto.BuildUdpPacket(0, proto.SocketAddress(target), payload), a.relay); err != nil {
			t.Fatal(err)
		}
		if _, _, err := a.client.ReadFromUDP(response); err != nil {
			t.Fatalf("association %d round trip: %v", i, err)
		}
	}
	defer func() {
		for _, a := range live {
			_ = a.client.Close()
			_ = a.control.Close()
		}
	}()

	time.Sleep(300 * time.Millisecond)
	runtime.GC()
	peakGoroutines := runtime.NumGoroutine()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	goroutinesPerAssoc := float64(peakGoroutines-baseGoroutines) / associations
	stackBytesPerAssoc := (int64(after.StackInuse) - int64(before.StackInuse)) / associations
	t.Logf("UDP association footprint over %d associations: goroutines/assoc=%.2f  stack_bytes/assoc=%d  (goroutines %d→%d)",
		associations, goroutinesPerAssoc, stackBytesPerAssoc, baseGoroutines, peakGoroutines)

	if goroutinesPerAssoc > 8 {
		t.Fatalf("goroutines/assoc=%.2f is implausibly high — likely a goroutine leak", goroutinesPerAssoc)
	}
	if goroutinesPerAssoc < 0.5 {
		t.Fatalf("goroutines/assoc=%.2f is implausibly low — associations may not have started", goroutinesPerAssoc)
	}
}
