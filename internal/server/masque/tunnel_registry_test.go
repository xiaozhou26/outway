package masque

import (
	"sync"
	"testing"
	"time"
)

func TestTunnelRegistryCloseAllAndWait(t *testing.T) {
	registry := newTunnelRegistry()
	tunnels := []*tunnel{{}, {}, {}}
	for _, tunnel := range tunnels {
		if !registry.Add(tunnel) {
			t.Fatal("active registry rejected tunnel")
		}
	}

	snapshot := registry.CloseAll()
	if len(snapshot) != len(tunnels) {
		t.Fatalf("CloseAll snapshot length = %d, want %d", len(snapshot), len(tunnels))
	}
	if registry.Add(&tunnel{}) {
		t.Fatal("closed registry accepted tunnel")
	}

	waitDone := make(chan struct{})
	go func() {
		registry.Wait()
		close(waitDone)
	}()
	select {
	case <-waitDone:
		t.Fatal("Wait returned before registered tunnels were removed")
	case <-time.After(20 * time.Millisecond):
	}

	for _, tunnel := range tunnels {
		registry.Remove(tunnel)
	}
	select {
	case <-waitDone:
	case <-time.After(time.Second):
		t.Fatal("Wait did not return after all tunnels were removed")
	}
}

func TestTunnelRegistryConcurrentCloseRejectsLateAdds(t *testing.T) {
	registry := newTunnelRegistry()
	const workers = 64
	start := make(chan struct{})
	var wg sync.WaitGroup
	accepted := make(chan *tunnel, workers)
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			<-start
			tunnel := &tunnel{}
			if registry.Add(tunnel) {
				accepted <- tunnel
			}
		}()
	}
	close(start)
	snapshot := registry.CloseAll()
	wg.Wait()
	close(accepted)

	registered := make(map[*tunnel]struct{}, len(snapshot))
	for _, tunnel := range snapshot {
		registered[tunnel] = struct{}{}
	}
	for tunnel := range accepted {
		if _, ok := registered[tunnel]; !ok {
			t.Fatal("accepted tunnel missing from CloseAll snapshot")
		}
		registry.Remove(tunnel)
	}
	registry.Wait()
}
