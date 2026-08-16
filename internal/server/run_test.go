package server

import (
	"sync"
	"testing"
	"time"
)

type blockingTestService struct {
	started   chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
}

func newBlockingTestService() *blockingTestService {
	return &blockingTestService{
		started: make(chan struct{}),
		closed:  make(chan struct{}),
	}
}

func (s *blockingTestService) Start() error {
	close(s.started)
	<-s.closed
	return nil
}

func (s *blockingTestService) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

func TestServiceLifecycleClosesProxyAndDiagnostics(t *testing.T) {
	proxy := newBlockingTestService()
	diagnostics := newBlockingTestService()
	services := []namedService{
		{name: "proxy", server: proxy},
		{name: "diagnostics", server: diagnostics},
	}
	results := startServices(services)

	for name, started := range map[string]<-chan struct{}{
		"proxy":       proxy.started,
		"diagnostics": diagnostics.started,
	} {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatalf("%s service did not start", name)
		}
	}

	if err := closeServices(services); err != nil {
		t.Fatalf("close services: %v", err)
	}
	if err := waitServiceResults(results, len(services)); err != nil {
		t.Fatalf("wait for services: %v", err)
	}
}
