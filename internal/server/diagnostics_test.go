package server

import (
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/xiaozhou26/outway/internal/server/socks"
)

type diagnosticsMetricsSource struct {
	stats socks.UDPStatsSnapshot
}

func (s diagnosticsMetricsSource) UDPStats() socks.UDPStatsSnapshot {
	return s.stats
}

func TestPrometheusMetricsIncludesUDPStats(t *testing.T) {
	source := diagnosticsMetricsSource{stats: socks.UDPStatsSnapshot{
		ActiveAssociations: 3,
		TotalAssociations:  7,
		QueueDepth:         2,
		QueueCapacity:      64,
		Errors:             5,
	}}
	metrics := prometheusMetrics(source)
	for _, want := range []string{
		"outway_dns_cache_hits_total ",
		"outway_dns_cache_hit_ratio ",
		"outway_socks5_udp_active_associations 3\n",
		"outway_socks5_udp_associations_total 7\n",
		"outway_socks5_udp_queue_depth 2\n",
		"outway_socks5_udp_queue_capacity 64\n",
		"outway_socks5_udp_errors_total 5\n",
	} {
		if !strings.Contains(metrics, want) {
			t.Fatalf("metrics output missing %q:\n%s", want, metrics)
		}
	}
}

func TestDiagnosticsServerServesMetricsAndPprof(t *testing.T) {
	bind := netip.MustParseAddrPort("127.0.0.1:0")
	diagnostics, err := newDiagnosticsServer(bind, diagnosticsMetricsSource{})
	if err != nil {
		t.Fatalf("new diagnostics server: %v", err)
	}

	serveDone := make(chan error, 1)
	go func() { serveDone <- diagnostics.Start() }()

	client := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{Proxy: nil},
	}
	baseURL := "http://" + diagnostics.Addr().String()
	for _, path := range []string{"/metrics", "/debug/pprof/"} {
		response, err := client.Get(baseURL + path)
		if err != nil {
			_ = diagnostics.Close()
			t.Fatalf("GET %s: %v", path, err)
		}
		body, readErr := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if readErr != nil {
			t.Fatalf("read %s: %v", path, readErr)
		}
		if closeErr != nil {
			t.Fatalf("close %s response: %v", path, closeErr)
		}
		if response.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status=%d body=%s", path, response.StatusCode, body)
		}
		if len(body) == 0 {
			t.Fatalf("GET %s returned an empty body", path)
		}
	}

	if err := diagnostics.Close(); err != nil {
		t.Fatalf("close diagnostics server: %v", err)
	}
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("diagnostics serve returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("diagnostics server did not stop after Close")
	}
}

func TestDiagnosticsServerRejectsWildcardAddress(t *testing.T) {
	bind := netip.MustParseAddrPort("0.0.0.0:0")
	if _, err := newDiagnosticsServer(bind, nil); err == nil {
		t.Fatal("expected wildcard diagnostics address to be rejected")
	}
}
