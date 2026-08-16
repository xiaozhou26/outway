package server

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"net/netip"
	"sync"

	"github.com/xiaozhou26/outway/internal/connect"
	"github.com/xiaozhou26/outway/internal/server/socks"
)

type udpStatsProvider interface {
	UDPStats() socks.UDPStatsSnapshot
}

type diagnosticsServer struct {
	listener  net.Listener
	server    *http.Server
	metrics   any
	closeOnce sync.Once
	closeErr  error
}

func newDiagnosticsServer(bind netip.AddrPort, metrics any) (*diagnosticsServer, error) {
	if !bind.IsValid() || bind.Addr().IsUnspecified() {
		return nil, errors.New("diagnostics address must be a valid, non-wildcard IP endpoint")
	}
	network := "tcp4"
	if bind.Addr().Is6() {
		network = "tcp6"
	}
	listener, err := net.Listen(network, bind.String())
	if err != nil {
		return nil, fmt.Errorf("listen for diagnostics on %s: %w", bind, err)
	}

	d := &diagnosticsServer{listener: listener, metrics: metrics}
	mux := http.NewServeMux()
	mux.Handle("/metrics", http.HandlerFunc(d.serveMetrics))
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	d.server = &http.Server{Handler: mux}
	return d, nil
}

func (d *diagnosticsServer) Start() error {
	slog.Info("Diagnostics server listening", "address", d.listener.Addr())
	err := d.server.Serve(d.listener)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (d *diagnosticsServer) Close() error {
	d.closeOnce.Do(func() {
		serverErr := d.server.Close()
		if errors.Is(serverErr, http.ErrServerClosed) || errors.Is(serverErr, net.ErrClosed) {
			serverErr = nil
		}
		listenerErr := d.listener.Close()
		if errors.Is(listenerErr, net.ErrClosed) {
			listenerErr = nil
		}
		d.closeErr = errors.Join(serverErr, listenerErr)
	})
	return d.closeErr
}

func (d *diagnosticsServer) Addr() net.Addr {
	return d.listener.Addr()
}

func (d *diagnosticsServer) serveMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = io.WriteString(w, prometheusMetrics(d.metrics))
}

func prometheusMetrics(source any) string {
	dns := connect.DNSCacheStats()
	payload := fmt.Sprintf(`# HELP outway_dns_cache_hits_total Positive DNS cache hits.
# TYPE outway_dns_cache_hits_total counter
outway_dns_cache_hits_total %d
# HELP outway_dns_cache_negative_hits_total Negative DNS cache hits.
# TYPE outway_dns_cache_negative_hits_total counter
outway_dns_cache_negative_hits_total %d
# HELP outway_dns_cache_misses_total DNS cache misses requiring resolution.
# TYPE outway_dns_cache_misses_total counter
outway_dns_cache_misses_total %d
# HELP outway_dns_cache_expired_drops_total Expired DNS entries removed.
# TYPE outway_dns_cache_expired_drops_total counter
outway_dns_cache_expired_drops_total %d
# HELP outway_dns_cache_capacity_drops_total DNS entries evicted for capacity.
# TYPE outway_dns_cache_capacity_drops_total counter
outway_dns_cache_capacity_drops_total %d
# HELP outway_dns_cache_hit_ratio Fraction of lookups served from positive or negative cache entries.
# TYPE outway_dns_cache_hit_ratio gauge
outway_dns_cache_hit_ratio %.6f
`, dns.Hits, dns.NegativeHits, dns.Misses, dns.ExpiredDrops, dns.CapacityDrops, dns.HitRate())

	provider, ok := source.(udpStatsProvider)
	if !ok {
		return payload
	}
	udp := provider.UDPStats()
	return payload + fmt.Sprintf(`# HELP outway_socks5_udp_active_associations Current active SOCKS5 UDP associations.
# TYPE outway_socks5_udp_active_associations gauge
outway_socks5_udp_active_associations %d
# HELP outway_socks5_udp_associations_total SOCKS5 UDP associations accepted.
# TYPE outway_socks5_udp_associations_total counter
outway_socks5_udp_associations_total %d
# TYPE outway_socks5_udp_in_packets_total counter
outway_socks5_udp_in_packets_total %d
# TYPE outway_socks5_udp_in_bytes_total counter
outway_socks5_udp_in_bytes_total %d
# TYPE outway_socks5_udp_out_packets_total counter
outway_socks5_udp_out_packets_total %d
# TYPE outway_socks5_udp_out_bytes_total counter
outway_socks5_udp_out_bytes_total %d
# TYPE outway_socks5_udp_queue_drops_total counter
outway_socks5_udp_queue_drops_total %d
# TYPE outway_socks5_udp_queue_depth gauge
outway_socks5_udp_queue_depth %d
# TYPE outway_socks5_udp_queue_capacity gauge
outway_socks5_udp_queue_capacity %d
# TYPE outway_socks5_udp_truncated_drops_total counter
outway_socks5_udp_truncated_drops_total %d
# TYPE outway_socks5_udp_malformed_drops_total counter
outway_socks5_udp_malformed_drops_total %d
# TYPE outway_socks5_udp_fragment_drops_total counter
outway_socks5_udp_fragment_drops_total %d
# TYPE outway_socks5_udp_unauthorized_drops_total counter
outway_socks5_udp_unauthorized_drops_total %d
# TYPE outway_socks5_udp_association_limit_drops_total counter
outway_socks5_udp_association_limit_drops_total %d
# TYPE outway_socks5_udp_batch_fallbacks_total counter
outway_socks5_udp_batch_fallbacks_total %d
# TYPE outway_socks5_udp_gro_coalesced_reads_total counter
outway_socks5_udp_gro_coalesced_reads_total %d
# TYPE outway_socks5_udp_gro_truncated_reads_total counter
outway_socks5_udp_gro_truncated_reads_total %d
# TYPE outway_socks5_udp_batch_buffers_in_use gauge
outway_socks5_udp_batch_buffers_in_use %d
# TYPE outway_socks5_udp_batch_buffer_budget gauge
outway_socks5_udp_batch_buffer_budget %d
# TYPE outway_socks5_udp_errors_total counter
outway_socks5_udp_errors_total %d
`,
		udp.ActiveAssociations,
		udp.TotalAssociations,
		udp.InPackets,
		udp.InBytes,
		udp.OutPackets,
		udp.OutBytes,
		udp.QueueDrops,
		udp.QueueDepth,
		udp.QueueCapacity,
		udp.TruncatedDrops,
		udp.MalformedDrops,
		udp.FragmentDrops,
		udp.UnauthorizedDrops,
		udp.AssociationDrops,
		udp.BatchFallbacks,
		udp.GROCoalescedReads,
		udp.GROTruncatedReads,
		udp.BatchBuffersInUse,
		udp.BatchBufferBudget,
		udp.Errors,
	)
}
