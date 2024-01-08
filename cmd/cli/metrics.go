package cli

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/prom2json"
)

// metricsServer represents a server to expose Prometheus metrics via HTTP.
type metricsServer struct {
	server  *http.Server
	mux     *http.ServeMux
	reg     *prometheus.Registry
	addr    string
	started bool
}

// newMetricsServer returns new metrics server.
func newMetricsServer(addr string, reg *prometheus.Registry) (*metricsServer, error) {
	mux := http.NewServeMux()
	ms := &metricsServer{
		server: &http.Server{Handler: mux},
		mux:    mux,
		reg:    reg,
	}
	ms.addr = addr
	ms.registerMetricsServerHandler()
	return ms, nil
}

// register adds handlers for given pattern.
func (ms *metricsServer) register(pattern string, handler http.Handler) {
	ms.mux.Handle(pattern, handler)
}

// registerMetricsServerHandler adds handlers for metrics server.
func (ms *metricsServer) registerMetricsServerHandler() {
	ms.register("/metrics", promhttp.HandlerFor(
		ms.reg,
		promhttp.HandlerOpts{
			EnableOpenMetrics: true,
			Timeout:           10 * time.Second,
		},
	))
	ms.register("/metrics/json", jsonResponse(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g := prometheus.ToTransactionalGatherer(ms.reg)
		mfs, done, err := g.Gather()
		defer done()
		if err != nil {
			msg := "could not gather metrics"
			mainLog.Load().Warn().Err(err).Msg(msg)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}
		result := make([]*prom2json.Family, 0, len(mfs))
		for _, mf := range mfs {
			result = append(result, prom2json.NewFamily(mf))
		}
		if err := json.NewEncoder(w).Encode(result); err != nil {
			msg := "could not marshal metrics result"
			mainLog.Load().Warn().Err(err).Msg(msg)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}
	})))
}

// start runs the metricsServer.
func (ms *metricsServer) start() error {
	listener, err := net.Listen("tcp", ms.addr)
	if err != nil {
		return err
	}
	go ms.server.Serve(listener)
	ms.started = true
	return nil
}

// stop shutdowns the metricsServer within 2 seconds timeout.
func (ms *metricsServer) stop() error {
	if !ms.started {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*1)
	defer cancel()
	return ms.server.Shutdown(ctx)
}

// runMetricsServer initializes metrics stats and runs the metrics server if enabled.
func (p *prog) runMetricsServer(ctx context.Context, reloadCh chan struct{}) {
	if !p.metricsEnabled() {
		return
	}

	// Reset all stats.
	statsVersion.Reset()
	statsQueriesCount.Reset()
	statsClientQueriesCount.Reset()

	reg := prometheus.NewRegistry()
	// Register queries count stats if enabled.
	if cfg.Service.MetricsQueryStats {
		reg.MustRegister(statsQueriesCount)
		reg.MustRegister(statsClientQueriesCount)
	}

	addr := p.cfg.Service.MetricsListener
	ms, err := newMetricsServer(addr, reg)
	if err != nil {
		mainLog.Load().Warn().Err(err).Msg("could not create new metrics server")
		return
	}
	// Only start listener address if defined.
	if addr != "" {
		// Go runtime stats.
		reg.MustRegister(collectors.NewBuildInfoCollector())
		reg.MustRegister(collectors.NewGoCollector(
			collectors.WithGoCollectorRuntimeMetrics(collectors.MetricsAll),
		))
		// ctrld stats.
		reg.MustRegister(statsVersion)
		statsVersion.WithLabelValues(commit, runtime.Version(), curVersion()).Inc()
		reg.MustRegister(statsTimeStart)
		statsTimeStart.Set(float64(time.Now().Unix()))
		mainLog.Load().Debug().Msgf("starting metrics server on: %s", addr)
		if err := ms.start(); err != nil {
			mainLog.Load().Warn().Err(err).Msg("could not start metrics server")
			return
		}
	}

	select {
	case <-p.stopCh:
	case <-ctx.Done():
	case <-reloadCh:
	}

	if err := ms.stop(); err != nil {
		mainLog.Load().Warn().Err(err).Msg("could not stop metrics server")
		return
	}
}
