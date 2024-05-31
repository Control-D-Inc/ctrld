package cli

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"reflect"
	"sort"
	"time"

	"github.com/kardianos/service"

	dto "github.com/prometheus/client_model/go"

	"github.com/Control-D-Inc/ctrld"
)

const (
	contentTypeJson  = "application/json"
	listClientsPath  = "/clients"
	startedPath      = "/started"
	reloadPath       = "/reload"
	deactivationPath = "/deactivation"
	cdPath           = "/cd"
	ifacePath        = "/iface"
)

type controlServer struct {
	server *http.Server
	mux    *http.ServeMux
	addr   string
}

func newControlServer(addr string) (*controlServer, error) {
	mux := http.NewServeMux()
	s := &controlServer{
		server: &http.Server{Handler: mux},
		mux:    mux,
	}
	s.addr = addr
	return s, nil
}

func (s *controlServer) start() error {
	_ = os.Remove(s.addr)
	unixListener, err := net.Listen("unix", s.addr)
	if l, ok := unixListener.(*net.UnixListener); ok {
		l.SetUnlinkOnClose(true)
	}
	if err != nil {
		return err
	}
	go s.server.Serve(unixListener)
	return nil
}

func (s *controlServer) stop() error {
	_ = os.Remove(s.addr)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	return s.server.Shutdown(ctx)
}

func (s *controlServer) register(pattern string, handler http.Handler) {
	s.mux.Handle(pattern, jsonResponse(handler))
}

func (p *prog) registerControlServerHandler() {
	p.cs.register(listClientsPath, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		clients := p.ciTable.ListClients()
		sort.Slice(clients, func(i, j int) bool {
			return clients[i].IP.Less(clients[j].IP)
		})
		if p.cfg.Service.MetricsQueryStats {
			for _, client := range clients {
				client.IncludeQueryCount = true
				dm := &dto.Metric{}
				m, err := statsClientQueriesCount.MetricVec.GetMetricWithLabelValues(
					client.IP.String(),
					client.Mac,
					client.Hostname,
				)
				if err != nil {
					mainLog.Load().Debug().Err(err).Msgf("could not get metrics for client: %v", client)
					continue
				}
				if err := m.Write(dm); err == nil {
					client.QueryCount = int64(dm.Counter.GetValue())
				}
			}
		}

		if err := json.NewEncoder(w).Encode(&clients); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	p.cs.register(startedPath, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		select {
		case <-p.onStartedDone:
			w.WriteHeader(http.StatusOK)
		case <-time.After(10 * time.Second):
			w.WriteHeader(http.StatusRequestTimeout)
		}
	}))
	p.cs.register(reloadPath, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		listeners := make(map[string]*ctrld.ListenerConfig)
		p.mu.Lock()
		for k, v := range p.cfg.Listener {
			listeners[k] = &ctrld.ListenerConfig{
				IP:   v.IP,
				Port: v.Port,
			}
		}
		oldSvc := p.cfg.Service
		p.mu.Unlock()
		if err := p.sendReloadSignal(); err != nil {
			mainLog.Load().Err(err).Msg("could not send reload signal")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		select {
		case <-p.reloadDoneCh:
		case <-time.After(5 * time.Second):
			http.Error(w, "timeout waiting for ctrld reload", http.StatusInternalServerError)
			return
		}

		p.mu.Lock()
		defer p.mu.Unlock()

		// Checking for cases that we could not do a reload.

		// 1. Listener config ip or port changes.
		for k, v := range p.cfg.Listener {
			l := listeners[k]
			if l == nil || l.IP != v.IP || l.Port != v.Port {
				w.WriteHeader(http.StatusCreated)
				return
			}
		}

		// 2. Service config changes.
		if !reflect.DeepEqual(oldSvc, p.cfg.Service) {
			w.WriteHeader(http.StatusCreated)
			return
		}

		// Otherwise, reload is done.
		w.WriteHeader(http.StatusOK)
	}))
	p.cs.register(deactivationPath, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		// Non-cd mode or pin code not set, always allowing deactivation.
		if cdUID == "" || deactivationPinNotSet() {
			w.WriteHeader(http.StatusOK)
			return
		}

		var req deactivationRequest
		if err := json.NewDecoder(request.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusPreconditionFailed)
			mainLog.Load().Err(err).Msg("invalid deactivation request")
			return
		}

		code := http.StatusForbidden
		switch req.Pin {
		case cdDeactivationPin:
			code = http.StatusOK
		case defaultDeactivationPin:
			// If the pin code was set, but users do not provide --pin, return proper code to client.
			code = http.StatusBadRequest
		}
		w.WriteHeader(code)
	}))
	p.cs.register(cdPath, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if cdUID != "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	p.cs.register(ifacePath, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		// p.setDNS is only called when running as a service
		if !service.Interactive() {
			<-p.csSetDnsDone
			if p.csSetDnsOk {
				w.Write([]byte(iface))
				return
			}
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
}

func jsonResponse(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}
