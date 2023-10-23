package cli

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/Control-D-Inc/ctrld"
)

const (
	contentTypeJson = "application/json"
	listClientsPath = "/clients"
	startedPath     = "/started"
	reloadPath      = "/reload"
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
		for k, v := range p.cfg.Listener {
			l := listeners[k]
			if l == nil || l.IP != v.IP || l.Port != v.Port {
				w.WriteHeader(http.StatusCreated)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
}

func jsonResponse(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}
