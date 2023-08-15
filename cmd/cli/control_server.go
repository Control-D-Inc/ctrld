package cli

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"sort"
	"time"
)

const (
	contentTypeJson = "application/json"
	listClientsPath = "/clients"
	startedPath     = "/started"
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
}

func jsonResponse(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}
