package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"time"
)

const contentTypeJson = "application/json"

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
	// TODO: register handler here.
}

func jsonResponse(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}
