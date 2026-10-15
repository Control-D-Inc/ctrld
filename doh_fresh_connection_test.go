package ctrld

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// staleConnProxy forwards TCP connections to target. Connections it accepted
// before staleExisting stop relaying, as connections opened before a sleep or
// on the previous network do; later connections work.
type staleConnProxy struct {
	ln     net.Listener
	target string
	mu     sync.Mutex
	conns  map[net.Conn]bool // accepted connection -> stale
}

func newStaleConnProxy(t *testing.T, target string) *staleConnProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &staleConnProxy{ln: ln, target: target, conns: map[net.Conn]bool{}}
	t.Cleanup(func() {
		ln.Close()
		p.mu.Lock()
		defer p.mu.Unlock()
		for c := range p.conns {
			c.Close()
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			p.mu.Lock()
			p.conns[c] = false
			p.mu.Unlock()
			go p.relay(c)
		}
	}()
	return p
}

func (p *staleConnProxy) staleExisting() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for c := range p.conns {
		p.conns[c] = true
	}
}

func (p *staleConnProxy) stale(c net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.conns[c]
}

func (p *staleConnProxy) relay(client net.Conn) {
	defer client.Close()
	server, err := net.Dial("tcp", p.target)
	if err != nil {
		return
	}
	defer server.Close()
	pipe := func(dst, src net.Conn) {
		buf := make([]byte, 32*1024)
		for {
			n, err := src.Read(buf)
			if err != nil {
				return
			}
			if p.stale(client) {
				continue
			}
			if _, err := dst.Write(buf[:n]); err != nil {
				return
			}
		}
	}
	go pipe(client, server)
	pipe(server, client)
}

// dnsAnsweringHandler answers every DoH GET with an empty NOERROR reply.
func dnsAnsweringHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(data); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		answer := new(dns.Msg)
		answer.SetReply(msg)
		out, _ := answer.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	})
}

// A query on a connection that went stale times out, and after ReBootstrap the
// next query opens a new connection and is answered: the retry on fresh
// connections that ctrld makes after a sleep or a network change (#631)
// depends on it.
func TestDoHReBootstrapReplacesStaleConnection(t *testing.T) {
	srv := httptest.NewUnstartedServer(dnsAnsweringHandler())
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{generateTestCertificate(t).tlsCert},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	proxy := newStaleConnProxy(t, srv.Listener.Addr().String())
	_, port, _ := net.SplitHostPort(proxy.ln.Addr().String())
	uc := dohUpstreamForTLSServer(t, srv)
	uc.Endpoint = "https://127.0.0.1:" + port + "/dns-query"
	uc.Init(context.Background())
	uc.BootstrapIP = "127.0.0.1"

	resolve := func() error {
		r, err := NewResolver(context.Background(), uc)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		msg := new(dns.Msg)
		msg.SetQuestion("time.apple.com.", dns.TypeA)
		_, err = r.Resolve(ctx, msg)
		return err
	}

	if err := resolve(); err != nil {
		t.Fatalf("first query: %v", err)
	}
	proxy.staleExisting()
	if err := resolve(); err == nil {
		t.Fatal("query on the stale connection succeeded; the test does not reproduce a dead connection")
	}
	uc.ReBootstrap(context.Background())
	if err := resolve(); err != nil {
		t.Fatalf("query after ReBootstrap: %v", err)
	}
}
