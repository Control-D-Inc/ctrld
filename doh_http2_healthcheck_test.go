package ctrld

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// freezableProxy forwards TCP traffic between the client and target until
// freeze is called. After that it stops relaying server-to-client bytes while
// still draining the client side, so the client sees a silent peer and only
// its own HTTP/2 health check can notice. clientClosed is closed when the
// client side of the connection ends.
type freezableProxy struct {
	ln           net.Listener
	target       string
	mu           sync.Mutex
	frozen       bool
	clientClosed chan struct{}
	once         sync.Once
}

func newFreezableProxy(t *testing.T, target string) *freezableProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &freezableProxy{ln: ln, target: target, clientClosed: make(chan struct{})}
	t.Cleanup(func() { ln.Close() })
	go p.serve()
	return p
}

func (p *freezableProxy) isFrozen() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.frozen
}

func (p *freezableProxy) freeze() {
	p.mu.Lock()
	p.frozen = true
	p.mu.Unlock()
}

func (p *freezableProxy) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handle(c)
	}
}

func (p *freezableProxy) handle(client net.Conn) {
	defer client.Close()
	server, err := net.Dial("tcp", p.target)
	if err != nil {
		return
	}
	defer server.Close()
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := server.Read(buf)
			if err != nil {
				return
			}
			if p.isFrozen() {
				continue
			}
			if _, err := client.Write(buf[:n]); err != nil {
				return
			}
		}
	}()
	buf := make([]byte, 32*1024)
	for {
		n, err := client.Read(buf)
		if err != nil {
			if p.isFrozen() {
				p.once.Do(func() { close(p.clientClosed) })
			}
			return
		}
		if p.isFrozen() {
			continue
		}
		if _, err := server.Write(buf[:n]); err != nil {
			return
		}
	}
}

// TestDoHTransport_HTTP2HealthCheckClosesSilentConnection verifies that the
// DoH transport negotiates HTTP/2 and that its HTTP/2 health check closes a
// connection whose peer stops answering, so a wedged connection is not kept
// in the pool (https://github.com/golang/go/issues/36026).
func TestDoHTransport_HTTP2HealthCheckClosesSilentConnection(t *testing.T) {
	oldSend, oldPing := dohSendPingTimeout, dohPingTimeout
	dohSendPingTimeout, dohPingTimeout = 200*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { dohSendPingTimeout, dohPingTimeout = oldSend, oldPing })

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	testCert := generateTestCertificate(t)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{testCert.tlsCert},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)

	proxy := newFreezableProxy(t, srv.Listener.Addr().String())
	_, port, _ := net.SplitHostPort(proxy.ln.Addr().String())

	uc := dohUpstreamForTLSServer(t, srv)
	uc.Endpoint = "https://127.0.0.1:" + port + "/dns-query"
	uc.BootstrapIP = "127.0.0.1"
	uc.SetupTransport(context.Background())
	t.Cleanup(uc.transport.CloseIdleConnections)

	if uc.transport.HTTP2 == nil {
		t.Fatal("DoH transport has no HTTP/2 config")
	}

	resp, err := uc.transport.RoundTrip(mustNewRequest(t, uc.Endpoint))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatalf("DoH transport negotiated HTTP/%d, want HTTP/2", resp.ProtoMajor)
	}

	proxy.freeze()

	select {
	case <-proxy.clientClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("DoH transport kept a silent HTTP/2 connection open: the health check PING did not close it")
	}
}

func mustNewRequest(t *testing.T, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}
