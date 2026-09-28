package ctrld

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go/http3"
)

func retirementWait(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// One real TLS connection, with the response optionally held until release.
// Cleanup joins the server goroutine and never touches host DNS or global state.
func retirementDOTServer(t *testing.T, hold bool) (*UpstreamConfig, <-chan struct{}, func(), <-chan struct{}) {
	t.Helper()
	cert := generateTestCertificate(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert.tlsCert}})
	if err != nil {
		t.Fatal(err)
	}
	entered, release, peerClosed, done := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	if !hold {
		unblock()
	}
	var mu sync.Mutex
	var accepted net.Conn
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		mu.Lock()
		accepted = c
		mu.Unlock()
		defer c.Close()
		dc := &dns.Conn{Conn: c}
		q, err := dc.ReadMsg()
		if err != nil {
			return
		}
		close(entered)
		<-release
		a := new(dns.Msg)
		a.SetReply(q)
		_ = dc.WriteMsg(a)
		// No more queries are sent on this fixture; EOF proves peer retirement.
		_, _ = dc.ReadMsg()
		close(peerClosed)
	}()
	roots := x509.NewCertPool()
	roots.AddCert(cert.cert)
	uc := &UpstreamConfig{Type: ResolverTypeDOT, Endpoint: ln.Addr().String(), BootstrapIP: "127.0.0.1", Domain: "localhost", certPool: roots}
	uc.SetupTransport(context.Background())
	uc.transportOnce.Do(func() {}) // SetupTransport above is the resolver's initial setup.
	t.Cleanup(func() {
		unblock()
		uc.CloseTransports()
		_ = ln.Close()
		mu.Lock()
		if accepted != nil {
			_ = accepted.Close()
		}
		mu.Unlock()
		retirementWait(t, done, "DoT server cleanup")
	})
	return uc, entered, unblock, peerClosed
}

func retirementQuery() *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion("retirement.example.", dns.TypeA)
	return q
}

func TestCloseTransportsDoHIdleSlots(t *testing.T) {
	for _, slot := range []string{"default", "v4", "v6", "aliased"} {
		t.Run(slot, func(t *testing.T) {
			closed := make(chan struct{})
			var once sync.Once
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("ok"))
			}))
			srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateClosed {
					once.Do(func() { close(closed) })
				}
			}
			srv.Start()
			defer srv.Close()
			transport := http.DefaultTransport.(*http.Transport).Clone()
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
			resp, err := client.Get(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			select {
			case <-closed:
				t.Fatal("fixture did not retain an idle connection")
			default:
			}
			uc := &UpstreamConfig{}
			switch slot {
			case "default":
				uc.transport = transport
			case "v4":
				uc.transport4 = transport
			case "v6":
				uc.transport6 = transport
			case "aliased":
				uc.transport, uc.transport4, uc.transport6 = transport, transport, transport
			}
			uc.CloseTransports()
			retirementWait(t, closed, "idle HTTP connection retirement")
			uc.CloseTransports()
		})
	}
}

func TestCloseTransportsDoTActive(t *testing.T) {
	uc, entered, release, peerClosed := retirementDOTServer(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := (&dotResolver{uc: uc}).Resolve(ctx, retirementQuery()); result <- err }()
	retirementWait(t, entered, "active DoT query")
	uc.CloseTransports()
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			// miekg/dns has its own two-second read timeout, independent of
			// the longer context deadline. A timeout is not retirement proof.
			t.Fatalf("active DoT query was not closed by retirement: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("active DoT query survived retirement until its own deadline")
	}
	release()
	retirementWait(t, peerClosed, "DoT peer socket closure")
	if _, err := (&dotResolver{uc: uc}).Resolve(ctx, retirementQuery()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("retired resolver accepted another query: %v", err)
	}
	if n := len(uc.dotClientPool.conns); n != 0 {
		t.Fatalf("late return repopulated pool: %d", n)
	}
}

func TestCloseTransportsDoTIdleAndLateReturn(t *testing.T) {
	for _, slot := range []string{"default", "v4", "v6", "aliased"} {
		for _, checkedOut := range []bool{false, true} {
			t.Run(slot+map[bool]string{false: "/idle", true: "/checked-out"}[checkedOut], func(t *testing.T) {
				uc, _, _, peerClosed := retirementDOTServer(t, false)
				p := uc.dotClientPool
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if _, err := p.Resolve(ctx, retirementQuery()); err != nil {
					t.Fatal(err)
				}
				var conn net.Conn
				if checkedOut {
					var err error
					conn, err = p.getConn(ctx)
					if err != nil {
						t.Fatal(err)
					}
				}
				switch slot {
				case "v4":
					uc.dotClientPool = nil
					uc.dotClientPool4 = p
				case "v6":
					uc.dotClientPool = nil
					uc.dotClientPool6 = p
				case "aliased":
					uc.dotClientPool4 = p
					uc.dotClientPool6 = p
				}
				uc.CloseTransports()
				retirementWait(t, peerClosed, "idle/checked-out DoT socket closure")
				// Simulate a response that completed just before retirement and returns late.
				if conn != nil {
					p.putConn(conn, true)
				}
				uc.CloseTransports() // aliased slots and repeated retirement are safe.
				if n := len(p.conns); n != 0 {
					t.Fatalf("retired pool has %d connections", n)
				}
				if _, err := p.getConn(ctx); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("get after close: %v", err)
				}
			})
		}
	}
}

func TestCloseTransportsDoTHandshake(t *testing.T) {
	for _, mode := range []string{"bootstrap", "parallel", "fallback"} {
		t.Run(mode, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			entered, peerClosed := make(chan struct{}), make(chan struct{})
			go func() {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				var b [1]byte
				if _, err := c.Read(b[:]); err != nil {
					return
				}
				close(entered) // ClientHello was received, but no TLS response is sent.
				_, _ = io.Copy(io.Discard, c)
				close(peerClosed)
			}()
			uc := &UpstreamConfig{Type: ResolverTypeDOT, Endpoint: ln.Addr().String(), BootstrapIP: "127.0.0.1", Domain: "localhost"}
			var addrs []string
			if mode != "bootstrap" {
				uc.BootstrapIP = ""
			}
			if mode == "parallel" {
				addrs = []string{"127.0.0.1"}
			}
			p := newDOTClientPool(context.Background(), uc, addrs)
			// The raw fallback fixture has no bootstrap hostname to infer SNI from.
			p.tlsConfig.ServerName = "localhost"
			uc.dotClientPool = p
			defer uc.CloseTransports()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() { _, err := p.Resolve(ctx, retirementQuery()); result <- err }()
			retirementWait(t, entered, "stalled TLS handshake")
			uc.CloseTransports()
			retirementWait(t, peerClosed, "handshaking socket closure")
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("handshake succeeded after retirement")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("handshake was not canceled")
			}
		})
	}
}

func TestCloseTransportsDoTPendingDial(t *testing.T) {
	// Per-pool dialer seam holds a real TCP dial before connect; no global hooks.
	uc := &UpstreamConfig{Type: ResolverTypeDOT, Endpoint: "127.0.0.1:853", BootstrapIP: "127.0.0.1"}
	p := newDOTClientPool(context.Background(), uc, nil)
	uc.dotClientPool = p
	defer uc.CloseTransports()
	entered, canceled := make(chan struct{}), make(chan struct{})
	p.dialer.ControlContext = func(ctx context.Context, _, _ string, _ syscall.RawConn) error {
		close(entered)
		<-ctx.Done()
		close(canceled)
		return ctx.Err()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := p.Resolve(ctx, retirementQuery()); result <- err }()
	retirementWait(t, entered, "pending TCP dial")
	uc.CloseTransports()
	retirementWait(t, canceled, "TCP dial cancellation")
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("dial succeeded after close")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("dial did not return")
	}
}

func TestDoTParallelDialClosesLosers(t *testing.T) {
	const attempts = 4
	cert := generateTestCertificate(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert.tlsCert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	allAccepted, release := make(chan struct{}), make(chan struct{})
	closed, received := make(chan struct{}, attempts), make(chan struct{}, attempts)
	var unblock sync.Once
	releaseAll := func() { unblock.Do(func() { close(release) }) }
	defer releaseAll()
	var wg sync.WaitGroup
	go func() {
		for i := 0; i < attempts; i++ {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				defer func() { closed <- struct{}{} }()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				<-release
				var b [1]byte
				if _, err := c.Read(b[:]); err == nil {
					received <- struct{}{}
					_, _ = io.Copy(io.Discard, c)
				}
			}()
		}
		close(allAccepted)
	}()
	roots := x509.NewCertPool()
	roots.AddCert(cert.cert)
	uc := &UpstreamConfig{Type: ResolverTypeDOT, Endpoint: ln.Addr().String(), Domain: "localhost", certPool: roots}
	addrs := make([]string, attempts)
	for i := range addrs {
		addrs[i] = "127.0.0.1"
	}
	p := newDOTClientPool(context.Background(), uc, addrs)
	uc.dotClientPool = p
	defer uc.CloseTransports()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	type result struct {
		conn net.Conn
		err  error
	}
	resultCh := make(chan result, 1)
	go func() { conn, err := p.getConn(ctx); resultCh <- result{conn, err} }()
	retirementWait(t, allAccepted, "all parallel TCP connections")
	releaseAll()
	var conn net.Conn
	select {
	case res := <-resultCh:
		if res.err != nil {
			t.Fatal(res.err)
		}
		conn = res.conn
	case <-time.After(3 * time.Second):
		t.Fatal("parallel dial failed to return a winner")
	}
	// A dial-context cancellation must close losers, not the winning connection.
	if _, err := conn.Write([]byte{42}); err != nil {
		t.Fatal(err)
	}
	retirementWait(t, received, "winner data")
	for i := 0; i < attempts-1; i++ {
		retirementWait(t, closed, "losing parallel socket closure")
	}
	uc.CloseTransports()
	retirementWait(t, closed, "winning socket retirement")
	p.putConn(conn, true)
	wg.Wait()
}

func TestDoTIdleCleanupPreservesActive(t *testing.T) {
	uc, entered, release, _ := retirementDOTServer(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := uc.dotClientPool.Resolve(ctx, retirementQuery()); result <- err }()
	retirementWait(t, entered, "active query")
	uc.closeTransports() // Idle-only cleanup, not transport replacement.
	release()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("idle cleanup aborted active query: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("query did not finish")
	}
	conn, err := uc.dotClientPool.getConn(ctx)
	if err != nil {
		t.Fatalf("idle cleanup retired pool: %v", err)
	}
	uc.dotClientPool.putConn(conn, true)
}

func TestCloseTransportsDoH3Active(t *testing.T) {
	for _, slot := range []string{"default", "v4", "v6", "aliased"} {
		t.Run(slot, func(t *testing.T) {
			entered, release, peerCanceled := make(chan struct{}), make(chan struct{}), make(chan struct{})
			srv := newTestHTTP3Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(entered)
				select {
				case <-r.Context().Done():
					close(peerCanceled)
				case <-release:
				}
			}))
			defer close(release)
			roots := x509.NewCertPool()
			roots.AddCert(srv.cert)
			uc := &UpstreamConfig{Type: ResolverTypeDOH3, BootstrapIP: "127.0.0.1", certPool: roots}
			rt := uc.newDOH3Transport(context.Background(), nil).(*http3.Transport)
			defer rt.Close()
			switch slot {
			case "default":
				uc.http3RoundTripper = rt
			case "v4":
				uc.http3RoundTripper4 = rt
			case "v6":
				uc.http3RoundTripper6 = rt
			case "aliased":
				uc.http3RoundTripper = rt
				uc.http3RoundTripper4 = rt
				uc.http3RoundTripper6 = rt
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			request := func() error {
				req, _ := http.NewRequestWithContext(ctx, "GET", "https://"+srv.addr, nil)
				resp, err := rt.RoundTrip(req)
				if err == nil {
					defer resp.Body.Close()
					_, err = io.ReadAll(resp.Body)
				}
				return err
			}
			result := make(chan error, 1)
			go func() { result <- request() }()
			retirementWait(t, entered, "active HTTP/3 request")
			uc.CloseTransports()
			retirementWait(t, peerCanceled, "HTTP/3 server request cancellation")
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("active HTTP/3 request survived close")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("HTTP/3 request was not aborted")
			}
			if err := request(); err == nil {
				t.Fatal("retired HTTP/3 transport accepted another request")
			}
			uc.CloseTransports()
		})
	}
}
