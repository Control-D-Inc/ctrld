package ctrld

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

var transportReplacements = []struct {
	name string
	run  func(*UpstreamConfig, context.Context)
}{
	{"SetupTransport", (*UpstreamConfig).SetupTransport},
	{"ForceReBootstrap", (*UpstreamConfig).ForceReBootstrap},
}

// Accept multiple connections so a replacement must answer on the same real
// endpoint, while the original query is still held by the server.
func replacementDOTServer(t *testing.T) (*UpstreamConfig, <-chan struct{}, func(), <-chan struct{}) {
	t.Helper()
	cert := generateTestCertificate(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert.tlsCert}})
	if err != nil {
		t.Fatal(err)
	}
	entered, release, peerClosed, done := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	var mu sync.Mutex
	var conns []net.Conn
	var wg sync.WaitGroup
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				dc := &dns.Conn{Conn: c}
				for {
					q, err := dc.ReadMsg()
					if err != nil {
						return
					}
					held := q.Question[0].Name == "held.example."
					if held {
						close(entered)
						defer close(peerClosed)
						<-release
					}
					a := new(dns.Msg)
					a.SetReply(q)
					if err := dc.WriteMsg(a); err != nil {
						return
					}
				}
			}()
		}
	}()
	roots := x509.NewCertPool()
	roots.AddCert(cert.cert)
	uc := &UpstreamConfig{Type: ResolverTypeDOT, Endpoint: ln.Addr().String(), BootstrapIP: "127.0.0.1", Domain: "localhost", certPool: roots}
	uc.ensureSetupTransport(context.Background())
	t.Cleanup(func() {
		unblock()
		uc.CloseTransports()
		_ = ln.Close()
		retirementWait(t, done, "DoT accept loop cleanup") // No more wg.Add after this.
		mu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return uc, entered, unblock, peerClosed
}

func replacementAnswer(t *testing.T, resolve func(context.Context, *dns.Msg) (*dns.Msg, error)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	q := retirementQuery()
	a, err := resolve(ctx, q)
	if err != nil {
		t.Fatalf("replacement query failed: %v", err)
	}
	if a == nil || !a.Response || a.Id != q.Id || len(a.Question) != 1 || a.Question[0] != q.Question[0] {
		t.Fatalf("replacement returned wrong DNS answer: %v", a)
	}
}

func replacementResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("old query survived replacement")
		return nil
	}
}

func TestReplaceTransportsDoTActive(t *testing.T) {
	for _, replace := range transportReplacements {
		t.Run(replace.name, func(t *testing.T) {
			uc, entered, release, peerClosed := replacementDOTServer(t)
			old := uc.dotClientPool
			selected := make(chan struct{})
			old.dialer.ControlContext = func(context.Context, string, string, syscall.RawConn) error {
				close(selected)
				return nil
			}
			r := &dotResolver{uc: uc}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			q := new(dns.Msg)
			q.SetQuestion("held.example.", dns.TypeA)
			result := make(chan error, 1)
			go func() { _, err := r.Resolve(ctx, q); result <- err }()
			retirementWait(t, selected, "DoT transport selection")
			retirementWait(t, entered, "active DoT query")
			replace.run(uc, context.Background())
			if uc.dotClientPool == old {
				t.Fatal("DoT pool was not replaced")
			}
			if err := replacementResult(t, result); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("old query did not fail from socket retirement: %v", err)
			}
			// This answer must arrive before releasing the old server handler.
			replacementAnswer(t, r.Resolve)
			release()
			retirementWait(t, peerClosed, "old DoT peer closure")
			if _, err := old.Resolve(ctx, retirementQuery()); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("late query revived replaced DoT pool: %v", err)
			}
			replacementAnswer(t, r.Resolve)
		})
	}
}

func TestReplaceTransportsDoTLateReturn(t *testing.T) {
	for _, replace := range transportReplacements {
		for _, slot := range []string{"default", "v4", "v6", "aliased"} {
			t.Run(replace.name+"/"+slot, func(t *testing.T) {
				uc, _, _, _ := replacementDOTServer(t)
				old := uc.dotClientPool
				r := &dotResolver{uc: uc}
				replacementAnswer(t, r.Resolve)
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				conn, err := old.getConn(ctx)
				if err != nil {
					t.Fatal(err)
				}
				// Model each old slot, including the IPv6-to-IPv4 alias, without
				// requiring an external IPv6 capability probe in this fixture.
				switch slot {
				case "v4":
					uc.dotClientPool, uc.dotClientPool4 = nil, old
				case "v6":
					uc.dotClientPool, uc.dotClientPool6 = nil, old
				case "aliased":
					uc.dotClientPool4, uc.dotClientPool6 = old, old
				}
				replace.run(uc, context.Background())
				// A successful borrower returning after the slots change must not
				// put its connection back into the now-orphaned pool.
				old.putConn(conn, true)
				if len(old.conns) != 0 {
					t.Fatal("late return repopulated replaced DoT pool")
				}
				if _, err := old.getConn(ctx); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("replaced DoT pool accepted late work: %v", err)
				}
				replacementAnswer(t, r.Resolve)
			})
		}
	}
}

func TestReplaceTransportsDoH3IdleAndLateWork(t *testing.T) {
	for _, replace := range transportReplacements {
		t.Run(replace.name, func(t *testing.T) {
			srv := newTestHTTP3Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			roots := x509.NewCertPool()
			roots.AddCert(srv.cert)
			uc := &UpstreamConfig{Type: ResolverTypeDOH3, Endpoint: "https://" + srv.addr, BootstrapIP: "127.0.0.1", certPool: roots}
			defer uc.CloseTransports()
			// The real warmup path initializes the transport and leaves it idle.
			if err := uc.ErrorPing(context.Background()); err != nil {
				t.Fatal(err)
			}
			old := uc.http3RoundTripper
			defer old.(io.Closer).Close()
			replace.run(uc, context.Background())
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, "HEAD", uc.Endpoint, nil)
			resp, err := old.RoundTrip(req)
			if resp != nil {
				resp.Body.Close()
			}
			if err == nil || ctx.Err() != nil {
				t.Fatalf("late work revived idle replaced HTTP/3 transport: %v (context: %v)", err, ctx.Err())
			}
			if err := uc.ErrorPing(context.Background()); err != nil {
				t.Fatalf("replacement HTTP/3 transport is not usable: %v", err)
			}
		})
	}
}

func TestReplaceTransportsDoH3ActiveAndLateWork(t *testing.T) {
	for _, replace := range transportReplacements {
		for _, slot := range []string{"default", "v4", "v6", "aliased"} {
			t.Run(replace.name+"/"+slot, func(t *testing.T) {
				entered, release, peerCanceled := make(chan struct{}), make(chan struct{}), make(chan struct{})
				srv := newTestHTTP3Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/late" {
						w.WriteHeader(http.StatusOK)
						return
					}
					data, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
					q := new(dns.Msg)
					if err != nil || q.Unpack(data) != nil || len(q.Question) != 1 {
						http.Error(w, "bad DNS query", http.StatusBadRequest)
						return
					}
					if q.Question[0].Name == "held.example." {
						close(entered)
						select {
						case <-r.Context().Done():
							close(peerCanceled)
						case <-release:
						}
						return
					}
					a := new(dns.Msg)
					a.SetReply(q)
					data, _ = a.Pack()
					w.Header().Set("Content-Type", headerApplicationDNS)
					_, _ = w.Write(data)
				}))
				defer close(release)
				roots := x509.NewCertPool()
				roots.AddCert(srv.cert)
				u, err := url.Parse("https://" + srv.addr + "/dns-query")
				if err != nil {
					t.Fatal(err)
				}
				uc := &UpstreamConfig{Type: ResolverTypeDOH3, Endpoint: u.String(), u: u, BootstrapIP: "127.0.0.1", certPool: roots}
				uc.ensureSetupTransport(context.Background())
				defer uc.CloseTransports()
				old := uc.http3RoundTripper
				// Clean the old transport even if a regression leaves it orphaned.
				defer old.(io.Closer).Close()
				selected := make(chan struct{})
				rt := old.(*http3.Transport)
				dial := rt.Dial
				var selectedOnce sync.Once
				rt.Dial = func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
					selectedOnce.Do(func() { close(selected) })
					return dial(ctx, addr, tlsCfg, cfg)
				}
				r := newDohResolver(uc)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				q := new(dns.Msg)
				q.SetQuestion("held.example.", dns.TypeA)
				result := make(chan error, 1)
				go func() { _, err := r.Resolve(ctx, q); result <- err }()
				// A network exchange alone isn't a Go happens-before edge. Observe
				// selection before writing slots; still execute the production dial.
				retirementWait(t, selected, "HTTP/3 transport selection")
				retirementWait(t, entered, "active HTTP/3 DNS query")
				switch slot {
				case "v4":
					uc.http3RoundTripper, uc.http3RoundTripper4 = nil, old
				case "v6":
					uc.http3RoundTripper, uc.http3RoundTripper6 = nil, old
				case "aliased":
					uc.http3RoundTripper4, uc.http3RoundTripper6 = old, old
				}
				replace.run(uc, context.Background())
				if uc.http3RoundTripper == old {
					t.Fatal("HTTP/3 transport was not replaced")
				}
				retirementWait(t, peerCanceled, "old HTTP/3 request cancellation")
				if err := replacementResult(t, result); err == nil || ctx.Err() != nil {
					t.Fatalf("old HTTP/3 query not aborted by replacement: %v (context: %v)", err, ctx.Err())
				}
				replacementAnswer(t, r.Resolve)
				req, _ := http.NewRequestWithContext(ctx, "GET", "https://"+srv.addr+"/late", nil)
				resp, err := old.RoundTrip(req)
				if resp != nil {
					resp.Body.Close()
				}
				if err == nil || ctx.Err() != nil {
					t.Fatalf("late request revived replaced HTTP/3 transport: %v (context: %v)", err, ctx.Err())
				}
				replacementAnswer(t, r.Resolve)
			})
		}
	}
}
