package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"

	"github.com/Control-D-Inc/ctrld"
)

func TestCloseReplacedUpstreamsPreservesRetainedAndNew(t *testing.T) {
	certServer := httptest.NewTLSServer(nil)
	certificate := certServer.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(certServer.Certificate())
	certServer.Close()

	type upstream struct {
		config  *ctrld.UpstreamConfig
		entered <-chan struct{}
		release func()
	}
	newUpstream := func() upstream {
		ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}})
		require.NoError(t, err)
		entered, release := make(chan struct{}), make(chan struct{})
		var enteredOnce, releaseOnce sync.Once
		s := &dns.Server{Listener: ln, Net: "tcp-tls", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, m *dns.Msg) {
			enteredOnce.Do(func() { close(entered) })
			<-release
			answer := new(dns.Msg)
			answer.SetReply(m)
			_ = w.WriteMsg(answer)
		})}
		done := make(chan error, 1)
		go func() { done <- s.ActivateAndServe() }()
		uc := &ctrld.UpstreamConfig{Type: ctrld.ResolverTypeDOT, Endpoint: ln.Addr().String(), BootstrapIP: "127.0.0.1"}
		uc.Init(context.Background())
		uc.SetCertPool(roots)
		unblock := func() { releaseOnce.Do(func() { close(release) }) }
		t.Cleanup(func() {
			unblock()
			uc.CloseTransports()
			_ = s.Shutdown()
			_ = ln.Close()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("test DNS server did not stop")
			}
		})
		return upstream{uc, entered, unblock}
	}
	removed, retained, replacement := newUpstream(), newUpstream(), newUpstream()
	query := func(u upstream) <-chan error {
		result := make(chan error, 1)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			r, err := ctrld.NewResolver(ctx, u.config)
			if err == nil {
				q := new(dns.Msg)
				q.SetQuestion("retirement.example.", dns.TypeA)
				_, err = r.Resolve(ctx, q)
			}
			result <- err
		}()
		return result
	}
	removedResult, retainedResult := query(removed), query(retained)
	for _, ch := range []<-chan struct{}{removed.entered, retained.entered} {
		select {
		case <-ch:
		case <-time.After(3 * time.Second):
			t.Fatal("query did not reach local upstream")
		}
	}
	closeReplacedUpstreams(map[string]*ctrld.UpstreamConfig{
		"0": removed.config, "1": retained.config, "nil": nil,
	}, map[string]*ctrld.UpstreamConfig{
		"0": replacement.config, "renamed": retained.config,
	})
	select {
	case err := <-removedResult:
		require.ErrorIs(t, err, net.ErrClosed)
	case <-time.After(time.Second):
		t.Fatal("removed upstream's active query was not closed")
	}
	retained.release()
	require.NoError(t, <-retainedResult, "retained pointer must remain usable under a different key")
	replacement.release()
	require.NoError(t, <-query(replacement), "new upstream must not be retired with the old key")
}
