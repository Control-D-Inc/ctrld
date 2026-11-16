package ctrld

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"
	"weak"

	"github.com/quic-go/quic-go/http3"
)

// TestDoHTransport_ReplacedHTTP2TransportIsCollected verifies that a DoH
// transport replaced by SetupTransport (as a re-bootstrap after a query
// timeout does) can be garbage collected after it has served HTTP/2 requests.
// An *http.Transport that has spoken HTTP/2 is in a reference cycle with its
// HTTP/2 transport; a finalizer on it keeps the whole cycle alive forever, so
// every re-bootstrap would leak one transport.
func TestDoHTransport_ReplacedHTTP2TransportIsCollected(t *testing.T) {
	// The HTTP/2 health-check timer of a closed connection still references
	// its transport until it fires once, SendPingTimeout after the last frame.
	// Shorten it so the test does not wait the production 10s.
	oldSend, oldPing := dohSendPingTimeout, dohPingTimeout
	dohSendPingTimeout, dohPingTimeout = 200*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { dohSendPingTimeout, dohPingTimeout = oldSend, oldPing })

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)

	uc := dohUpstreamForTLSServer(t, srv)

	const n = 20
	replaced := make([]weak.Pointer[http.Transport], 0, n)
	for i := 0; i < n; i++ {
		uc.SetupTransport(context.Background())
		replaced = append(replaced, weak.Make(uc.transport))
		resp, err := uc.transport.RoundTrip(mustNewRequest(t, uc.Endpoint))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.ProtoMajor != 2 {
			t.Fatalf("DoH transport negotiated HTTP/%d, want HTTP/2", resp.ProtoMajor)
		}
	}
	// Replace the last one too, so every transport in replaced is retired.
	uc.SetupTransport(context.Background())
	t.Cleanup(uc.transport.CloseIdleConnections)

	waitCollected(t, "HTTP/2 DoH", replaced)
}

// TestDoH3Transport_ReplacedTransportIsCollected is the DoH3 version of
// TestDoHTransport_ReplacedHTTP2TransportIsCollected: an *http3.Transport
// replaced by SetupTransport must be garbage collected after it has served a
// request.
func TestDoH3Transport_ReplacedTransportIsCollected(t *testing.T) {
	srv := newTestHTTP3Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	uc := doh3UpstreamForAddr(t, srv.addr, srv.cert)
	url := "https://" + srv.addr + "/dns-query"

	const n = 20
	replaced := make([]weak.Pointer[http3.Transport], 0, n)
	for i := 0; i < n; i++ {
		uc.SetupTransport(context.Background())
		rt, ok := uc.http3RoundTripper.(*http3.Transport)
		if !ok {
			t.Fatalf("DoH3 round tripper is %T, want *http3.Transport", uc.http3RoundTripper)
		}
		replaced = append(replaced, weak.Make(rt))
		resp, err := rt.RoundTrip(mustNewRequest(t, url))
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	// Replace the last one too, so every transport in replaced is retired.
	uc.SetupTransport(context.Background())
	t.Cleanup(uc.retireTransports)

	waitCollected(t, "DoH3", replaced)
}

// waitCollected runs GC until every pointer in replaced is freed, and fails
// the test if some are still reachable after 5s.
func waitCollected[T any](t *testing.T, kind string, replaced []weak.Pointer[T]) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		runtime.GC()
		live := 0
		for _, p := range replaced {
			if p.Value() != nil {
				live++
			}
		}
		if live == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d replaced %s transports are still reachable after GC", live, len(replaced), kind)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
