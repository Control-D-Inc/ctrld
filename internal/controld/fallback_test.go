package controld

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
)

// errRoundTripper fails the hostname attempt and the direct-ip attempt with
// different errors, mimicking the Firewall Mode incident: the hostname attempt is
// denied by a local firewall (WSAEACCES on Windows) while the direct-ip fallback
// reports an unreachable IPv6 route.
type errRoundTripper struct {
	hostname string
	firstErr error
	fbErr    error
	fbCalled bool
}

func (rt *errRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == rt.hostname {
		return nil, &net.OpError{Op: "dial", Net: "tcp4", Err: rt.firstErr}
	}
	rt.fbCalled = true
	if rt.fbErr == nil {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       http.NoBody,
			Request:    req,
		}, nil
	}
	return nil, &net.OpError{Op: "dial", Net: "tcp6", Err: rt.fbErr}
}

// wsaEACCES is WSAEACCES (10013): "An attempt was made to access a socket in a way
// forbidden by its access permissions." The value is what Windows reports when a
// WFP filter denies the connect; it is used here as a plain errno so the test runs
// on every platform.
const wsaEACCES = syscall.Errno(10013)

func TestDoWithFallbackPreservesFirstError(t *testing.T) {
	const (
		hostname = "api.controld.com"
		apiIP    = "147.185.34.1"
	)
	rt := &errRoundTripper{
		hostname: hostname,
		firstErr: wsaEACCES,
		fbErr:    syscall.EHOSTUNREACH,
	}
	req, err := http.NewRequest(http.MethodPost, "https://"+hostname+"/utility", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := doWithFallback(&http.Client{Transport: rt}, req, apiIP)
	if err == nil {
		t.Fatalf("expected an error, got response %v", resp)
	}
	if !rt.fbCalled {
		t.Error("direct-ip fallback was not attempted")
	}

	// The actionable failure must survive: an operator reading this error has to be
	// able to tell "the host is blocking us" from "the network is down".
	if !errors.Is(err, wsaEACCES) {
		t.Errorf("first-attempt error (WSAEACCES) was lost, got: %v", err)
	}
	if !errors.Is(err, syscall.EHOSTUNREACH) {
		t.Errorf("fallback error was lost, got: %v", err)
	}
	if got := err.Error(); !strings.Contains(got, apiIP) {
		t.Errorf("error does not mention the fallback ip %q: %v", apiIP, got)
	}
}

func TestDoWithFallbackSucceedsOnFallback(t *testing.T) {
	const hostname = "api.controld.com"
	rt := &errRoundTripper{hostname: hostname, firstErr: wsaEACCES}
	req, err := http.NewRequest(http.MethodPost, "https://"+hostname+"/utility", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := doWithFallback(&http.Client{Transport: rt}, req, "147.185.34.1")
	if err != nil {
		t.Fatalf("expected the fallback to succeed, got: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestDoWithFallbackNoFallbackOnSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	req, err := http.NewRequest(http.MethodPost, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := doWithFallback(srv.Client(), req, "127.0.0.2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// TestDoWithFallbackComposesHostnameAttemptFirst pins the order of the composed error.
//
// The order is not cosmetic. cmd/cli's preflight retry predicate classifies this error
// with errors.As, which returns the first match in the tree, so whichever attempt is
// wrapped first decides whether processCDFlags keeps backing off or fails fast. That
// predicate lives in another package and cannot be called from here, so this test
// guards the property it depends on: the hostname attempt - the one that carries the
// diagnosis - must come first.
func TestDoWithFallbackComposesHostnameAttemptFirst(t *testing.T) {
	const hostname = "api.controld.com"
	rt := &errRoundTripper{
		hostname: hostname,
		firstErr: wsaEACCES,
		fbErr:    syscall.EHOSTUNREACH,
	}
	req, err := http.NewRequest(http.MethodPost, "https://"+hostname+"/utility", nil)
	if err != nil {
		t.Fatal(err)
	}

	_, gotErr := doWithFallback(&http.Client{Transport: rt}, req, "147.185.34.1")
	if gotErr == nil {
		t.Fatal("expected both attempts to fail")
	}

	var opErr *net.OpError
	if !errors.As(gotErr, &opErr) {
		t.Fatalf("no net.OpError in the chain: %v", gotErr)
	}
	if !errors.Is(opErr.Err, wsaEACCES) {
		t.Errorf("first OpError in the chain is %v, want the hostname attempt (%v)", opErr.Err, wsaEACCES)
	}
	// The tcp4/tcp6 split distinguishes the two attempts in the fake transport.
	if opErr.Net != "tcp4" {
		t.Errorf("first OpError is from the %s attempt, want tcp4 (hostname)", opErr.Net)
	}
}
