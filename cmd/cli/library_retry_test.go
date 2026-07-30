package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"testing"

	"github.com/Control-D-Inc/ctrld/internal/controld"
)

// wsaEACCES is WSAEACCES (10013): "An attempt was made to access a socket in a way
// forbidden by its access permissions." This is what Windows reports when a WFP
// filter denies the connect. Used as a plain errno so the test runs everywhere.
const wsaEACCES = syscall.Errno(10013)

// denyingRoundTripper denies the hostname attempt with firstErr and the direct-ip
// attempt with fbErr, the shape seen during the Firewall Mode incident: the
// hostname attempt was denied by ctrld's own stale block-all filters, while the
// direct-ip fallback failed on an unreachable IPv6 route.
type denyingRoundTripper struct {
	hostname string
	firstErr error
	fbErr    error
}

func (rt *denyingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == rt.hostname {
		return nil, &net.OpError{Op: "dial", Net: "tcp4", Err: rt.firstErr}
	}
	return nil, &net.OpError{Op: "dial", Net: "tcp6", Err: rt.fbErr}
}

func TestDoWithRetryPreservesHostnameError(t *testing.T) {
	const hostname = "dl.controld.dev"
	req, err := http.NewRequest(http.MethodGet, "https://"+hostname+"/v2/windows-amd64/ctrld.exe", nil)
	if err != nil {
		t.Fatal(err)
	}
	rt := &denyingRoundTripper{
		hostname: hostname,
		firstErr: wsaEACCES,
		fbErr:    syscall.EHOSTUNREACH,
	}

	_, err = doWithRetryClient(&http.Client{Transport: rt}, req, 1, "23.171.240.151")
	if err == nil {
		t.Fatal("expected doWithRetry to fail when both attempts are denied")
	}
	if !errors.Is(err, wsaEACCES) {
		t.Errorf("hostname-attempt error (WSAEACCES) was lost, got: %v", err)
	}
	if !errors.Is(err, syscall.EHOSTUNREACH) {
		t.Errorf("fallback error was lost, got: %v", err)
	}
}

// composedAttemptErrors builds the error shape the two-attempt paths return: each
// attempt's *url.Error (as produced by http.Client.Do) wrapped by a single fmt.Errorf
// with two %w verbs, hostname attempt first. Mirrors doWithFallback in
// internal/controld and doWithRetryClient above.
func composedAttemptErrors(first, fallback error) error {
	attempt := func(network string, cause error) error {
		return &url.Error{
			Op:  "Post",
			URL: "https://api.controld.com/utility",
			Err: &net.OpError{Op: "dial", Net: network, Err: cause},
		}
	}
	return fmt.Errorf("request failed: %w; fallback to direct ip %s failed: %w",
		attempt("tcp4", first), "147.185.34.1", attempt("tcp6", fallback))
}

// TestComposedFallbackErrorRetryClassification pins which attempt decides whether
// preflight keeps retrying.
//
// Reporting both attempt errors is not purely diagnostic: processCDFlags decides
// retryability with errUrlNetworkError, which uses errors.As, and errors.As is
// order-sensitive - it returns the *first* matching error in the tree. Composing the
// hostname attempt first therefore hands the retry predicate the hostname failure,
// where previously only the fallback's error survived to be classified.
//
// The consequence is deliberate: a locally denied socket (WSAEACCES, a firewall
// blocking ctrld) is no longer treated as a transient network error, so preflight fails
// fast and reports instead of backing off - the incident logged 256 retry cycles
// against filters that were never going to clear on their own. The boot case that
// justifies the indefinite retry, a network unreachable on both attempts, is preserved.
//
// If the wrap order is ever reversed, this test fails rather than silently restoring
// indefinite retries against a host that is actively refusing.
func TestComposedFallbackErrorRetryClassification(t *testing.T) {
	tests := []struct {
		name          string
		hostname      error
		fallback      error
		wantRetryable bool
	}{
		{
			// The incident's pair: denied locally, IPv6 route unusable.
			name:          "denied socket then unreachable fallback fails fast",
			hostname:      wsaEACCES,
			fallback:      syscall.EHOSTUNREACH,
			wantRetryable: false,
		},
		{
			// Boot with no network yet: must still retry indefinitely.
			name:          "network unreachable on both attempts still retries",
			hostname:      syscall.ENETUNREACH,
			fallback:      syscall.ENETUNREACH,
			wantRetryable: true,
		},
		{
			name:          "connection refused still retries",
			hostname:      syscall.ECONNREFUSED,
			fallback:      syscall.EHOSTUNREACH,
			wantRetryable: true,
		},
		{
			name:          "permission denied on both attempts fails fast",
			hostname:      syscall.EACCES,
			fallback:      syscall.EACCES,
			wantRetryable: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := composedAttemptErrors(tc.hostname, tc.fallback)
			if got := errUrlNetworkError(err); got != tc.wantRetryable {
				t.Errorf("errUrlNetworkError() = %v, want %v", got, tc.wantRetryable)
			}
			// Both attempts remain reportable regardless of classification.
			if !errors.Is(err, tc.hostname) {
				t.Error("hostname attempt error was lost")
			}
			if !errors.Is(err, tc.fallback) {
				t.Error("fallback attempt error was lost")
			}
		})
	}
}

// TestUnresolvedHostnameDefersToFallbackAttempt covers the asymmetric pair.
//
// Only the hostname attempt resolves DNS, and Go marks a *net.DNSError as temporary only
// for socket failures that reached the server - so a SERVFAIL or "no such host" answer is
// not temporary. At boot behind a captive portal, or before a router's forwarder is up,
// that is exactly how the hostname attempt fails while the network is merely not ready.
// Before the composed error existed only the fallback decided, so this pair retried;
// classifying the hostname attempt alone would fail it fast and reach Fatal.
//
// A name-resolution failure therefore carries no verdict: the fallback attempt decides.
// The locally-denied case above still fails fast, because a denied socket is definitive.
func TestUnresolvedHostnameDefersToFallbackAttempt(t *testing.T) {
	dnsFailure := &url.Error{
		Op:  "Post",
		URL: "https://api.controld.com/utility",
		Err: &net.DNSError{Err: "server misbehaving", Name: "api.controld.com", IsTemporary: false},
	}
	attempt := func(cause error) error {
		return &url.Error{
			Op:  "Post",
			URL: "https://api.controld.com/utility",
			Err: &net.OpError{Op: "dial", Net: "tcp6", Err: cause},
		}
	}

	retryable := fmt.Errorf("request failed: %w; fallback to direct ip %s failed: %w",
		dnsFailure, "147.185.34.1", attempt(syscall.ECONNREFUSED))
	if !errUrlNetworkError(retryable) {
		t.Error("an unresolved hostname with a retryable fallback must keep retrying: at boot the network is simply not up yet")
	}

	denied := fmt.Errorf("request failed: %w; fallback to direct ip %s failed: %w",
		dnsFailure, "147.185.34.1", attempt(wsaEACCES))
	if errUrlNetworkError(denied) {
		t.Error("an unresolved hostname with a denied fallback must fail fast: nothing here clears on its own")
	}

	// A resolution failure alone still says nothing, so it must not be read as retryable.
	if errUrlNetworkError(dnsFailure) {
		t.Error("a bare name-resolution failure must not be classified as retryable")
	}
}

// TestDoWithFallbackClassificationEndToEnd drives the real composition in
// internal/controld through the real predicate, instead of asserting a hand-written copy
// of its error shape against another hand-written copy. A change to either side's format
// string or wrap order is caught here.
func TestDoWithFallbackClassificationEndToEnd(t *testing.T) {
	const hostname = "api.controld.com"
	req, err := http.NewRequest(http.MethodPost, "https://"+hostname+"/utility", nil)
	if err != nil {
		t.Fatal(err)
	}
	rt := &denyingRoundTripper{
		hostname: hostname,
		firstErr: wsaEACCES,
		fbErr:    syscall.EHOSTUNREACH,
	}

	_, gotErr := controld.DoWithFallbackForTest(context.Background(), &http.Client{Transport: rt}, req, "147.185.34.1")
	if gotErr == nil {
		t.Fatal("expected both attempts to fail")
	}
	if errUrlNetworkError(gotErr) {
		t.Errorf("the real composed error was classified as retryable: %v", gotErr)
	}
	if !errors.Is(gotErr, wsaEACCES) || !errors.Is(gotErr, syscall.EHOSTUNREACH) {
		t.Errorf("the real composed error lost an attempt: %v", gotErr)
	}
}

// TestDoWithRetryComposesHostnameAttemptFirst anchors the ordering assumption above to
// the real composition, so a reordering of the wrap in doWithRetryClient is caught here
// and not only in the hand-built shape.
func TestDoWithRetryComposesHostnameAttemptFirst(t *testing.T) {
	const hostname = "dl.controld.dev"
	req, err := http.NewRequest(http.MethodGet, "https://"+hostname+"/v2/windows-amd64/ctrld.exe", nil)
	if err != nil {
		t.Fatal(err)
	}
	rt := &denyingRoundTripper{hostname: hostname, firstErr: wsaEACCES, fbErr: syscall.EHOSTUNREACH}

	_, gotErr := doWithRetryClient(&http.Client{Transport: rt}, req, 1, "23.171.240.151")
	if gotErr == nil {
		t.Fatal("expected both attempts to fail")
	}

	// errors.As must reach the hostname attempt first: that is what the retry
	// predicate classifies.
	var opErr *net.OpError
	if !errors.As(gotErr, &opErr) {
		t.Fatalf("no net.OpError in the chain: %v", gotErr)
	}
	if !errors.Is(opErr.Err, wsaEACCES) {
		t.Errorf("first OpError in the chain is %v, want the hostname attempt (%v)", opErr.Err, wsaEACCES)
	}
}
