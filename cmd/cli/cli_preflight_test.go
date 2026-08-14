package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
)

func TestContextFromStopCh(t *testing.T) {
	t.Run("cancels when stopCh closes", func(t *testing.T) {
		stopCh := make(chan struct{})
		ctx, cancel := contextFromStopCh(stopCh)
		defer cancel()

		if ctx.Err() != nil {
			t.Fatalf("context cancelled before the stop request: %v", ctx.Err())
		}
		close(stopCh)
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("context was not cancelled after stopCh closed")
		}
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Errorf("ctx.Err() = %v, want %v", ctx.Err(), context.Canceled)
		}
	})

	t.Run("cancel releases the watcher", func(t *testing.T) {
		// stopCh is never closed: cancel() must still end the goroutine watching it.
		ctx, cancel := contextFromStopCh(make(chan struct{}))
		cancel()
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("context was not cancelled by cancel()")
		}
	})

	t.Run("nil stopCh is usable", func(t *testing.T) {
		// Mobile callers have no stop channel; preflight must still run.
		ctx, cancel := contextFromStopCh(nil)
		defer cancel()
		if ctx.Err() != nil {
			t.Fatalf("context cancelled immediately: %v", ctx.Err())
		}
	})
}

// retryableNetworkErr is the shape processCDFlags treats as "retry with bootstrap
// DNS": a url.Error wrapping a network failure.
func retryableNetworkErr() error {
	return &url.Error{
		Op:  "Post",
		URL: "https://api.controld.com/utility",
		Err: &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED},
	}
}

func TestProcessCDFlagsStopsWhenCancelled(t *testing.T) {
	oldFetch := fetchResolverConfig
	oldUID := cdUID
	t.Cleanup(func() {
		fetchResolverConfig = oldFetch
		cdUID = oldUID
	})
	cdUID = "testuid"

	var calls atomic.Int64
	fetchResolverConfig = func(ctx context.Context, req *controld.ResolverConfigRequest, dev bool) (*controld.ResolverConfig, error) {
		calls.Add(1)
		return nil, retryableNetworkErr()
	}

	// A stop request arriving while the API is unreachable. Before this was
	// cancellable, the retry loop kept running after the service reported itself
	// stopped, which is what kept the incident's process alive and enforcing.
	stopCh := make(chan struct{})
	ctx, cancel := contextFromStopCh(stopCh)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		cfg := ctrld.Config{}
		_, err := processCDFlags(ctx, &cfg)
		done <- err
	}()

	// Let it fail at least once and settle into backoff before stopping.
	deadline := time.After(10 * time.Second)
	for calls.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("resolver config was never fetched")
		case err := <-done:
			t.Fatalf("processCDFlags returned before any fetch: %v", err)
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	close(stopCh)

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("processCDFlags err = %v, want it to report %v", err, context.Canceled)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("processCDFlags did not return after the stop request")
	}
}

func TestProcessCDFlagsReturnsImmediatelyWhenAlreadyCancelled(t *testing.T) {
	oldFetch := fetchResolverConfig
	oldUID := cdUID
	t.Cleanup(func() {
		fetchResolverConfig = oldFetch
		cdUID = oldUID
	})
	cdUID = "testuid"

	var calls atomic.Int64
	fetchResolverConfig = func(ctx context.Context, req *controld.ResolverConfigRequest, dev bool) (*controld.ResolverConfig, error) {
		calls.Add(1)
		return nil, retryableNetworkErr()
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cfg := ctrld.Config{}
	_, err := processCDFlags(ctx, &cfg)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("processCDFlags err = %v, want %v", err, context.Canceled)
	}
	// One attempt is made before the loop notices; it must not retry past that.
	if got := calls.Load(); got > 1 {
		t.Errorf("fetched %d times with a cancelled context, want at most 1", got)
	}
}

// TestRunAPIPreflightClassification is the regression guard for classifying a preflight
// failure as an operator stop.
//
// runAPIPreflight cancels the context it derived from stopCh. Sampling the stop state
// from that context afterwards reports "stopped" unconditionally, because
// context.CancelFunc sets ctx.Err() whether or not anyone asked to stop. run() then
// takes the stop branch for every failure, which skips self-uninstalling a deleted
// device, skips the mobile exit callback, and tells the service manager a failed start
// was a clean exit.
func TestRunAPIPreflightClassification(t *testing.T) {
	oldFetch := fetchResolverConfig
	oldUID := cdUID
	t.Cleanup(func() {
		fetchResolverConfig = oldFetch
		cdUID = oldUID
	})
	cdUID = "testuid"

	// A deleted ControlD device: non-retryable, so preflight returns promptly.
	deletedDevice := func() error {
		e := &controld.ErrorResponse{}
		e.ErrorField.Code = controld.InvalidConfigCode
		e.ErrorField.Message = "device does not exist"
		return e
	}

	openCh := make(chan struct{})
	closedCh := make(chan struct{})
	close(closedCh)

	tests := []struct {
		name     string
		stopCh   <-chan struct{}
		fetchErr func() error
		wantStop bool
	}{
		{
			// The P1: no stop was requested, so this must reach the failure branch.
			name:     "api error with no stop request",
			stopCh:   openCh,
			fetchErr: deletedDevice,
		},
		{
			// Mobile passes no stop channel at all, so it could never have stopped.
			name:     "api error with a nil stop channel",
			stopCh:   nil,
			fetchErr: deletedDevice,
		},
		{
			name:     "stop requested during preflight",
			stopCh:   closedCh,
			fetchErr: func() error { return retryableNetworkErr() },
			wantStop: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fetchResolverConfig = func(context.Context, *controld.ResolverConfigRequest, bool) (*controld.ResolverConfig, error) {
				return nil, tc.fetchErr()
			}
			cfg := ctrld.Config{}
			pf := runAPIPreflight(tc.stopCh, &cfg)

			if pf.err == nil {
				t.Fatal("expected preflight to fail")
			}
			if pf.stopRequested != tc.wantStop {
				t.Errorf("stopRequested = %v, want %v", pf.stopRequested, tc.wantStop)
			}
		})
	}
}

// TestRunAPIPreflightPreservesAPIError verifies the error reaches the caller in a form
// the failure branch can still act on: self-uninstall keys off an *ErrorResponse with
// InvalidConfigCode, and it only runs if that error is both classified as a failure and
// still unwrappable.
func TestRunAPIPreflightPreservesAPIError(t *testing.T) {
	oldFetch := fetchResolverConfig
	oldUID := cdUID
	t.Cleanup(func() {
		fetchResolverConfig = oldFetch
		cdUID = oldUID
	})
	cdUID = "testuid"

	want := &controld.ErrorResponse{}
	want.ErrorField.Code = controld.InvalidConfigCode
	fetchResolverConfig = func(context.Context, *controld.ResolverConfigRequest, bool) (*controld.ResolverConfig, error) {
		return nil, want
	}

	cfg := ctrld.Config{}
	pf := runAPIPreflight(make(chan struct{}), &cfg)

	if pf.stopRequested {
		t.Error("a device-deleted failure must not be reported as an operator stop")
	}
	var got *controld.ErrorResponse
	if !errors.As(pf.err, &got) {
		t.Fatalf("error no longer unwraps to *controld.ErrorResponse: %v", pf.err)
	}
	if got.ErrorField.Code != controld.InvalidConfigCode {
		t.Errorf("code = %d, want %d (self-uninstall would not trigger)", got.ErrorField.Code, controld.InvalidConfigCode)
	}
}

// TestPermanentAPIRejectionNarrowsToClientErrors is the regression guard for the clean
// exit added above.
//
// controld builds an *ErrorResponse for any non-200 whose body decodes, so the Go type
// says nothing about whether the API's answer will change on a retry. Keying the clean
// exit off the type alone meant a 502 from a load balancer, or an API having a bad ten
// minutes, stopped ctrld on every affected host with no service-manager retry behind it -
// worse than the abnormal exit it replaced, because a Fatal at least gets restarted.
//
// Only a client-error status may take that path.
func TestPermanentAPIRejectionNarrowsToClientErrors(t *testing.T) {
	rejection := func(status, code int) error {
		e := &controld.ErrorResponse{StatusCode: status}
		e.ErrorField.Code = code
		e.ErrorField.Message = "api said no"
		return e
	}

	tests := []struct {
		name          string
		err           error
		wantPermanent bool
	}{
		{
			// The case the clean exit exists for: the device is gone, and every restart
			// will be told the same thing.
			name:          "deleted device",
			err:           rejection(http.StatusNotFound, controld.InvalidConfigCode),
			wantPermanent: true,
		},
		{"revoked credentials", rejection(http.StatusUnauthorized, 0), true},
		{"forbidden", rejection(http.StatusForbidden, 0), true},
		{"malformed request", rejection(http.StatusBadRequest, 0), true},

		// Server-side trouble. These must keep the abnormal exit so the service
		// manager's recovery policy retries.
		{"bad gateway", rejection(http.StatusBadGateway, 0), false},
		{"internal error", rejection(http.StatusInternalServerError, 0), false},
		{"service unavailable", rejection(http.StatusServiceUnavailable, 0), false},

		// 4xx, but both are the API asking for a later attempt rather than refusing
		// this configuration.
		{"request timeout", rejection(http.StatusRequestTimeout, 0), false},
		{"rate limited", rejection(http.StatusTooManyRequests, 0), false},

		// An *ErrorResponse built without a recorded status carries no verdict. A
		// hand-constructed one, or a decode path that forgets to record the status,
		// must not silently gain the clean exit.
		{"no recorded status", rejection(0, controld.InvalidConfigCode), false},

		// Not an API answer at all: the incident's denied socket reaches Fatal.
		{"network failure", retryableNetworkErr(), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := permanentAPIRejection(tc.err)
			if ok != tc.wantPermanent {
				t.Errorf("permanentAPIRejection() = %v, want %v", ok, tc.wantPermanent)
			}
			if ok && got == nil {
				t.Error("a permanent rejection must return the rejection for reporting")
			}
		})
	}

	// The wrapped form matters too: preflight composes the fetch error, and errors.As has
	// to reach through that for either branch to be chosen correctly.
	wrapped := fmt.Errorf("processCDFlags: %w", rejection(http.StatusNotFound, controld.InvalidConfigCode))
	if _, ok := permanentAPIRejection(wrapped); !ok {
		t.Error("a wrapped API rejection must still be recognised")
	}
	wrappedTransient := fmt.Errorf("processCDFlags: %w", rejection(http.StatusBadGateway, 0))
	if _, ok := permanentAPIRejection(wrappedTransient); ok {
		t.Error("a wrapped 502 must not be treated as a permanent rejection")
	}
}

func TestStopRequested(t *testing.T) {
	closedCh := make(chan struct{})
	close(closedCh)

	if stopRequested(nil) {
		t.Error("a nil stop channel must read as no stop (mobile passes none)")
	}
	if stopRequested(make(chan struct{})) {
		t.Error("an open stop channel must read as no stop")
	}
	if !stopRequested(closedCh) {
		t.Error("a closed stop channel must read as a stop")
	}
}

// TestReloadFetchIsBoundedByServiceLifetime covers the reload path's stop wiring.
//
// Reload fetches the ControlD config too, and it used to build the bounded context
// itself. Nothing tested that: the wrong channel, or a dropped cancel, would have left a
// reload retrying against an unreachable API after "service stopped" was logged, and no
// test would have failed. Both paths now go through one bounded fetch, so this pins it.
func TestReloadFetchIsBoundedByServiceLifetime(t *testing.T) {
	original := processCDFlagsFn
	t.Cleanup(func() { processCDFlagsFn = original })

	t.Run("a stop request cancels the reload fetch", func(t *testing.T) {
		stopCh := make(chan struct{})
		close(stopCh)

		var sawCancelled bool
		processCDFlagsFn = func(ctx context.Context, _ *ctrld.Config) (*controld.ResolverConfig, error) {
			select {
			case <-ctx.Done():
				sawCancelled = true
			case <-time.After(2 * time.Second):
			}
			return nil, ctx.Err()
		}

		p := &prog{stopCh: stopCh}
		if _, err := p.fetchCDConfigBoundedByLifetime(&ctrld.Config{}); !errors.Is(err, context.Canceled) {
			t.Errorf("reload fetch err = %v, want %v", err, context.Canceled)
		}
		if !sawCancelled {
			t.Error("the reload fetch did not observe the stop request: it is not bound to the service lifetime")
		}
	})

	t.Run("the derived context is always released", func(t *testing.T) {
		// stopCh stays open: the fetch's own cancel is what must end the watcher, or
		// every reload leaks a goroutine.
		var captured context.Context
		processCDFlagsFn = func(ctx context.Context, _ *ctrld.Config) (*controld.ResolverConfig, error) {
			captured = ctx
			return nil, nil
		}

		p := &prog{stopCh: make(chan struct{})}
		if _, err := p.fetchCDConfigBoundedByLifetime(&ctrld.Config{}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		select {
		case <-captured.Done():
		case <-time.After(time.Second):
			t.Error("the reload fetch left its context uncancelled")
		}
	})
}
