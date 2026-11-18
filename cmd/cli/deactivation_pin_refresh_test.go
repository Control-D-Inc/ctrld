package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
)

// On mobile, an app can stop a run and start the next one while a PIN refresh
// of the old run waits for the API. The late answer must not write the PIN of
// the old run over the PIN of the next run, and the stopped request must not
// be checked against the PIN of the next run.
func TestDeactivationPinAnswerAfterServerStopKeepsGlobals(t *testing.T) {
	isolateDeactivationPinState(t)
	// The values differ from what the late answer stores, so a late write
	// changes both.
	const nextRunPin, oldRunPin, wrongPin = int64(1111), int64(2222), int64(3333)
	cdDeactivationPin.Store(nextRunPin)
	deactivationPinKnown.Store(false)
	// One more wrong PIN locks deactivation, so a late check of the wrong PIN
	// below would show in the lockout counters.
	const failedBefore = deactivationMaxFailedAttempts - 1
	deactivationFailedAttempts.Store(failedBefore)

	// The stub ignores its context. It stands for an answer that is already on
	// its way back when the stop comes.
	fetchStarted := make(chan context.Context, 1)
	releaseFetch := make(chan struct{})
	fetchResolverConfig = func(ctx context.Context, _ *controld.ResolverConfigRequest, _ bool) (*controld.ResolverConfig, error) {
		fetchStarted <- ctx
		<-releaseFetch
		pin := oldRunPin
		return &controld.ResolverConfig{DeactivationPin: &pin}, nil
	}

	cs, sock := startDeactivationTestServer(t)

	type answer struct {
		status int
		err    error
	}
	answered := make(chan answer, 1)
	go func() {
		status, err := postDeactivationPin(sock, wrongPin)
		answered <- answer{status, err}
	}()

	var fetchCtx context.Context
	select {
	case fetchCtx = <-fetchStarted:
	case <-time.After(5 * time.Second):
		close(releaseFetch)
		t.Fatal("the deactivation handler never reached the fetch")
	}

	stopped := make(chan struct{})
	go func() {
		_ = cs.stop()
		close(stopped)
	}()

	select {
	case <-fetchCtx.Done():
	case <-time.After(3 * time.Second):
		t.Error("the stop of the control server did not end the context of the PIN fetch")
	}

	close(releaseFetch)
	var late answer
	select {
	case late = <-answered:
	case <-time.After(5 * time.Second):
		t.Fatal("the deactivation handler did not answer after the fetch returned")
	}
	<-stopped

	require.NoError(t, late.err)
	if late.status != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d: a stopped request was still decided", late.status, http.StatusServiceUnavailable)
	}
	if got := deactivationFailedAttempts.Load(); got != failedBefore {
		t.Errorf("deactivationFailedAttempts = %d, want %d: a stopped request counted a wrong PIN", got, failedBefore)
	}
	if deactivationLockedUntil.Load() != 0 {
		t.Error("deactivationLockedUntil is set: a stopped request locked deactivation")
	}

	if got := cdDeactivationPin.Load(); got != nextRunPin {
		t.Errorf("cdDeactivationPin = %d, want %d: the answer of a stopped request wrote the PIN", got, nextRunPin)
	}
	if deactivationPinKnown.Load() {
		t.Error("deactivationPinKnown = true: the answer of a stopped request marked the PIN as known")
	}
}

// The request context of a running control server must stay live, so that
// the refresh stores the answer: a new PIN, and the default when the API has
// no PIN.
func TestDeactivationPinAnswerOfLiveRequestIsStored(t *testing.T) {
	isolateDeactivationPinState(t)
	cdDeactivationPin.Store(defaultDeactivationPin)
	deactivationPinKnown.Store(false)

	const apiPin = int64(2222)
	answer := &controld.ResolverConfig{DeactivationPin: new(int64)}
	*answer.DeactivationPin = apiPin
	fetchResolverConfig = func(context.Context, *controld.ResolverConfigRequest, bool) (*controld.ResolverConfig, error) {
		return answer, nil
	}

	_, sock := startDeactivationTestServer(t)

	status, err := postDeactivationPin(sock, apiPin)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status, "the PIN of the API answer did not authorize the deactivation")
	require.Equal(t, apiPin, cdDeactivationPin.Load(), "the answer of a live request did not store the PIN")
	require.True(t, deactivationPinKnown.Load(), "the answer of a live request did not mark the PIN as known")

	answer = &controld.ResolverConfig{}
	status, err = postDeactivationPin(sock, defaultDeactivationPin)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status, "a device with no PIN could not be deactivated")
	require.Equal(t, int64(defaultDeactivationPin), cdDeactivationPin.Load(), "an answer with no PIN did not clear the old PIN")
}

// isolateDeactivationPinState gives the test its own resolver UID and PIN
// state, and puts back the fetch seam and the PIN globals when the test ends.
func isolateDeactivationPinState(t *testing.T) {
	t.Helper()
	oldFetch, oldUID := fetchResolverConfig, cdUID
	oldPin, oldKnown := cdDeactivationPin.Load(), deactivationPinKnown.Load()
	t.Cleanup(func() {
		fetchResolverConfig, cdUID = oldFetch, oldUID
		cdDeactivationPin.Store(oldPin)
		deactivationPinKnown.Store(oldKnown)
		deactivationLockedUntil.Store(0)
		deactivationFailedAttempts.Store(0)
	})
	cdUID = "test-uid"
	deactivationLockedUntil.Store(0)
	deactivationFailedAttempts.Store(0)
}

// startDeactivationTestServer serves the real control server handlers on a
// test socket.
func startDeactivationTestServer(t *testing.T) (*controlServer, string) {
	t.Helper()
	_, sock, cs := newTestControlServer(t)
	p := &prog{cs: cs, pinCodeValidCh: make(chan struct{}, 1)}
	p.logger.Store(discardLogger())
	p.registerControlServerHandler()
	require.NoError(t, cs.start())
	return cs, sock
}

func postDeactivationPin(sock string, pin int64) (int, error) {
	body, _ := json.Marshal(&deactivationRequest{Pin: pin})
	resp, err := newControlClient(sock).post(deactivationPath, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

// On mobile, the PIN globals outlive a run. When the API answers the start of
// the next run with no PIN, the PIN of the old run must not stay.
func TestStartupAnswerWithNoPinClearsTheOldPin(t *testing.T) {
	isolateDeactivationPinState(t)
	cdDeactivationPin.Store(1111)
	deactivationPinKnown.Store(true)
	fetchResolverConfig = func(context.Context, *controld.ResolverConfigRequest, bool) (*controld.ResolverConfig, error) {
		return &controld.ResolverConfig{}, nil
	}

	_, _ = processCDFlagsRuntime(context.Background(), &ctrld.Config{})

	require.Equal(t, int64(defaultDeactivationPin), cdDeactivationPin.Load(), "a start whose answer has no PIN kept the PIN of the old run")
	require.True(t, deactivationPinKnown.Load())
}
