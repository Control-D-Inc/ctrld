package cli

import (
	"testing"
	"time"
)

// interceptStateStub stands in for the platform pfState/wfpState; the
// recovery cleanup path only checks dnsInterceptState != nil.
type interceptStateStub struct{}

// setupInterceptRecovery puts p into "intercept-mode recovery in flight"
// state and restores the package-level dnsIntercept flag on cleanup.
func setupInterceptRecovery(t *testing.T, p *prog) {
	t.Helper()
	oldIntercept := dnsIntercept
	dnsIntercept = true
	t.Cleanup(func() { dnsIntercept = oldIntercept })
	p.dnsInterceptState = &interceptStateStub{}
	p.recoveryBypass.Store(true)
	p.recoveryRunning.Store(true)
	p.recoveryCancel = func() {}
}

// TestRecoveryCanceledCleanup_LastRecoveryResetsState pins issue #597: a
// canceled recovery with no successor must clear recoveryBypass and
// recoveryRunning, or the daemon stays in bypass forever (every query
// detours to the OS resolver) and the DNS watchdog stays disabled.
func TestRecoveryCanceledCleanup_LastRecoveryResetsState(t *testing.T) {
	p := &prog{}
	setupInterceptRecovery(t, p)
	gen := p.recoveryGen.Add(1)

	p.recoveryCanceledCleanup(gen)

	if p.recoveryBypass.Load() {
		t.Error("recoveryBypass still set after canceled recovery with no successor")
	}
	if p.recoveryRunning.Load() {
		t.Error("recoveryRunning still set after canceled recovery with no successor")
	}
	p.recoveryCancelMu.Lock()
	cancelCleared := p.recoveryCancel == nil
	p.recoveryCancelMu.Unlock()
	if !cancelCleared {
		t.Error("recoveryCancel not cleared after canceled recovery with no successor")
	}
}

// TestRecoveryCanceledCleanup_SupersededKeepsSuccessorState pins the
// captive-portal/network-flap contract: when a newer recovery superseded the
// canceled one, the canceled recovery must NOT clear shared state — the
// successor owns bypass for its own duration.
func TestRecoveryCanceledCleanup_SupersededKeepsSuccessorState(t *testing.T) {
	p := &prog{}
	setupInterceptRecovery(t, p)
	gen := p.recoveryGen.Add(1)
	// A successor recovery started.
	p.recoveryGen.Add(1)

	p.recoveryCanceledCleanup(gen)

	if !p.recoveryBypass.Load() {
		t.Error("superseded canceled recovery cleared recoveryBypass owned by its successor")
	}
	if !p.recoveryRunning.Load() {
		t.Error("superseded canceled recovery cleared recoveryRunning owned by its successor")
	}
	p.recoveryCancelMu.Lock()
	cancelKept := p.recoveryCancel != nil
	p.recoveryCancelMu.Unlock()
	if !cancelKept {
		t.Error("superseded canceled recovery cleared the successor's recoveryCancel")
	}
}

// TestRecoveryCanceledCleanup_NonInterceptResetsRunning covers traditional
// (non-intercept) mode: recoveryRunning must still be reset so watchdogs
// resume, while bypass is untouched (it is never set in that mode).
func TestRecoveryCanceledCleanup_NonInterceptResetsRunning(t *testing.T) {
	oldIntercept := dnsIntercept
	dnsIntercept = false
	t.Cleanup(func() { dnsIntercept = oldIntercept })

	p := &prog{}
	p.recoveryRunning.Store(true)
	p.recoveryCancel = func() {}
	gen := p.recoveryGen.Add(1)

	p.recoveryCanceledCleanup(gen)

	if p.recoveryRunning.Load() {
		t.Error("recoveryRunning still set after canceled non-intercept recovery")
	}
}

func TestBeginRecoveryTransfersOwnershipAtomically(t *testing.T) {
	oldIntercept := dnsIntercept
	dnsIntercept = true
	t.Cleanup(func() { dnsIntercept = oldIntercept })

	p := &prog{dnsInterceptState: &interceptStateStub{}}
	firstCtx, firstGen, _, ok := p.beginRecovery(RecoveryReasonRegularFailure)
	if !ok {
		t.Fatal("first recovery did not acquire ownership")
	}
	if _, _, _, ok := p.beginRecovery(RecoveryReasonRegularFailure); ok {
		t.Fatal("duplicate upstream recovery acquired ownership")
	}

	_, successorGen, intercept, ok := p.beginRecovery(RecoveryReasonNetworkChange)
	if !ok || !intercept || successorGen <= firstGen {
		t.Fatalf("network recovery did not replace owner: first=%d successor=%d intercept=%v ok=%v", firstGen, successorGen, intercept, ok)
	}
	select {
	case <-firstCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("successor did not cancel the previous recovery")
	}

	p.recoveryCanceledCleanup(firstGen)
	if !p.recoveryRunning.Load() || !p.recoveryBypass.Load() || !p.recoveryOwnsState(successorGen) {
		t.Fatal("stale cleanup changed successor-owned recovery state")
	}
	if !p.completeRecovery(successorGen) {
		t.Fatal("successor could not complete its own recovery state")
	}
}

func TestRecoveryCleanupClearsBypassAfterInterceptStateDisappears(t *testing.T) {
	p := &prog{}
	p.recoveryBypass.Store(true)
	p.recoveryRunning.Store(true)
	p.recoveryCancel = func() {}
	gen := p.recoveryGen.Add(1)

	p.recoveryCanceledCleanup(gen)
	if p.recoveryBypass.Load() || p.recoveryRunning.Load() {
		t.Fatal("cleanup retained recovery flags after intercept state disappeared")
	}
}

func TestSystemNameserversForInterceptRetryNormalizesEmptyDiscovery(t *testing.T) {
	original := initializeOsResolverWithSystemNameserversFn
	called := false
	initializeOsResolverWithSystemNameserversFn = func(guard bool) ([]string, []string) {
		called = true
		if !guard {
			t.Error("intercept retry discovery did not guard the existing resolver")
		}
		return nil, nil
	}
	t.Cleanup(func() { initializeOsResolverWithSystemNameserversFn = original })

	if got := systemNameserversForInterceptRetry(); got == nil || len(got) != 0 {
		t.Fatalf("system discovery = %#v, want non-nil empty slice", got)
	}
	if !called {
		t.Fatal("system discovery was not called")
	}
}
