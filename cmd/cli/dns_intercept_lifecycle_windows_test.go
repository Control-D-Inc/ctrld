//go:build windows

package cli

import (
	"runtime"
	"testing"
	"time"
)

// newInterceptTestProg returns a prog with a published intercept state, fake NRPT
// operations already installed, and no WFP engine (engineHandle 0).
//
// The fake is installed here, before anything can inspect registry state, and it is the
// safety boundary - not the empty wfpState. A zero-valued state has owner None, and
// shutdown's None branch sweeps orphaned ctrld rules, so an unfaked stopDNSIntercept would
// reach the production nrptCatchAllRuleExists / removeNRPTCatchAllRule / signalNRPTChange.
// On a host that has ctrld's deterministic key - a developer box, or a CI runner where
// ctrld is installed - that deletes live policy and forces a Group Policy refresh, a
// Dnscache paramchange and a cache flush. A green run on a clean runner proves nothing
// about that.
func newInterceptTestProg(t *testing.T) (*prog, *wfpState, *fakeNRPTOps) {
	t.Helper()
	f := fakeNRPTOpsForTest(t)
	// Prove the fake is in effect before anything can inspect registry state. Asserting
	// zero side effects afterwards cannot do that: an uninstalled fake reports zero
	// whether it was consulted or bypassed.
	requireFakeNRPTOpsInstalled(t, f)
	state := &wfpState{stopCh: make(chan struct{}), listenerIP: "127.0.0.1"}
	p := &prog{}
	p.dnsInterceptState = state
	return p, state, f
}

// assertNoNRPTSideEffects fails when a lifecycle path wrote NRPT policy or signalled the
// DNS Client. Every test in this file exercises a guard that is supposed to stand down, so
// any registry write or signal here means the guard did not hold - and, without the fake,
// would have hit the host's real policy.
func assertNoNRPTSideEffects(t *testing.T, f *fakeNRPTOps) {
	t.Helper()
	add, remove, signal, _ := f.counts()
	if add != 0 || remove != 0 || signal != 0 {
		t.Errorf("addRule = %d, removeRule = %d, signal = %d, want 0/0/0: this path must not write NRPT policy",
			add, remove, signal)
	}
	if flush := f.flushCount(); flush != 0 {
		t.Errorf("flush calls = %d, want 0: this path must not flush the resolver cache", flush)
	}
}

// TestStopDNSInterceptRevokesBeforeTeardown pins the ordering the shutdown/monitor race
// depends on. Teardown deletes our WFP sublayer, and a missing sublayer is precisely what
// the health monitor treats as "our filters were wiped, rebuild everything". Were the
// state revoked only after teardown, a monitor tick inside that window would rebuild the
// intercept during shutdown.
func TestStopDNSInterceptRevokesBeforeTeardown(t *testing.T) {
	p, state, f := newInterceptTestProg(t)
	defer assertNoNRPTSideEffects(t, f)

	if p.interceptStateRevoked(state) {
		t.Fatal("a freshly published intercept state must not read as retired")
	}
	if err := p.stopDNSIntercept(); err != nil {
		t.Fatalf("stopDNSIntercept() = %v", err)
	}
	if !p.interceptStateRevoked(state) {
		t.Error("state still reads live after shutdown: the monitor and heal flows would keep writing host DNS state")
	}
	if p.dnsInterceptState != nil {
		t.Error("dnsInterceptState survived shutdown")
	}
	if p.dnsInterceptStopRequested.Load() {
		t.Error("stop-requested flag was left set; a later start would see a phantom shutdown")
	}
}

// TestRebuildDNSInterceptRefusedAfterShutdown is the regression test for the reported
// race: SCM stop runs resetDNS -> stopDNSIntercept while the health monitor is mid-tick,
// and the monitor then reaches the rebuild path before the process exits. The rebuild
// must refuse - completing it would re-add the NRPT catch-all and the WFP filters moments
// before ctrld disappears, leaving Windows resolving through a listener that is gone.
//
// That refusal is also what keeps this test safe on a real Windows host: a rebuild that
// did not refuse would run startDNSIntercept and write NRPT policy to the machine
// running the tests.
func TestRebuildDNSInterceptRefusedAfterShutdown(t *testing.T) {
	p, state, f := newInterceptTestProg(t)
	defer assertNoNRPTSideEffects(t, f)
	if err := p.stopDNSIntercept(); err != nil {
		t.Fatalf("stopDNSIntercept() = %v", err)
	}

	if got := p.rebuildDNSIntercept(state, "WFP sublayer missing during health check"); got != interceptRebuildRetired {
		t.Fatalf("rebuildDNSIntercept() = %v, want interceptRebuildRetired - a post-shutdown rebuild resurrects DNS interception", got)
	}
	if p.dnsInterceptState != nil {
		t.Error("rebuild published new intercept state after shutdown")
	}
}

// TestRebuildDNSInterceptRefusedForReplacedState covers the other stale-owner case: an
// earlier rebuild already replaced the state, so a goroutine still holding the old one
// must not tear down its successor.
func TestRebuildDNSInterceptRefusedForReplacedState(t *testing.T) {
	p, old, f := newInterceptTestProg(t)
	defer assertNoNRPTSideEffects(t, f)
	current := &wfpState{stopCh: make(chan struct{}), listenerIP: "127.0.0.1"}
	p.dnsInterceptState = current

	if got := p.rebuildDNSIntercept(old, "WFP sublayer missing during health check"); got != interceptRebuildRetired {
		t.Fatalf("rebuildDNSIntercept() = %v, want interceptRebuildRetired for a superseded state", got)
	}
	if p.dnsInterceptState != any(current) {
		t.Error("a superseded state's rebuild replaced the live intercept")
	}
	if p.interceptStateRevoked(current) {
		t.Error("the live state was revoked by a superseded rebuild")
	}
}

// TestRepairMissingWFPStandsDownAfterShutdown checks the monitor's entry point. It must
// not even query WFP for a retired state - the sublayer it looks for is what teardown
// just deleted - and it must tell the monitor goroutine to exit.
func TestRepairMissingWFPStandsDownAfterShutdown(t *testing.T) {
	p, state, f := newInterceptTestProg(t)
	defer assertNoNRPTSideEffects(t, f)
	if err := p.stopDNSIntercept(); err != nil {
		t.Fatalf("stopDNSIntercept() = %v", err)
	}
	// Set the handle only after teardown. A fake handle proves the revocation check
	// comes first, but must never reach the real WFP calls in cleanupWFPFilters.
	state.engineHandle = 1

	if !p.repairMissingWFP(state) {
		t.Error("repairMissingWFP() = false after shutdown; the health monitor would keep running for a dead intercept")
	}
	if p.dnsInterceptState != nil {
		t.Error("repairMissingWFP rebuilt the intercept after shutdown")
	}
}

// TestPendingStopSignalsRevocation covers how a stop avoids waiting: while it is blocked
// on the lifecycle lock it must already read as revoked, so an in-flight NRPT heal
// abandons its probe backoff instead of making the service stop wait it out. A stop that
// waits too long is killed by the Service Control Manager, which cleans up nothing.
func TestPendingStopSignalsRevocation(t *testing.T) {
	p, state, f := newInterceptTestProg(t)
	defer assertNoNRPTSideEffects(t, f)

	p.dnsInterceptMu.Lock()
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		_ = p.stopDNSIntercept()
	}()

	// Wait for the stop to announce itself while it is blocked on the lock.
	deadline := time.Now().Add(5 * time.Second)
	for !p.dnsInterceptStopRequested.Load() {
		if time.Now().After(deadline) {
			p.dnsInterceptMu.Unlock()
			<-stopped
			t.Fatal("stop never announced itself before waiting for the lifecycle lock")
		}
		runtime.Gosched()
	}
	if !p.interceptStateRevoked(state) {
		t.Error("a pending stop does not read as revoked; the heal flows would keep it waiting")
	}
	p.dnsInterceptMu.Unlock()
	<-stopped

	if p.dnsInterceptState != nil {
		t.Error("the pending stop did not tear down the intercept once it acquired the lock")
	}
}

// TestInterceptWaitAbandonsPromptlyOnPendingStop is the bound on how long a stop can be
// delayed by a recovery flow: the heal sequence's waits add up to tens of seconds, and
// each one must end as soon as a stop is pending.
func TestInterceptWaitAbandonsPromptlyOnPendingStop(t *testing.T) {
	p, state, f := newInterceptTestProg(t)
	defer assertNoNRPTSideEffects(t, f)
	p.dnsInterceptStopRequested.Store(true)

	start := time.Now()
	if p.interceptWait(state, 30*time.Second) {
		t.Fatal("interceptWait() = true with a stop pending; the caller would carry on writing host DNS state")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("interceptWait took %v to notice a pending stop; shutdown would inherit that delay", elapsed)
	}
}

// TestInterceptWaitRunsToCompletionWhileLive guards the other direction: the cancellable
// wait must still actually wait, or the recovery flows lose their backoff.
func TestInterceptWaitRunsToCompletionWhileLive(t *testing.T) {
	p, state, f := newInterceptTestProg(t)
	defer assertNoNRPTSideEffects(t, f)

	start := time.Now()
	if !p.interceptWait(state, 250*time.Millisecond) {
		t.Fatal("interceptWait() = false for a live intercept")
	}
	if elapsed := time.Since(start); elapsed < 250*time.Millisecond {
		t.Errorf("interceptWait returned after %v, want at least 250ms", elapsed)
	}
}

// TestNRPTNeedsCtrldActivation covers the recovery gap that left a machine unfiltered
// until restart: a failed NRPT write clears ownership, and an owner-None tick used to do
// nothing at all, so nothing ever retried the write.
func TestNRPTNeedsCtrldActivation(t *testing.T) {
	tests := []struct {
		name       string
		owner      nrptRuleOwner
		ruleExists bool
		want       bool
	}{
		{
			// The reported hole: activation failed, ownership was cleared, and no
			// other path re-arms it. In hard mode WFP keeps blocking DNS meanwhile.
			name:  "no owner retries the failed write",
			owner: nrptRuleOwnerNone,
			want:  true,
		},
		{
			name:       "no owner retries even if a rule is somehow present",
			owner:      nrptRuleOwnerNone,
			ruleExists: true,
			want:       true,
		},
		{
			name:  "ctrld-owned rule removed externally is re-added",
			owner: nrptRuleOwnerCtrld,
			want:  true,
		},
		{
			name:       "healthy ctrld-owned rule is left alone",
			owner:      nrptRuleOwnerCtrld,
			ruleExists: true,
			want:       false,
		},
		{
			// Writing beside external policy would be ambiguous policy, not recovery.
			name:  "external policy is never overwritten",
			owner: nrptRuleOwnerGroupPolicy,
			want:  false,
		},
		{
			name:       "external policy is never overwritten even with a ctrld rule present",
			owner:      nrptRuleOwnerGroupPolicy,
			ruleExists: true,
			want:       false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := nrptNeedsCtrldActivation(tc.owner, tc.ruleExists); got != tc.want {
				t.Errorf("nrptNeedsCtrldActivation(%v, %v) = %v, want %v", tc.owner, tc.ruleExists, got, tc.want)
			}
		})
	}
}

// TestActivateCtrldNRPTFallbackRefusedAfterShutdown guards the worst leftover. A
// catch-all re-added after shutdown points every DNS query on the machine at a listener
// that no longer exists, so nothing resolves at all. Refusing early also keeps this test
// from writing NRPT policy on the machine running it.
func TestActivateCtrldNRPTFallbackRefusedAfterShutdown(t *testing.T) {
	p, state, f := newInterceptTestProg(t)
	defer assertNoNRPTSideEffects(t, f)
	if err := p.stopDNSIntercept(); err != nil {
		t.Fatalf("stopDNSIntercept() = %v", err)
	}

	if p.activateCtrldNRPTFallback(state, "ctrld-owned rule missing during health check") {
		t.Error("activateCtrldNRPTFallback() = true after shutdown: the catch-all would outlive ctrld")
	}
	if owner, _ := state.nrptPolicyOwner(); owner != nrptRuleOwnerNone {
		t.Errorf("NRPT owner = %v after a refused fallback, want nrptRuleOwnerNone", owner)
	}
}

// TestAllowHandbackAttemptRateLimits covers the throttle on testing an external
// catch-all. Each attempt takes ctrld's rule out of the way for a probe, so a rule that
// never routes would cost a brief DNS outage on every 30s health tick without this - in
// hard mode a window where WFP blocks DNS and nothing redirects it.
func TestHandbackThrottleIsPerRule(t *testing.T) {
	state := &wfpState{stopCh: make(chan struct{})}
	now := time.Now()

	if !state.handbackAllowed(now, "{GP-RULE}", nrptHandbackRetryInterval) {
		t.Fatal("first handback attempt must be allowed")
	}
	// Checking alone must not spend the budget: a pre-probe can still abort the attempt
	// without disturbing NRPT, and that must not cost the rule its next window.
	if !state.handbackAllowed(now, "{GP-RULE}", nrptHandbackRetryInterval) {
		t.Error("handbackAllowed must not consume the budget by itself")
	}

	state.recordHandbackAttempt(now, "{GP-RULE}", nrptHandbackRetryInterval)
	if state.handbackAllowed(now.Add(nrptHandbackRetryInterval-time.Second), "{GP-RULE}", nrptHandbackRetryInterval) {
		t.Error("re-testing the same rule inside the interval must be suppressed")
	}
	// Group Policy alternating between two names must not erase either one's memory:
	// with a single slot every swap costs another removal of the live rule.
	if !state.handbackAllowed(now.Add(time.Second), "{OTHER-RULE}", nrptHandbackRetryInterval) {
		t.Error("a different rule name means the administrator changed policy: test it now")
	}
	state.recordHandbackAttempt(now.Add(time.Second), "{OTHER-RULE}", nrptHandbackRetryInterval)
	if state.handbackAllowed(now.Add(2*time.Second), "{GP-RULE}", nrptHandbackRetryInterval) {
		t.Error("testing another rule must not clear the first rule's throttle")
	}

	if !state.handbackAllowed(now.Add(2*nrptHandbackRetryInterval), "{GP-RULE}", nrptHandbackRetryInterval) {
		t.Error("the same rule must be testable again after the interval")
	}
}
