//go:build windows

package cli

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Control-D-Inc/ctrld"
)

// fakeNRPTOps records the Windows side effects a transition would cause and serves
// scripted probe results, so the ownership decisions can be driven without touching the
// registry or the DNS Client.
type fakeNRPTOps struct {
	mu sync.Mutex

	// probeResults is consumed in order; the last value repeats once exhausted.
	probeResults []bool
	probeCalls   int
	flushCalls   int

	gpRule          string // rule name findGPRule reports, "" for none
	gpConflict      bool   // whether an external catch-all targets another resolver
	parentEmpty     bool   // whether the GP parent key reads as present but empty
	cleanCalls      int
	gpConflictCalls int
	ctrldRule       bool // whether ctrld's own catch-all exists
	existsCalls     int
	addCalls        int
	removeCalls     int
	signalCalls     int

	addErr    error
	removeErr error

	// beforeAdd runs inside addRule, while the transition lock is held.
	beforeAdd func()
	// onProbe runs after the nth probe (1-based) is answered, so a test can change the
	// GP store mid-probe the way a Group Policy refresh would.
	onProbe func(call int)
	// onGPConflicts runs after each gpConflicts check, which is the last ops call before
	// the two-phase re-add queues for the transition lock.
	onGPConflicts func(call int)
	// waitHook stands in for a cancellable wait: returning false models the intercept
	// being retired mid-wait.
	waitHook func() bool
}

func (f *fakeNRPTOps) ops() *nrptOps {
	return &nrptOps{
		probe: func(*wfpState) bool {
			f.mu.Lock()
			f.probeCalls++
			call := f.probeCalls
			result := false
			if len(f.probeResults) > 0 {
				result = f.probeResults[0]
				if len(f.probeResults) > 1 {
					f.probeResults = f.probeResults[1:]
				}
			}
			onProbe := f.onProbe
			f.mu.Unlock()
			if onProbe != nil {
				onProbe(call)
			}
			return result
		},
		ruleExists: func() bool {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.existsCalls++
			return f.ctrldRule
		},
		addRule: func(string) error {
			f.mu.Lock()
			beforeAdd, err := f.beforeAdd, f.addErr
			f.addCalls++
			if err == nil {
				f.ctrldRule = true
			}
			f.mu.Unlock()
			if beforeAdd != nil {
				beforeAdd()
			}
			return err
		},
		removeRule: func() error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.removeCalls++
			if f.removeErr != nil {
				return f.removeErr
			}
			f.ctrldRule = false
			return nil
		},
		signal: func() {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.signalCalls++
		},
		findGPRule: func(string) string {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.gpRule
		},
		gpRuleMatches: func(ruleName, _ string) bool {
			f.mu.Lock()
			defer f.mu.Unlock()
			return ruleName != "" && ruleName == f.gpRule
		},
		gpConflicts: func(*wfpState, string) bool {
			f.mu.Lock()
			f.gpConflictCalls++
			call := f.gpConflictCalls
			conflict, hook := f.gpConflict, f.onGPConflicts
			f.mu.Unlock()
			if hook != nil {
				hook(call)
			}
			return conflict
		},
		loopback: func(*wfpState) error { return nil },
		// No real waiting in tests; report "still live" unless a test says otherwise.
		wait: func(*wfpState, time.Duration) bool {
			f.mu.Lock()
			hook := f.waitHook
			f.mu.Unlock()
			if hook != nil {
				return hook()
			}
			return true
		},
		startWFP: func(*wfpState) error { return nil },
		flush: func() {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.flushCalls++
		},
		parentEmpty: func(string) bool {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.parentEmpty
		},
		cleanParent: func() bool {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.cleanCalls++
			wasEmpty := f.parentEmpty
			f.parentEmpty = false
			return wasEmpty
		},
	}
}

func (f *fakeNRPTOps) counts() (add, remove, signal, probe int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.addCalls, f.removeCalls, f.signalCalls, f.probeCalls
}

func (f *fakeNRPTOps) ruleExistsCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.existsCalls
}

func (f *fakeNRPTOps) flushCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.flushCalls
}

// setGPRule replaces what the fake GP store reports, as a policy refresh would.
func (f *fakeNRPTOps) setGPRule(ruleName string, conflicting bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gpRule = ruleName
	f.gpConflict = conflicting
}

// hasCtrldRule reports whether ctrld's catch-all is currently installed.
func (f *fakeNRPTOps) hasCtrldRule() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ctrldRule
}

// installedFakeNRPTOps is the fake currently standing in for the production NRPT
// operations, so fixtures can hand it to tests and can tell whether one is installed at
// all.
var installedFakeNRPTOps *fakeNRPTOps

// installFakeNRPTOps swaps in the fake for the duration of the test.
func installFakeNRPTOps(t *testing.T, f *fakeNRPTOps) {
	t.Helper()
	nrptOpsForTest = f.ops()
	installedFakeNRPTOps = f
	t.Cleanup(func() {
		nrptOpsForTest = nil
		installedFakeNRPTOps = nil
	})
}

// fakeNRPTSeed is the starting state a test wants the fixture's fake to have. It is a
// separate type so the fake - which carries a mutex - is never copied.
type fakeNRPTSeed struct {
	probeResults []bool
	gpRule       string
	gpConflict   bool
	parentEmpty  bool
	ctrldRule    bool
	addErr       error
	removeErr    error
}

// configure re-arms the fake the fixture installed with a test's own starting state, so
// the fixture keeps ownership of installation - and therefore of the production-call guard.
func (f *fakeNRPTOps) configure(seed fakeNRPTSeed) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.probeResults = seed.probeResults
	f.gpRule = seed.gpRule
	f.gpConflict = seed.gpConflict
	f.parentEmpty = seed.parentEmpty
	f.ctrldRule = seed.ctrldRule
	f.addErr = seed.addErr
	f.removeErr = seed.removeErr
}

// requireFakeNRPTOpsInstalled proves the fake is the table production code will actually
// consult, and fails the test immediately if it is not.
//
// Identity is not enough on its own, and neither is asserting side-effect counters after
// the fact: a fixture that never installed the fake, or a seam that stopped consulting the
// override, leaves those counters at zero and every "no side effects" assertion passes
// while the real registry and signalling functions run. So this calls through
// prog.nrptOps() and requires the call to land on the fake. The probe is only made once an
// override is known to exist, so it can never reach the host itself.
func requireFakeNRPTOpsInstalled(t *testing.T, f *fakeNRPTOps) {
	t.Helper()
	if err := checkFakeNRPTOpsInstalled(f); err != nil {
		t.Fatal(err)
	}
}

// checkFakeNRPTOpsInstalled is the precondition itself, as a predicate so it can be tested
// like any other logic - see TestFakeNRPTOpsPreconditionDetectsBypass. It returns nil only
// when f is the table prog.nrptOps() hands out.
func checkFakeNRPTOpsInstalled(f *fakeNRPTOps) error {
	if nrptOpsForTest == nil {
		return errors.New("fake NRPT operations are not installed: production registry and signalling functions would run")
	}
	if installedFakeNRPTOps != f {
		return errors.New("the installed fake is not the one this fixture returned")
	}
	before := f.ruleExistsCount()
	_ = (&prog{}).nrptOps().ruleExists()
	if f.ruleExistsCount() == before {
		return errors.New("prog.nrptOps() did not route to the installed fake: the seam is not in effect")
	}
	return nil
}

// fakeNRPTOpsForTest returns the installed fake, installing a default one if the test has
// not already done so.
//
// Every fixture goes through this before publishing state, so no test can reach the
// production registry and signalling functions. That matters because those are not
// read-only: on a host where ctrld's deterministic key exists, one unfaked call can delete
// live NRPT policy and force a Group Policy refresh, a Dnscache paramchange and a cache
// flush. A clean runner is not a safety boundary.
func fakeNRPTOpsForTest(t *testing.T) *fakeNRPTOps {
	t.Helper()
	if installedFakeNRPTOps != nil {
		return installedFakeNRPTOps
	}
	f := &fakeNRPTOps{}
	installFakeNRPTOps(t, f)
	return f
}

func newHandbackTestProg(t *testing.T) (*prog, *wfpState, *fakeNRPTOps) {
	t.Helper()
	// Never let a test fall through to the production NRPT operations, and prove it here
	// rather than trusting that installation happened.
	f := fakeNRPTOpsForTest(t)
	requireFakeNRPTOpsInstalled(t, f)
	state := &wfpState{stopCh: make(chan struct{}), listenerIP: "127.0.0.1"}
	p := &prog{}
	p.dnsInterceptState = state
	return p, state, f
}

// TestHandbackRestoresFallbackWhenGPCannotRoute is the behaviour test for the handback
// contract. The first probe runs while ctrld's fallback is still installed, so that
// fallback can satisfy it; only a probe taken after ctrld's keys are gone says anything
// about the GP rule. With results [true, false] - the GP child looks fine until ctrld
// steps aside - the transition must put ctrld's rule back and keep ctrld ownership.
//
// Getting this wrong deletes the last working route and declares external ownership: in
// hard mode a machine-wide DNS outage, because WFP keeps blocking outbound DNS with
// nothing redirecting it to ctrld.
func TestHandbackRestoresFallbackWhenGPCannotRoute(t *testing.T) {
	f := &fakeNRPTOps{probeResults: []bool{true, false}, gpRule: "{GP-RULE}", ctrldRule: true}
	installFakeNRPTOps(t, f)

	p, state, _ := newHandbackTestProg(t)
	state.setNRPTPolicyOwner(nrptRuleOwnerCtrld, "")

	if got := p.tryAdoptMatchingGPNRPT(state); got {
		t.Error("tryAdoptMatchingGPNRPT() = true for a GP rule that cannot route without ctrld's rule")
	}
	if owner, _ := state.nrptPolicyOwner(); owner != nrptRuleOwnerCtrld {
		t.Errorf("NRPT owner = %v, want nrptRuleOwnerCtrld: ownership must not move to a rule that failed the post-removal probe", owner)
	}
	add, remove, _, _ := f.counts()
	if remove != 1 {
		t.Errorf("removeRule calls = %d, want 1: the handback probe must run with ctrld's keys gone", remove)
	}
	if add != 1 {
		t.Errorf("addRule calls = %d, want 1: the ctrld fallback must be restored after the probe fails", add)
	}
	if !f.hasCtrldRule() {
		t.Error("ctrld's NRPT rule is missing after a failed handback; the host has no working route")
	}
}

// TestHandbackAcceptsGPWhenItRoutesWithoutCtrld is the other half of the contract: when
// the post-removal probe passes, external policy really is carrying DNS, so ctrld hands
// ownership over and leaves its keys off the machine.
func TestHandbackAcceptsGPWhenItRoutesWithoutCtrld(t *testing.T) {
	f := &fakeNRPTOps{probeResults: []bool{true, true}, gpRule: "{GP-RULE}", ctrldRule: true}
	installFakeNRPTOps(t, f)

	p, state, _ := newHandbackTestProg(t)
	state.setNRPTPolicyOwner(nrptRuleOwnerCtrld, "")

	if !p.tryAdoptMatchingGPNRPT(state) {
		t.Fatal("tryAdoptMatchingGPNRPT() = false for a GP rule that routes on its own")
	}
	owner, ruleName := state.nrptPolicyOwner()
	if owner != nrptRuleOwnerGroupPolicy || ruleName != "{GP-RULE}" {
		t.Errorf("owner = %v, rule = %q, want GroupPolicy/{GP-RULE}", owner, ruleName)
	}
	add, remove, _, _ := f.counts()
	if remove != 1 || add != 0 {
		t.Errorf("removeRule = %d, addRule = %d, want 1/0: ctrld's rule must be removed and not restored", remove, add)
	}
	if f.hasCtrldRule() {
		t.Error("ctrld's rule is still installed beside the adopted GP catch-all")
	}
}

// TestIneffectiveGPRuleTriggersNoSignalling holds ctrld to #576's contract for a
// present-but-ineffective external rule: warn and retry WFP-only, with no policy
// refresh, no Dnscache paramchange and no cache flush. signalNRPTChange is all three at
// once, so on a permanently dead GP rule a signalling loop would force machine Group
// Policy on a schedule.
func TestIneffectiveGPRuleTriggersNoSignalling(t *testing.T) {
	f := &fakeNRPTOps{probeResults: []bool{false}, gpRule: "{GP-RULE}"}
	installFakeNRPTOps(t, f)

	p, state, _ := newHandbackTestProg(t)
	state.setNRPTPolicyOwner(nrptRuleOwnerGroupPolicy, "{GP-RULE}")

	// The verification path a health tick and the heal cycle both take.
	if got := p.nrptHandbackToExternal(state, "{GP-RULE}", "test"); got != nrptHandbackUnverified {
		t.Fatalf("nrptHandbackToExternal() = %v, want nrptHandbackUnverified", got)
	}
	if p.healBlockedLoopbackDNS(state, "test") {
		t.Error("healBlockedLoopbackDNS() = true although the probe never succeeds")
	}

	add, remove, signal, _ := f.counts()
	if signal != 0 {
		t.Errorf("signal calls = %d, want 0: ctrld must not force GP refresh, paramchange or a cache flush while external policy owns NRPT", signal)
	}
	if add != 0 || remove != 0 {
		t.Errorf("addRule = %d, removeRule = %d, want 0/0: external policy must be left untouched", add, remove)
	}
	if owner, _ := state.nrptPolicyOwner(); owner != nrptRuleOwnerGroupPolicy {
		t.Errorf("owner = %v, want nrptRuleOwnerGroupPolicy: ctrld must not seize a namespace an administrator owns", owner)
	}
}

// TestConcurrentFallbackActivationWritesOnce drives two health paths - the monitor and a
// delayed recheck - into activation at the same moment. Without a transition lock they
// both observe "rule missing" and both write and signal.
func TestConcurrentFallbackActivationWritesOnce(t *testing.T) {
	f := &fakeNRPTOps{probeResults: []bool{true}}
	installFakeNRPTOps(t, f)

	p, state, _ := newHandbackTestProg(t)
	state.setNRPTPolicyOwner(nrptRuleOwnerCtrld, "")

	// Hold both callers at the barrier until each is inside activateCtrldNRPTFallback.
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make([]bool, 2)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i] = p.activateCtrldNRPTFallback(state, "concurrent test")
		}(i)
	}
	close(start)
	wg.Wait()

	add, _, signal, _ := f.counts()
	if add != 1 {
		t.Errorf("addRule calls = %d, want 1: concurrent activations must not both write the catch-all", add)
	}
	if signal != 1 {
		t.Errorf("signal calls = %d, want 1: the DNS Client must be signalled once per transition", signal)
	}
	if results[0] == results[1] {
		t.Errorf("both callers reported %v; exactly one transition should report having written the rule", results[0])
	}
	if owner, _ := state.nrptPolicyOwner(); owner != nrptRuleOwnerCtrld {
		t.Errorf("owner = %v, want nrptRuleOwnerCtrld", owner)
	}
}

// waitFor polls cond until it holds, failing the test if it never does.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestActivationLosingRaceWithStopWritesNothing is the interleaving a revocation check
// alone cannot catch: the activation passes its check, and the stop then revokes the
// state, removes NRPT and finishes before the write lands. Windows would be left routing
// every query to a listener that is gone.
//
// The test asserts the transition lock is load-bearing, in three steps. The barrier sits
// inside addRule, so the stop starts while a transition is mid-write; the stop is then
// shown to be unable to progress past its own NRPT cleanup while that transition holds
// the lock; and once the transition releases, the stop must actually have removed the
// rule before a later activation attempt is refused. Dropping the lock on either side -
// activation or stop cleanup - makes the second step fail, because the stop's removeRule
// then runs while the transition is still in flight.
func TestActivationLosingRaceWithStopWritesNothing(t *testing.T) {
	f := &fakeNRPTOps{probeResults: []bool{true}}
	installFakeNRPTOps(t, f)

	p, state, _ := newHandbackTestProg(t)
	state.setNRPTPolicyOwner(nrptRuleOwnerCtrld, "")

	stopDone := make(chan struct{})
	f.beforeAdd = func() {
		// Runs with the transition lock held, from the test goroutine.
		go func() {
			defer close(stopDone)
			_ = p.stopDNSIntercept()
		}()

		// The stop closes stopCh before it reaches the transition lock, so once that is
		// closed the stop can only be waiting on this transition. Waiting on stopCh
		// rather than interceptStateRevoked matters: the latter also reports the
		// stop-requested flag, which is set before the stop has done anything.
		waitFor(t, "the stop to revoke the intercept state", func() bool {
			select {
			case <-state.stopCh:
				return true
			default:
				return false
			}
		})

		// Give it a window in which it would visibly proceed if the lock were not held,
		// then prove it did not: no NRPT removal, and the stop has not finished.
		time.Sleep(100 * time.Millisecond)
		if _, remove, _, _ := f.counts(); remove != 0 {
			t.Errorf("stop removed NRPT (removeRule calls = %d) while a transition held the lock", remove)
		}
		select {
		case <-stopDone:
			t.Error("stop completed while an NRPT transition was still in flight")
		default:
		}
	}

	if !p.activateCtrldNRPTFallback(state, "activation racing a stop") {
		t.Fatal("the in-flight activation should have completed its transition")
	}
	<-stopDone

	// The stop ran after the transition released the lock, so its cleanup must have
	// removed the rule this transition wrote.
	if f.hasCtrldRule() {
		t.Error("ctrld's NRPT rule survived the stop: the machine is left pointing at a listener that is gone")
	}
	if _, remove, _, _ := f.counts(); remove != 1 {
		t.Errorf("removeRule calls = %d, want 1: the stop must clean up the rule written by the racing transition", remove)
	}
	if p.dnsInterceptState != nil {
		t.Error("the stop did not complete after the in-flight transition released the lock")
	}

	// A second attempt models the other health path arriving after the stop finished.
	addBefore, _, signalBefore, _ := f.counts()
	if p.activateCtrldNRPTFallback(state, "activation after the stop completed") {
		t.Error("activateCtrldNRPTFallback() = true after shutdown completed")
	}
	addAfter, _, signalAfter, _ := f.counts()
	if addAfter != addBefore || signalAfter != signalBefore {
		t.Errorf("addRule %d->%d, signal %d->%d: a post-shutdown transition wrote NRPT policy for a dead listener",
			addBefore, addAfter, signalBefore, signalAfter)
	}
	if f.hasCtrldRule() {
		t.Error("a post-shutdown transition re-created ctrld's NRPT rule")
	}
}

// TestOwnedRecoveryDefersToIneffectiveExternalPolicy is the caller-level case for the
// ownership boundary: state says ctrld-owned, ctrld's key has disappeared, and an exact
// GP child is present but not routing.
//
// The handback records Group Policy ownership and reports Unverified. That is terminal:
// an administrator's catch-all owns the namespace whether or not it currently routes, so
// the owned-recovery flow must not go on to signal the DNS Client or delete and recreate
// ctrld's rule beside it. Only loopback WFP protect is allowed, and it touches no policy.
func TestOwnedRecoveryDefersToIneffectiveExternalPolicy(t *testing.T) {
	f := &fakeNRPTOps{probeResults: []bool{false}, gpRule: "{GP-RULE}", ctrldRule: false}
	installFakeNRPTOps(t, f)

	p, state, _ := newHandbackTestProg(t)
	state.setNRPTPolicyOwner(nrptRuleOwnerCtrld, "")

	p.nrptProbeAndHeal(state)

	add, remove, signal, _ := f.counts()
	if add != 0 || remove != 0 || signal != 0 {
		t.Errorf("addRule = %d, removeRule = %d, signal = %d, want 0/0/0: owned recovery must stop once external policy owns the namespace",
			add, remove, signal)
	}
	if f.hasCtrldRule() {
		t.Error("owned recovery recreated ctrld's catch-all beside the administrator's rule")
	}
	owner, ruleName := state.nrptPolicyOwner()
	if owner != nrptRuleOwnerGroupPolicy || ruleName != "{GP-RULE}" {
		t.Errorf("owner = %v, rule = %q, want GroupPolicy/{GP-RULE}", owner, ruleName)
	}
}

// TestHandbackAbortedWhenRuleCannotBeRemoved keeps a failed registry step from being
// read as a verdict about external policy.
func TestHandbackAbortedWhenRuleCannotBeRemoved(t *testing.T) {
	p, state, f := newHandbackTestProg(t)
	f.configure(fakeNRPTSeed{
		probeResults: []bool{true, true},
		gpRule:       "{GP-RULE}",
		ctrldRule:    true,
		removeErr:    errors.New("access denied"),
	})
	state.setNRPTPolicyOwner(nrptRuleOwnerCtrld, "")

	if got := p.nrptHandbackToExternal(state, "{GP-RULE}", "test"); got != nrptHandbackAborted {
		t.Fatalf("nrptHandbackToExternal() = %v, want nrptHandbackAborted", got)
	}
	if owner, _ := state.nrptPolicyOwner(); owner != nrptRuleOwnerCtrld {
		t.Errorf("owner = %v, want nrptRuleOwnerCtrld: a failed removal is not proof about external policy", owner)
	}
}

// TestHandbackRestoresFallbackWhenGPChildDisappearsMidProbe covers a Group Policy refresh
// landing during the post-removal probe: the child ctrld was testing is simply gone. There
// is no external policy left to hand ownership to, so ctrld's rule has to come back.
func TestHandbackRestoresFallbackWhenGPChildDisappearsMidProbe(t *testing.T) {
	f := &fakeNRPTOps{probeResults: []bool{true, false}, gpRule: "{GP-RULE}", ctrldRule: true}
	installFakeNRPTOps(t, f)
	f.onProbe = func(call int) {
		if call == 2 {
			f.setGPRule("", false) // the administrator removed the catch-all
		}
	}

	p, state, _ := newHandbackTestProg(t)
	state.setNRPTPolicyOwner(nrptRuleOwnerCtrld, "")

	if got := p.nrptHandbackToExternal(state, "{GP-RULE}", "test"); got != nrptHandbackKeptCtrld {
		t.Fatalf("nrptHandbackToExternal() = %v, want nrptHandbackKeptCtrld", got)
	}
	if owner, _ := state.nrptPolicyOwner(); owner != nrptRuleOwnerCtrld {
		t.Errorf("owner = %v, want nrptRuleOwnerCtrld", owner)
	}
	if !f.hasCtrldRule() {
		t.Error("ctrld's rule was not restored after the GP child disappeared; the host has no route")
	}
	if add, remove, _, _ := f.counts(); add != 1 || remove != 1 {
		t.Errorf("addRule = %d, removeRule = %d, want 1/1", add, remove)
	}
}

// TestHandbackWritesNoSiblingWhenGPChildTurnsConflicting is the case the same-child
// re-read exists for. ctrld removes its keys to test an exact catch-all, and during the
// probe Group Policy replaces it with one that targets another resolver (or a malformed
// one). Restoring ctrld's rule would create exactly the competing sibling beside
// administrator policy that this must never write, so the rule stays off and ownership
// goes to nobody.
func TestHandbackWritesNoSiblingWhenGPChildTurnsConflicting(t *testing.T) {
	f := &fakeNRPTOps{probeResults: []bool{true, false}, gpRule: "{GP-RULE}", ctrldRule: true}
	installFakeNRPTOps(t, f)
	f.onProbe = func(call int) {
		if call == 2 {
			// The child now names another resolver: not a match for this listener, and
			// reported as a conflict by the GP classifier.
			f.setGPRule("", true)
		}
	}

	p, state, _ := newHandbackTestProg(t)
	state.setNRPTPolicyOwner(nrptRuleOwnerCtrld, "")

	if got := p.nrptHandbackToExternal(state, "{GP-RULE}", "test"); got != nrptHandbackConflict {
		t.Fatalf("nrptHandbackToExternal() = %v, want nrptHandbackConflict", got)
	}
	if add, _, _, _ := f.counts(); add != 0 {
		t.Errorf("addRule calls = %d, want 0: restoring here writes a competing rule beside administrator policy", add)
	}
	if f.hasCtrldRule() {
		t.Error("ctrld's rule is installed beside a GP catch-all that targets another resolver")
	}
	if owner, _ := state.nrptPolicyOwner(); owner != nrptRuleOwnerNone {
		t.Errorf("owner = %v, want nrptRuleOwnerNone: ctrld owns nothing once external policy points elsewhere", owner)
	}
}

// TestHandbackWithoutCtrldRuleClassifiesAfterFailedProbe covers the other short-circuit:
// with no ctrld rule to remove, a failed probe must still be classified before anything is
// recorded. A child that changed into a conflicting catch-all is not an ineffective ctrld
// candidate, and must not be recorded as one.
func TestHandbackWithoutCtrldRuleClassifiesAfterFailedProbe(t *testing.T) {
	f := &fakeNRPTOps{probeResults: []bool{false}, gpRule: "{GP-RULE}"}
	installFakeNRPTOps(t, f)
	f.onProbe = func(call int) {
		if call == 1 {
			f.setGPRule("", true)
		}
	}

	p, state, _ := newHandbackTestProg(t)
	state.setNRPTPolicyOwner(nrptRuleOwnerCtrld, "")

	if got := p.nrptHandbackToExternal(state, "{GP-RULE}", "test"); got != nrptHandbackConflict {
		t.Fatalf("nrptHandbackToExternal() = %v, want nrptHandbackConflict", got)
	}
	if add, remove, signal, _ := f.counts(); add != 0 || remove != 0 || signal != 0 {
		t.Errorf("addRule = %d, removeRule = %d, signal = %d, want 0/0/0", add, remove, signal)
	}
	owner, ruleName := state.nrptPolicyOwner()
	if owner != nrptRuleOwnerNone || ruleName != "" {
		t.Errorf("owner = %v, rule = %q, want nrptRuleOwnerNone/\"\": a conflicting child must not be recorded as ctrld's external owner", owner, ruleName)
	}
}

// TestHandbackGivesReplacementChildItsOwnPass keeps an unproved child from inheriting a
// verdict that was measured against a different one. With no ctrld rule installed the
// replacement is simply probed on its own pass; failing that pass records it as external
// policy that is not routing, and writes nothing either way.
func TestHandbackGivesReplacementChildItsOwnPass(t *testing.T) {
	f := &fakeNRPTOps{probeResults: []bool{false, false}, gpRule: "{GP-RULE}"}
	installFakeNRPTOps(t, f)
	f.onProbe = func(call int) {
		if call == 1 {
			f.setGPRule("{NEW-GP-RULE}", false)
		}
	}

	p, state, _ := newHandbackTestProg(t)

	if got := p.nrptHandbackToExternal(state, "{GP-RULE}", "test"); got != nrptHandbackUnverified {
		t.Fatalf("nrptHandbackToExternal() = %v, want nrptHandbackUnverified", got)
	}
	if add, remove, signal, _ := f.counts(); add != 0 || remove != 0 || signal != 0 {
		t.Errorf("addRule = %d, removeRule = %d, signal = %d, want 0/0/0", add, remove, signal)
	}
	owner, ruleName := state.nrptPolicyOwner()
	if owner != nrptRuleOwnerGroupPolicy || ruleName != "{NEW-GP-RULE}" {
		t.Errorf("owner = %v, rule = %q, want GroupPolicy/{NEW-GP-RULE}: the verdict must name the child it was measured against", owner, ruleName)
	}
}

// TestHandbackWritesNoSiblingWhenReplacementChildTakesOver is the case where ctrld's rule
// was removed for the probe and a *different* exact catch-all took the namespace while it
// was off.
//
// Restoring ctrld's rule here is not a return to the status quo: the replacement was not
// there when the transition started, and addNRPTCatchAllRule writes ctrld's own GP
// catch-all whenever another GP rule exists, so the restore would plant a sibling beside
// the administrator's new rule. The replacement gets its own probe instead, and a failed
// one leaves NRPT to Group Policy with nothing of ctrld's written.
func TestHandbackWritesNoSiblingWhenReplacementChildTakesOver(t *testing.T) {
	// [pre-probe true, post-removal probe false, replacement's own pass false]
	f := &fakeNRPTOps{probeResults: []bool{true, false, false}, gpRule: "{GP-RULE}", ctrldRule: true}
	installFakeNRPTOps(t, f)
	f.onProbe = func(call int) {
		if call == 2 {
			f.setGPRule("{NEW-GP-RULE}", false) // a policy refresh swaps the child
		}
	}

	p, state, _ := newHandbackTestProg(t)
	state.setNRPTPolicyOwner(nrptRuleOwnerCtrld, "")

	if got := p.nrptHandbackToExternal(state, "{GP-RULE}", "test"); got != nrptHandbackUnverified {
		t.Fatalf("nrptHandbackToExternal() = %v, want nrptHandbackUnverified", got)
	}
	if add, remove, _, _ := f.counts(); add != 0 || remove != 1 {
		t.Errorf("addRule = %d, removeRule = %d, want 0/1: ctrld's rule must not be restored beside a replacement catch-all", add, remove)
	}
	if f.hasCtrldRule() {
		t.Error("ctrld's rule is installed beside an administrator catch-all that took the namespace")
	}
	owner, ruleName := state.nrptPolicyOwner()
	if owner != nrptRuleOwnerGroupPolicy || ruleName != "{NEW-GP-RULE}" {
		t.Errorf("owner = %v, rule = %q, want GroupPolicy/{NEW-GP-RULE}", owner, ruleName)
	}
}

// TestHandbackAdoptsReplacementChildThatRoutes is the same swap where the replacement does
// carry DNS on its own: it is adopted, still with no ctrld write.
func TestHandbackAdoptsReplacementChildThatRoutes(t *testing.T) {
	f := &fakeNRPTOps{probeResults: []bool{true, false, true}, gpRule: "{GP-RULE}", ctrldRule: true}
	installFakeNRPTOps(t, f)
	f.onProbe = func(call int) {
		if call == 2 {
			f.setGPRule("{NEW-GP-RULE}", false)
		}
	}

	p, state, _ := newHandbackTestProg(t)
	state.setNRPTPolicyOwner(nrptRuleOwnerCtrld, "")

	if got := p.nrptHandbackToExternal(state, "{GP-RULE}", "test"); got != nrptHandbackVerified {
		t.Fatalf("nrptHandbackToExternal() = %v, want nrptHandbackVerified", got)
	}
	if add, _, _, _ := f.counts(); add != 0 {
		t.Errorf("addRule calls = %d, want 0", add)
	}
	owner, ruleName := state.nrptPolicyOwner()
	if owner != nrptRuleOwnerGroupPolicy || ruleName != "{NEW-GP-RULE}" {
		t.Errorf("owner = %v, rule = %q, want GroupPolicy/{NEW-GP-RULE}", owner, ruleName)
	}
}

// TestHandbackChurnFailsSafeToCurrentExternalOwner bounds the extra pass without letting
// exhaustion become a licence to write.
//
// When the probe budget runs out with the store still changing, the transition classifies
// the store as it stands and proves no route. Reporting "undecided" instead would be
// unsafe: that disposition is not terminal external ownership, so startup and owned
// recovery fall through to writing ctrld's rule, and addNRPTCatchAllRule puts it in the GP
// path beside whichever exact catch-all is there now.
func TestHandbackChurnFailsSafeToCurrentExternalOwner(t *testing.T) {
	f := &fakeNRPTOps{probeResults: []bool{true, false, false}, gpRule: "{GP-RULE}", ctrldRule: true}
	installFakeNRPTOps(t, f)
	f.onProbe = func(call int) {
		switch call {
		case 2:
			f.setGPRule("{GP-RULE-2}", false)
		case 3:
			f.setGPRule("{GP-RULE-3}", false)
		}
	}

	p, state, _ := newHandbackTestProg(t)
	state.setNRPTPolicyOwner(nrptRuleOwnerCtrld, "")

	got := p.nrptHandbackToExternal(state, "{GP-RULE}", "test")
	if got != nrptHandbackUnverified {
		t.Fatalf("nrptHandbackToExternal() = %v, want nrptHandbackUnverified", got)
	}
	if !nrptExternalOwns(got) {
		t.Error("the churn disposition is not terminal external ownership; callers would fall through and write a sibling")
	}
	if add, _, _, _ := f.counts(); add != 0 {
		t.Errorf("addRule calls = %d, want 0: no sibling write while the GP store is churning", add)
	}
	owner, ruleName := state.nrptPolicyOwner()
	if owner != nrptRuleOwnerGroupPolicy || ruleName != "{GP-RULE-3}" {
		t.Errorf("owner = %v, rule = %q, want GroupPolicy/{GP-RULE-3}: exhaustion must record the store as it stands", owner, ruleName)
	}
}

// TestHandbackChurnFailsSafeToConflict covers exhaustion where the store has settled on a
// catch-all that does not target ctrld: still terminal, still no write.
func TestHandbackChurnFailsSafeToConflict(t *testing.T) {
	f := &fakeNRPTOps{probeResults: []bool{true, false, false}, gpRule: "{GP-RULE}", ctrldRule: true}
	installFakeNRPTOps(t, f)
	f.onProbe = func(call int) {
		switch call {
		case 2:
			f.setGPRule("{GP-RULE-2}", false)
		case 3:
			f.setGPRule("", true) // now an administrator catch-all for another resolver
		}
	}

	p, state, _ := newHandbackTestProg(t)
	state.setNRPTPolicyOwner(nrptRuleOwnerCtrld, "")

	if got := p.nrptHandbackToExternal(state, "{GP-RULE}", "test"); got != nrptHandbackConflict {
		t.Fatalf("nrptHandbackToExternal() = %v, want nrptHandbackConflict", got)
	}
	if add, _, _, _ := f.counts(); add != 0 {
		t.Errorf("addRule calls = %d, want 0", add)
	}
	if owner, _ := state.nrptPolicyOwner(); owner != nrptRuleOwnerNone {
		t.Errorf("owner = %v, want nrptRuleOwnerNone", owner)
	}
}

// TestHandbackChurnRestoresFallbackWhenNamespaceFreed is the third exhaustion outcome: the
// store ended up with no external catch-all at all, so the namespace is free and ctrld's
// rule is the one that belongs there.
func TestHandbackChurnRestoresFallbackWhenNamespaceFreed(t *testing.T) {
	f := &fakeNRPTOps{probeResults: []bool{true, false, false}, gpRule: "{GP-RULE}", ctrldRule: true}
	installFakeNRPTOps(t, f)
	f.onProbe = func(call int) {
		switch call {
		case 2:
			f.setGPRule("{GP-RULE-2}", false)
		case 3:
			f.setGPRule("", false) // the administrator removed the policy entirely
		}
	}

	p, state, _ := newHandbackTestProg(t)
	state.setNRPTPolicyOwner(nrptRuleOwnerCtrld, "")

	if got := p.nrptHandbackToExternal(state, "{GP-RULE}", "test"); got != nrptHandbackKeptCtrld {
		t.Fatalf("nrptHandbackToExternal() = %v, want nrptHandbackKeptCtrld", got)
	}
	if !f.hasCtrldRule() {
		t.Error("ctrld's rule was not restored although no external catch-all remains")
	}
	if owner, _ := state.nrptPolicyOwner(); owner != nrptRuleOwnerCtrld {
		t.Errorf("owner = %v, want nrptRuleOwnerCtrld", owner)
	}
}

// TestActivationWritesNoSiblingWhileGPStoreChurns is the caller-level closure for the churn
// path. activateCtrldNRPTFallback is the function both startup fallback and owned recovery
// reach when ctrld's rule is missing, and it is where a non-terminal churn disposition
// would turn into addNRPTCatchAllRule writing a GP sibling beside the current catch-all.
func TestActivationWritesNoSiblingWhileGPStoreChurns(t *testing.T) {
	f := &fakeNRPTOps{probeResults: []bool{false, false}, gpRule: "{GP-RULE}"}
	installFakeNRPTOps(t, f)
	f.onProbe = func(call int) {
		switch call {
		case 1:
			f.setGPRule("{GP-RULE-2}", false)
		case 2:
			f.setGPRule("{GP-RULE-3}", false)
		}
	}

	p, state, _ := newHandbackTestProg(t)
	// Startup and the owner-None retry both arrive here with no ownership recorded.
	state.setNRPTPolicyOwner(nrptRuleOwnerNone, "")

	if p.activateCtrldNRPTFallback(state, "churn test") {
		t.Error("activateCtrldNRPTFallback() = true while an external catch-all owns the namespace")
	}
	add, remove, signal, _ := f.counts()
	if add != 0 || signal != 0 {
		t.Errorf("addRule = %d, signal = %d, want 0/0: ctrld must not write beside the administrator's catch-all", add, signal)
	}
	if remove != 0 {
		t.Errorf("removeRule calls = %d, want 0: there was no ctrld rule to remove", remove)
	}
	if owner, _ := state.nrptPolicyOwner(); owner != nrptRuleOwnerGroupPolicy {
		t.Errorf("owner = %v, want nrptRuleOwnerGroupPolicy: the current external catch-all owns the namespace", owner)
	}
}

// TestStopLeavesGPManagedPolicyAlone is the central promise of this work: an
// administrator's catch-all is a deployment contract that must survive service stop,
// restart and uninstall. A regression that removed NRPT for every owner would delete that
// rule and take the fleet's DNS policy with it.
func TestStopLeavesGPManagedPolicyAlone(t *testing.T) {
	f := &fakeNRPTOps{gpRule: "{GP-RULE}"}
	installFakeNRPTOps(t, f)

	p, state, _ := newHandbackTestProg(t)
	state.setNRPTPolicyOwner(nrptRuleOwnerGroupPolicy, "{GP-RULE}")

	if err := p.stopDNSIntercept(); err != nil {
		t.Fatalf("stopDNSIntercept() = %v", err)
	}

	add, remove, signal, _ := f.counts()
	if remove != 0 || signal != 0 || add != 0 {
		t.Errorf("removeRule = %d, signal = %d, addRule = %d, want 0/0/0: shutdown must not touch externally owned NRPT policy",
			remove, signal, add)
	}
	if f.flushCount() != 0 {
		t.Errorf("flush calls = %d, want 0: no cache flush is owed for a rule ctrld does not own", f.flushCount())
	}
	if p.dnsInterceptState != nil {
		t.Error("dnsInterceptState survived shutdown")
	}
}

// TestStopRemovesOrphanWhileLeavingGPPolicy is the same shutdown with a ctrld rule left
// behind by an earlier unclean exit. External policy still stays, but the orphan must go:
// while GP mode hides the local store this stop is the last chance anything looks there.
func TestStopRemovesOrphanWhileLeavingGPPolicy(t *testing.T) {
	f := &fakeNRPTOps{gpRule: "{GP-RULE}", ctrldRule: true}
	installFakeNRPTOps(t, f)

	p, state, _ := newHandbackTestProg(t)
	state.setNRPTPolicyOwner(nrptRuleOwnerGroupPolicy, "{GP-RULE}")

	if err := p.stopDNSIntercept(); err != nil {
		t.Fatalf("stopDNSIntercept() = %v", err)
	}

	add, remove, signal, _ := f.counts()
	if remove != 1 || signal != 1 {
		t.Errorf("removeRule = %d, signal = %d, want 1/1: the orphaned ctrld rule must be removed on the way out", remove, signal)
	}
	if add != 0 {
		t.Errorf("addRule calls = %d, want 0", add)
	}
	if f.hasCtrldRule() {
		t.Error("the orphaned ctrld rule survived shutdown; a later GP removal would activate it")
	}
	if f.flushCount() != 0 {
		t.Errorf("flush calls = %d, want 0: the ctrld-owned branch is what owes a flush, not the GP branch", f.flushCount())
	}
}

// TestRemoveOrphanedCtrldNRPTRule covers the sweep directly, including that it is a no-op
// when there is nothing of ctrld's on disk - it runs on shutdown paths where the common
// case is a clean machine.
func TestRemoveOrphanedCtrldNRPTRule(t *testing.T) {
	t.Run("removes and signals when a ctrld rule exists", func(t *testing.T) {
		f := &fakeNRPTOps{ctrldRule: true}
		installFakeNRPTOps(t, f)

		p, _, _ := newHandbackTestProg(t)
		p.removeOrphanedCtrldNRPTRule("test")

		add, remove, signal, _ := f.counts()
		if remove != 1 || signal != 1 || add != 0 {
			t.Errorf("removeRule = %d, signal = %d, addRule = %d, want 1/1/0", remove, signal, add)
		}
		if f.hasCtrldRule() {
			t.Error("the ctrld rule is still installed")
		}
	})

	t.Run("does nothing when no ctrld rule exists", func(t *testing.T) {
		f := &fakeNRPTOps{}
		installFakeNRPTOps(t, f)

		p, _, _ := newHandbackTestProg(t)
		p.removeOrphanedCtrldNRPTRule("test")

		add, remove, signal, _ := f.counts()
		if remove != 0 || signal != 0 || add != 0 {
			t.Errorf("removeRule = %d, signal = %d, addRule = %d, want 0/0/0: nothing to sweep must cost no registry writes and no signalling",
				remove, signal, add)
		}
	})
}

// TestHandbackThrottleBlocksTheSecondAttempt exercises the throttle through the
// transition, not just its accessor. Each attempt removes the live catch-all for a probe,
// so a second attempt inside the window must cost nothing at all: no probe, no removal.
func TestHandbackThrottleBlocksTheSecondAttempt(t *testing.T) {
	f := &fakeNRPTOps{probeResults: []bool{true, false}, gpRule: "{GP-RULE}", ctrldRule: true}
	installFakeNRPTOps(t, f)

	p, state, _ := newHandbackTestProg(t)
	state.setNRPTPolicyOwner(nrptRuleOwnerCtrld, "")

	if got := p.nrptHandbackToExternal(state, "{GP-RULE}", "first"); got != nrptHandbackKeptCtrld {
		t.Fatalf("first nrptHandbackToExternal() = %v, want nrptHandbackKeptCtrld", got)
	}
	_, removeAfterFirst, _, probesAfterFirst := f.counts()

	if got := p.nrptHandbackToExternal(state, "{GP-RULE}", "second"); got != nrptHandbackAborted {
		t.Fatalf("second nrptHandbackToExternal() = %v, want nrptHandbackAborted", got)
	}
	_, remove, _, probes := f.counts()
	if probes != probesAfterFirst {
		t.Errorf("probe calls went from %d to %d: a throttled attempt must not probe", probesAfterFirst, probes)
	}
	if remove != removeAfterFirst {
		t.Errorf("removeRule calls went from %d to %d: a throttled attempt must not remove the live rule", removeAfterFirst, remove)
	}
	if owner, _ := state.nrptPolicyOwner(); owner != nrptRuleOwnerCtrld {
		t.Errorf("owner = %v, want nrptRuleOwnerCtrld", owner)
	}
}

// TestHealLadderRunsRetriesThenTwoPhaseRecovery drives the ctrld-owned heal cycle end to
// end: the immediate probe, the signal-and-backoff retries, then the two-phase delete and
// re-add, with the last probe finally succeeding. Each nrptTransition phase is asserted
// through its side effects, since these are its only call sites.
func TestHealLadderRunsRetriesThenTwoPhaseRecovery(t *testing.T) {
	// Every probe fails until the one after the re-add.
	f := &fakeNRPTOps{
		probeResults: []bool{false, false, false, false, true},
		ctrldRule:    true,
	}
	installFakeNRPTOps(t, f)

	p, state, _ := newHandbackTestProg(t)
	state.setNRPTPolicyOwner(nrptRuleOwnerCtrld, "")

	p.nrptProbeAndHeal(state)

	add, remove, signal, probes := f.counts()
	if remove != 1 {
		t.Errorf("removeRule calls = %d, want 1: phase one of the two-phase recovery deletes ctrld's rule once", remove)
	}
	if add != 1 {
		t.Errorf("addRule calls = %d, want 1: phase two re-adds it once", add)
	}
	if !f.hasCtrldRule() {
		t.Error("ctrld's rule is missing after the two-phase recovery")
	}
	// Three backoff rounds signal, then the delete phase and the re-add phase.
	if signal < 5 {
		t.Errorf("signal calls = %d, want at least 5 (three retries plus both recovery phases)", signal)
	}
	if probes < 5 {
		t.Errorf("probe calls = %d, want at least 5", probes)
	}
	if owner, _ := state.nrptPolicyOwner(); owner != nrptRuleOwnerCtrld {
		t.Errorf("owner = %v, want nrptRuleOwnerCtrld", owner)
	}
}

// TestHealLadderStopsWhenGPAppearsBeforeTwoPhase covers a Group Policy catch-all landing
// during the backoff retries. The ladder must hand back and stop before the destructive
// delete-and-re-add phase, and must not write ctrld's rule beside the new policy.
func TestHealLadderStopsWhenGPAppearsBeforeTwoPhase(t *testing.T) {
	f := &fakeNRPTOps{probeResults: []bool{false}, ctrldRule: true}
	installFakeNRPTOps(t, f)
	// The administrator's rule appears while the fourth probe is in flight, which is the
	// last one before the two-phase recovery.
	f.onProbe = func(call int) {
		if call == 4 {
			f.setGPRule("{GP-RULE}", false)
		}
	}

	p, state, _ := newHandbackTestProg(t)
	state.setNRPTPolicyOwner(nrptRuleOwnerCtrld, "")

	p.nrptProbeAndHeal(state)

	add, remove, _, _ := f.counts()
	if remove != 0 {
		t.Errorf("removeRule calls = %d, want 0: the ladder must stop before the delete half of the two-phase recovery", remove)
	}
	if add != 0 {
		t.Errorf("addRule calls = %d, want 0: the ladder must not recreate ctrld's rule beside a new GP catch-all", add)
	}
	if !f.hasCtrldRule() {
		t.Error("ctrld's rule was deleted after an administrator catch-all appeared")
	}
	owner, ruleName := state.nrptPolicyOwner()
	if owner != nrptRuleOwnerGroupPolicy || ruleName != "{GP-RULE}" {
		t.Errorf("owner = %v, rule = %q, want GroupPolicy/{GP-RULE}: the ladder must defer rather than continue", owner, ruleName)
	}
}

// TestHealLadderCleansEmptyGPParentBeforeRetrying pins the empty-GP-parent shortcut: an
// empty parent key puts the DNS Client in GP mode where ctrld's local rule is invisible, so
// signalling retries cannot succeed until it is deleted.
func TestHealLadderCleansEmptyGPParentBeforeRetrying(t *testing.T) {
	f := &fakeNRPTOps{probeResults: []bool{false, true}, ctrldRule: true, parentEmpty: true}
	installFakeNRPTOps(t, f)

	p, state, _ := newHandbackTestProg(t)
	state.setNRPTPolicyOwner(nrptRuleOwnerCtrld, "")

	p.nrptProbeAndHeal(state)

	if f.cleanCalls != 1 {
		t.Errorf("cleanParent calls = %d, want 1: the empty GP parent must be removed before burning retries", f.cleanCalls)
	}
	if add, remove, _, _ := f.counts(); add != 0 || remove != 0 {
		t.Errorf("addRule = %d, removeRule = %d, want 0/0: the probe passed after the cleanup, so no recovery was needed", add, remove)
	}
}

// TestRepairMissingWFPRetriesHardModeWithNoEngine covers the entry point a startup WFP
// failure depends on. In hard mode a closed engine means nothing is being blocked, so the
// health monitor must keep retrying; in dns mode a closed engine is the normal state and
// must not trigger anything.
func TestRepairMissingWFPRetriesHardModeWithNoEngine(t *testing.T) {
	originalRebuild, originalHard := rebuildDNSInterceptFn, hardIntercept
	t.Cleanup(func() { rebuildDNSInterceptFn, hardIntercept = originalRebuild, originalHard })

	var reasons []string
	rebuildDNSInterceptFn = func(_ *prog, _ *wfpState, reason string) interceptRebuildResult {
		reasons = append(reasons, reason)
		return interceptRebuildDone
	}

	t.Run("hard mode retries when the engine never opened", func(t *testing.T) {
		reasons = nil
		hardIntercept = true
		p, state, _ := newHandbackTestProg(t)

		if !p.repairMissingWFP(state) {
			t.Error("repairMissingWFP() = false; the monitor must hand over to the rebuilt intercept")
		}
		if len(reasons) != 1 {
			t.Fatalf("rebuild requests = %d, want 1: hard mode with no WFP engine must be retried", len(reasons))
		}
		if !strings.Contains(reasons[0], "no WFP engine") {
			t.Errorf("rebuild reason = %q, want it to name the missing engine", reasons[0])
		}
	})

	t.Run("dns mode leaves a closed engine alone", func(t *testing.T) {
		reasons = nil
		hardIntercept = false
		p, state, _ := newHandbackTestProg(t)

		if p.repairMissingWFP(state) {
			t.Error("repairMissingWFP() = true in dns mode; a closed engine is normal there")
		}
		if len(reasons) != 0 {
			t.Errorf("rebuild requests = %d, want 0", len(reasons))
		}
	})
}

// TestPhaseTwoRevalidatesOwnershipAfterWaitingForTheLock is the ordering a pre-lock check
// cannot cover. Phase one removes ctrld's rule and releases the transition lock; the
// pre-re-add checks see no GP rule; another health path then takes the lock, hands the
// namespace to a GP catch-all that has just arrived, and records GroupPolicy. Phase two
// acquires the lock afterwards.
//
// Without a re-read inside the locked closure, phase two re-adds ctrld's rule beside the
// administrator's catch-all and stamps ctrld ownership over theirs - exactly the competing
// policy this work exists to prevent.
func TestPhaseTwoRevalidatesOwnershipAfterWaitingForTheLock(t *testing.T) {
	p, state, f := newHandbackTestProg(t)
	// Every probe fails, so the ladder runs to the two-phase recovery.
	f.configure(fakeNRPTSeed{probeResults: []bool{false}, ctrldRule: true})
	state.setNRPTPolicyOwner(nrptRuleOwnerCtrld, "")

	// The last ops call before phase two queues for the lock. Hold the lock from another
	// goroutine and complete the competing transition while phase two waits for it.
	f.onGPConflicts = func(call int) {
		if call != 1 {
			return
		}
		locked := make(chan struct{})
		go func() {
			p.nrptTransitionMu.Lock()
			close(locked)
			f.setGPRule("{GP-RULE}", false)
			state.setNRPTPolicyOwner(nrptRuleOwnerGroupPolicy, "{GP-RULE}")
			// Hold it long enough that phase two must queue behind this transition.
			time.Sleep(100 * time.Millisecond)
			p.nrptTransitionMu.Unlock()
		}()
		<-locked
	}

	p.nrptProbeAndHeal(state)

	if add, _, _, _ := f.counts(); add != 0 {
		t.Errorf("addRule calls = %d, want 0: phase two re-added ctrld's rule beside a GP catch-all that took ownership while it waited for the lock", add)
	}
	if f.hasCtrldRule() {
		t.Error("ctrld's rule is installed beside the administrator's catch-all")
	}
	owner, ruleName := state.nrptPolicyOwner()
	if owner != nrptRuleOwnerGroupPolicy || ruleName != "{GP-RULE}" {
		t.Errorf("owner = %v, rule = %q, want GroupPolicy/{GP-RULE}: phase two overwrote a newer ownership transition", owner, ruleName)
	}
}

// TestRetiredHealDoesNotDeleteSuccessorRule covers the other side of a rebuild. The heal
// cycle re-adds ctrld's rule, then its final settle wait observes that its own state was
// retired - while a successor intercept is already running with the same deterministic key.
//
// The key is process-global, so any cleanup from here would delete the successor's route
// and leave hard mode blocking DNS with nothing redirecting it. Teardown of the retired
// state owns that cleanup instead.
func TestRetiredHealDoesNotDeleteSuccessorRule(t *testing.T) {
	p, state, f := newHandbackTestProg(t)
	f.configure(fakeNRPTSeed{probeResults: []bool{false}, ctrldRule: true})
	state.setNRPTPolicyOwner(nrptRuleOwnerCtrld, "")

	successor := &wfpState{stopCh: make(chan struct{}), listenerIP: "127.0.0.1"}
	// Retire this cycle's state during the final wait - the one after the re-add, which is
	// the only wait where both a removal and an add have happened - and publish a successor
	// that owns the same deterministic key.
	f.waitHook = func() bool {
		if add, remove, _, _ := f.counts(); add == 0 || remove == 0 {
			return true
		}
		close(state.stopCh) // a rebuild retired the old state
		p.dnsInterceptState = successor
		successor.setNRPTPolicyOwner(nrptRuleOwnerCtrld, "")
		return false
	}

	p.nrptProbeAndHeal(state)

	if !f.hasCtrldRule() {
		t.Error("the successor's NRPT rule was deleted by a retired heal cycle")
	}
	if owner, _ := successor.nrptPolicyOwner(); owner != nrptRuleOwnerCtrld {
		t.Errorf("successor owner = %v, want nrptRuleOwnerCtrld", owner)
	}
}

// TestStartupReportsFailureWhenExternalPolicyNeverRoutes is the readiness direction of the
// GP-managed contract, driven through the real startup control flow.
//
// An exact GP child is present and no probe ever reaches ctrld. Startup must keep the
// recovery state and the monitor - the rule may start routing later, and only external
// policy can fix it - must leave adapter DNS alone, and must not write an owned fallback.
// What it must not do is return success: setDNS records readiness from a nil error, so
// reporting ready here publishes "service healthy" while the DNS Client is not delivering
// queries to ctrld, and in hard mode WFP is blocking every other resolver at the same time.
func TestStartupReportsFailureWhenExternalPolicyNeverRoutes(t *testing.T) {
	originalCfg, originalMode, originalIntercept, originalHard := cfg, interceptMode, dnsIntercept, hardIntercept
	t.Cleanup(func() {
		cfg, interceptMode, dnsIntercept, hardIntercept = originalCfg, originalMode, originalIntercept, originalHard
	})
	cfg = ctrld.Config{}
	cfg.Listener = map[string]*ctrld.ListenerConfig{"0": {IP: "127.0.0.1", Port: 53}}
	interceptMode, dnsIntercept, hardIntercept = "dns", true, false

	p, _, f := newHandbackTestProg(t)
	p.cfg = &cfg
	p.dnsInterceptState = nil // startup publishes its own state
	// An exact GP child that never answers a probe.
	f.configure(fakeNRPTSeed{probeResults: []bool{false}, gpRule: "{GP-RULE}"})

	err := p.startDNSInterceptLocked()
	if err == nil {
		t.Fatal("startDNSInterceptLocked() = nil: startup reported success while no probe reached ctrld, so setDNS would mark the service ready")
	}
	if !interceptFailedUnderExternalDNSPolicy(err) {
		t.Errorf("err = %v; the failure must tell setDNS to leave adapter DNS untouched", err)
	}
	if interceptFailedWithVerifiedExternalDNS(err) {
		t.Errorf("err = %v; this route was never verified, so it must not read as the verified case", err)
	}
	if add, remove, signal, _ := f.counts(); add != 0 || remove != 0 || signal != 0 {
		t.Errorf("addRule = %d, removeRule = %d, signal = %d, want 0/0/0: no owned fallback may be written beside an administrator catch-all", add, remove, signal)
	}

	// Recovery must stay live so the rule can be re-tested.
	state, ok := p.dnsInterceptState.(*wfpState)
	if !ok || state == nil {
		t.Fatal("intercept state was not published; nothing would keep re-testing the external rule")
	}
	if owner, ruleName := state.nrptPolicyOwner(); owner != nrptRuleOwnerGroupPolicy || ruleName != "{GP-RULE}" {
		t.Errorf("owner = %v, rule = %q, want GroupPolicy/{GP-RULE}", owner, ruleName)
	}
	// Stop the monitor startup launched.
	_ = p.stopDNSIntercept()
}

// TestFakeNRPTOpsPreconditionDetectsBypass guards the guard. The fixtures' promise is that
// no test can reach the production registry and signalling functions, and that promise is
// only as good as this precondition: if it stops detecting a bypass, every "no side
// effects" assertion in the Windows suite silently becomes vacuous while the real host
// policy is at risk.
func TestFakeNRPTOpsPreconditionDetectsBypass(t *testing.T) {
	f := &fakeNRPTOps{}

	// The exact bypass to catch: a fixture that returns a fake it never installed.
	if err := checkFakeNRPTOpsInstalled(f); err == nil {
		t.Error("an uninstalled fake passed the precondition; a test could fall through to production NRPT operations")
	}

	installFakeNRPTOps(t, f)
	if err := checkFakeNRPTOpsInstalled(f); err != nil {
		t.Errorf("an installed fake failed the precondition: %v", err)
	}

	// A different fake than the installed one must not pass either: side-effect counters
	// would be read from an object nothing consults.
	if err := checkFakeNRPTOpsInstalled(&fakeNRPTOps{}); err == nil {
		t.Error("a fake that is not the installed one passed the precondition")
	}
}
