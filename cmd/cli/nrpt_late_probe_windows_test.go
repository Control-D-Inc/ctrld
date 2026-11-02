//go:build windows

package cli

import "testing"

// TestHealLadderTreatsLateProbeAsVerified covers #657: the first probe of a heal cycle
// reaches ctrld after the normal timeout. That proves the rule routes, so the cycle must
// end there with no policy refresh, paramchange, flush or two-phase recovery.
func TestHealLadderTreatsLateProbeAsVerified(t *testing.T) {
	f := &fakeNRPTOps{
		probeResults:   []bool{true},
		lateProbeCalls: map[int]bool{1: true},
		ctrldRule:      true,
	}
	installFakeNRPTOps(t, f)

	p, state, _ := newHandbackTestProg(t)
	state.setNRPTPolicyOwner(nrptRuleOwnerCtrld, "")

	if !p.nrptProbeAndHeal(state) {
		t.Fatal("nrptProbeAndHeal = false, want true: a late probe still proves the rule routes to ctrld")
	}
	add, remove, signal, probes := f.counts()
	if signal != 0 {
		t.Errorf("signal calls = %d, want 0: a slow DNS Client must not get policy refresh or paramchange", signal)
	}
	if add != 0 || remove != 0 || f.restoreLocalCount() != 0 {
		t.Errorf("addRule = %d, removeRule = %d, restoreLocalRule = %d, want 0/0/0: no two-phase recovery after a late probe", add, remove, f.restoreLocalCount())
	}
	if f.flushCount() != 0 {
		t.Errorf("flush calls = %d, want 0", f.flushCount())
	}
	if probes != 1 || f.graceCalls != 1 {
		t.Errorf("probe calls = %d (grace %d), want 1 (1): the cycle ends on the late arrival", probes, f.graceCalls)
	}
	if !f.hasCtrldRule() {
		t.Error("ctrld's rule is missing after a late but successful probe")
	}
	if attempts := state.nrptRecoveryLimiter.attempts; attempts != 0 {
		t.Errorf("recovery flows recorded = %d, want 0: nothing was remediated", attempts)
	}
}

// TestHealLadderOnTimeProbeSkipsRecovery pins the fast path: an on-time first probe ends
// the cycle with no signalling.
func TestHealLadderOnTimeProbeSkipsRecovery(t *testing.T) {
	f := &fakeNRPTOps{probeResults: []bool{true}, ctrldRule: true}
	installFakeNRPTOps(t, f)

	p, state, _ := newHandbackTestProg(t)
	state.setNRPTPolicyOwner(nrptRuleOwnerCtrld, "")

	if !p.nrptProbeAndHeal(state) {
		t.Fatal("nrptProbeAndHeal = false, want true")
	}
	add, remove, signal, probes := f.counts()
	if add != 0 || remove != 0 || signal != 0 || probes != 1 {
		t.Errorf("add/remove/signal/probe = %d/%d/%d/%d, want 0/0/0/1", add, remove, signal, probes)
	}
}

// TestHealLadderMissedProbeKeepsBoundedRecovery pins the other half of #657: a probe that
// never arrives, even in the late window, still runs the existing retries and the
// two-phase recovery.
func TestHealLadderMissedProbeKeepsBoundedRecovery(t *testing.T) {
	f := &fakeNRPTOps{
		probeResults: []bool{false, false, false, false, true},
		ctrldRule:    true,
	}
	installFakeNRPTOps(t, f)

	p, state, _ := newHandbackTestProg(t)
	state.setNRPTPolicyOwner(nrptRuleOwnerCtrld, "")

	p.nrptProbeAndHeal(state)

	add, remove, signal, _ := f.counts()
	if f.graceCalls != 1 {
		t.Errorf("grace probe calls = %d, want 1: only the first probe of the cycle waits for a late arrival", f.graceCalls)
	}
	if signal < 5 || remove != 1 || add != 1 {
		t.Errorf("signal = %d, removeRule = %d, addRule = %d, want >=5/1/1: a missed probe keeps the retries and two-phase recovery", signal, remove, add)
	}
}

// TestStartupVerificationKeepsPlainFirstProbe covers the synchronous startup call: service
// readiness waits on it, so its first probe must not use the late window. A late arrival
// there is a miss and the bounded retries run, exactly as before #657.
func TestStartupVerificationKeepsPlainFirstProbe(t *testing.T) {
	f := &fakeNRPTOps{
		probeResults:   []bool{true, true},
		lateProbeCalls: map[int]bool{1: true},
		ctrldRule:      true,
	}
	installFakeNRPTOps(t, f)

	p, state, _ := newHandbackTestProg(t)
	state.setNRPTPolicyOwner(nrptRuleOwnerCtrld, "")

	if !p.nrptProbeAndHealStartup(state) {
		t.Fatal("nrptProbeAndHealStartup = false, want true: the on-time retry probe verifies")
	}
	if f.graceCalls != 0 {
		t.Errorf("grace probe calls = %d, want 0: startup must not wait out the late window", f.graceCalls)
	}
	if _, _, signal, probes := f.counts(); probes != 2 || signal != 1 {
		t.Errorf("probe calls = %d, signal calls = %d, want 2/1: the late first probe is a miss, then one signalled retry", probes, signal)
	}
}
