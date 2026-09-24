package cli

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	ctrld "github.com/Control-D-Inc/ctrld"
)

const recoverySkipMessage = "Recovery skipped: configured upstream is not marked down"

func TestOSRecoverySkipRefreshesWithoutNetworkChange(t *testing.T) {
	h := newScopeTestHarness(t)
	h.markOSDown(t)
	var refreshes atomic.Int64
	initializeOsResolverWithSystemNameserversFn = func(_ context.Context, guard bool, reason string) ([]string, []string) {
		if !guard || reason != recoveryResolverReason {
			t.Error("refresh lost empty-discovery guard or reason")
		}
		refreshes.Add(1)
		h.osAnswers.Store(true)
		return nil, nil
	}
	// This query still fails; the asynchronously triggered refresh repairs
	// discovery for the next policy query, without a network-change callback.
	h.query(t, true)
	scopeWait(t, h.finished)
	if refreshes.Load() != 1 || !h.prog.um.isDown(upstreamOS) {
		t.Fatal("refresh must run without claiming a successful OS response")
	}
	if h.query(t, true).answer.Rcode != dns.RcodeSuccess || h.prog.um.isDown(upstreamOS) {
		t.Fatal("OS policy did not recover on its own resolver")
	}
	if h.prog.recoveryBypass.Load() || h.prog.recoveryRunning.Load() || h.prog.recoveryGen.Load() != 0 {
		t.Fatal("local refresh acquired global recovery state")
	}
}

func TestOSRecoverySkipRefreshIsBounded(t *testing.T) {
	h := newScopeTestHarness(t)
	now := time.Unix(1000, 0)
	oldNow := networkEventsNowFn
	networkEventsNowFn = func() time.Time { return now }
	t.Cleanup(func() { networkEventsNowFn = oldNow })
	calls := 0
	initializeOsResolverWithSystemNameserversFn = func(context.Context, bool, string) ([]string, []string) {
		calls++
		return nil, nil
	}
	for range 100 {
		h.prog.handleRecovery(RecoveryReasonOSFailure)
	}
	if calls != 1 {
		t.Fatalf("burst discovery calls=%d, want 1", calls)
	}
	now = now.Add(upstreamDownDelay - time.Nanosecond)
	h.prog.handleRecovery(RecoveryReasonOSFailure)
	if calls != 1 {
		t.Fatal("discovery retried before the cooldown")
	}
	now = now.Add(time.Nanosecond)
	h.prog.handleRecovery(RecoveryReasonOSFailure)
	if calls != 2 {
		t.Fatal("later OS failures cannot retry discovery")
	}
	event := oneRecoveryEvent(t, h.logs, recoverySkipMessage)
	wantField(t, event, "journal", true)
	wantField(t, event, "healthy_upstream", "upstream.0")
	wantField(t, event, "recovery_reason", "os_resolver_failure")
	now = now.Add(5 * time.Minute)
	h.prog.handleRecovery(RecoveryReasonOSFailure)
	if len(jsonLogEvents(t, h.logs, recoverySkipMessage)) != 2 {
		t.Fatal("persistent skips lost the bounded journal heartbeat")
	}
}

func TestOSRecoverySkipCoalescesConcurrentRefresh(t *testing.T) {
	h := newScopeTestHarness(t)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var calls atomic.Int64
	initializeOsResolverWithSystemNameserversFn = func(context.Context, bool, string) ([]string, []string) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-release
		return nil, nil
	}
	go func() { h.prog.handleRecovery(RecoveryReasonOSFailure); close(done) }()
	scopeWait(t, entered)
	other := make(chan struct{})
	go func() { h.prog.handleRecovery(RecoveryReasonOSFailure); close(other) }()
	// Release the first worker even if coalescing regresses, to keep cleanup safe.
	select {
	case <-other:
	case <-time.After(time.Second):
		close(release)
		scopeWait(t, done)
		scopeWait(t, other)
		t.Fatal("concurrent failure waited on discovery")
	}
	close(release)
	scopeWait(t, done)
	if calls.Load() != 1 {
		t.Fatalf("overlapping discovery calls=%d", calls.Load())
	}
}

func TestOSRecoverySkipJournalsChangedCandidatePrivately(t *testing.T) {
	h := newScopeTestHarness(t)
	h.prog.cfg.Upstream["private-token.example"] = &ctrld.UpstreamConfig{Type: ctrld.ResolverTypeLegacy}
	h.prog.handleRecovery(RecoveryReasonOSFailure)
	h.prog.um.mu.Lock()
	h.prog.um.markDown("upstream.0", 1, "test")
	h.prog.um.mu.Unlock()
	h.prog.handleRecovery(RecoveryReasonOSFailure)
	events := jsonLogEvents(t, h.logs, recoverySkipMessage)
	if len(events) != 2 {
		t.Fatalf("candidate change events=%d", len(events))
	}
	wantField(t, events[0], "healthy_upstream", "upstream.0")
	wantField(t, events[1], "healthy_upstream", "upstream.custom")
	if strings.Contains(h.logs.String(), "private-token.example") {
		t.Fatal("operator-provided upstream key leaked")
	}
}

func TestOSRecoverySkipSurvivesDebugTruncation(t *testing.T) {
	h := newScopeTestHarness(t)
	p, _ := startInternalLogging(t)
	h.prog.logger.Store(mainLog.Load())
	useTestSendBudget(t, 1024)
	for range 100 {
		h.prog.handleRecovery(RecoveryReasonOSFailure)
	}
	for range 40 {
		mainLog.Load().Debug().Msg(strings.Repeat("debug filler", 20))
	}
	debugPart, journalPart := splitUpload(t, readLogReader(t, p, false), time.Now())
	if strings.Contains(string(debugPart), recoverySkipMessage) {
		t.Fatal("fixture did not truncate the skip from debug")
	}
	if strings.Count(string(journalPart), recoverySkipMessage) != 1 || !strings.Contains(string(journalPart), `"healthy_upstream":"upstream.0"`) {
		t.Fatal("journal did not retain the bounded skip and admission candidate")
	}
}
