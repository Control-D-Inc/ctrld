package cli

import (
	"context"
	"net"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	ctrld "github.com/Control-D-Inc/ctrld"
)

// Loopback transports exercise the real proxy and recovery loop without host
// DNS changes. The event harness intercepts the first platform mutation.
func scopeTestResolver(t *testing.T, answering *atomic.Bool, calls *atomic.Int64) *ctrld.UpstreamConfig {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	srv := &dns.Server{PacketConn: pc, Net: "udp", NotifyStartedFunc: func() { close(started) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, m *dns.Msg) {
		calls.Add(1)
		if answering.Load() {
			a := new(dns.Msg)
			a.SetReply(m)
			_ = w.WriteMsg(a)
		}
	})}
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown() })
	return &ctrld.UpstreamConfig{Type: ctrld.ResolverTypeLegacy, Endpoint: pc.LocalAddr().String(), Timeout: 40}
}

type scopeTestHarness struct {
	*recoveryEventHarness
	osAnswers, defaultAnswers atomic.Bool
	osCalls, defaultCalls     atomic.Int64
	finished                  chan struct{}
}

func newScopeTestHarness(t *testing.T) *scopeTestHarness {
	t.Helper()
	h := &scopeTestHarness{recoveryEventHarness: newRecoveryEventHarness(t), finished: make(chan struct{}, 8)}
	// These flows keep interception active (or reject recovery before host work).
	// Fence the first platform calls if that contract regresses, not merely a
	// later DNS write: startDNSIntercept can install PF/NRPT/WFP policy.
	oldStart, oldReset := startDNSInterceptFn, recoveryResetDNSFn
	var hostCalls atomic.Int64
	startDNSInterceptFn = func(*prog) error {
		hostCalls.Add(1)
		t.Fatal("scope recovery attempted to start host interception")
		return nil
	}
	recoveryResetDNSFn = func(*prog, bool, bool) {
		hostCalls.Add(1)
		t.Fatal("scope recovery attempted to reset host DNS")
	}
	t.Cleanup(func() {
		startDNSInterceptFn, recoveryResetDNSFn = oldStart, oldReset
		if got := hostCalls.Load(); got != 0 {
			t.Errorf("unexpected first host calls: %d", got)
		}
	})
	h.dhcpServers = nil
	initializeOsResolverWithSystemNameserversFn = func(context.Context, bool, string) ([]string, []string) { return nil, nil }
	oldOS, oldQueryRecovery := osUpstreamConfig, queryRecoveryFn
	t.Cleanup(func() { osUpstreamConfig, queryRecoveryFn = oldOS, oldQueryRecovery })
	osUpstreamConfig = scopeTestResolver(t, &h.osAnswers, &h.osCalls)
	h.defaultAnswers.Store(true)
	h.prog.cfg.Upstream = map[string]*ctrld.UpstreamConfig{"0": scopeTestResolver(t, &h.defaultAnswers, &h.defaultCalls)}
	leak := true
	h.prog.cfg.Service.LeakOnUpstreamFailure = &leak
	h.prog.um = newUpstreamMonitor(h.prog.cfg, mainLog.Load())
	h.prog.um.after = func(time.Duration, func()) {}
	h.prog.um.clearRecovered(upstreamOS)
	h.prog.um.clearRecovered("upstream.0")
	queryRecoveryFn = func(p *prog, reason RecoveryReason) {
		p.handleRecovery(reason)
		h.finished <- struct{}{}
	}
	return h
}

func (h *scopeTestHarness) query(t *testing.T, policy bool) *proxyResponse {
	t.Helper()
	name := "ordinary.example."
	ufr := &upstreamForResult{upstreams: []string{"upstream.0"}, matched: true}
	if policy {
		name = "os-only.example."
		lc := listenerWithRules(ctrld.Rule{"os-only.example": []string{}})
		ufr = h.prog.upstreamFor(context.Background(), "0", lc, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53000}, "", "os-only.example")
		if !ufr.matched || len(ufr.upstreams) != 0 {
			t.Fatalf("wrong policy fixture: %+v", ufr)
		}
	}
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeTXT)
	return h.prog.proxy(context.Background(), &proxyRequest{msg: m, ufr: ufr})
}

func (h *scopeTestHarness) markOSDown(t *testing.T) {
	t.Helper()
	if got := h.query(t, true).answer.Rcode; got != dns.RcodeServerFailure {
		t.Fatalf("OS fixture rcode=%d", got)
	}
	// Fire the real delayed-down callback without waiting ten seconds.
	h.prog.um.markDownAfterDelay(upstreamOS)
	if !h.prog.um.isDown(upstreamOS) {
		t.Fatal("OS down precondition failed")
	}
}

func scopeWait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("recovery handler did not return")
	}
}

func TestOSPolicyFailureDoesNotBypassHealthyDefault(t *testing.T) {
	h := newScopeTestHarness(t)
	if h.query(t, false).answer.Rcode != dns.RcodeSuccess {
		t.Fatal("default fixture failed")
	}
	h.markOSDown(t)
	for range 3 {
		if h.query(t, true).answer.Rcode != dns.RcodeServerFailure {
			t.Fatal("policy changed resolver")
		}
		scopeWait(t, h.finished)
		if h.prog.recoveryBypass.Load() || h.prog.recoveryRunning.Load() {
			t.Fatal("policy failure started global recovery")
		}
	}
	before := h.osCalls.Load()
	if h.query(t, false).answer.Rcode != dns.RcodeSuccess {
		t.Fatal("default request failed")
	}
	if h.osCalls.Load() != before {
		t.Fatal("unrelated request detoured through OS DNS")
	}
	if len(jsonLogEvents(t, h.logs, recoveryBeginMessage)) != 0 {
		t.Fatal("rejected recovery touched host state")
	}
}

func TestQueuedOSFailureRechecksHealthyDefault(t *testing.T) {
	h := newScopeTestHarness(t)
	h.markOSDown(t)
	h.prog.um.mu.Lock()
	h.prog.um.markDown("upstream.0", 1, "test")
	h.prog.um.mu.Unlock()
	entered, proceed := make(chan struct{}), make(chan struct{})
	queryRecoveryFn = func(p *prog, reason RecoveryReason) {
		close(entered)
		<-proceed
		p.handleRecovery(reason)
		h.finished <- struct{}{}
	}
	h.query(t, true)
	scopeWait(t, entered)
	if h.query(t, false).answer.Rcode != dns.RcodeSuccess {
		t.Fatal("default did not recover")
	}
	close(proceed)
	scopeWait(t, h.finished)
	if len(jsonLogEvents(t, h.logs, recoveryBeginMessage)) != 0 {
		t.Fatal("late OS trigger ignored newer default success")
	}
}

func TestOSFailureRecoversThroughConfiguredPool(t *testing.T) {
	h := newScopeTestHarness(t)
	h.markOSDown(t)
	h.prog.um.mu.Lock()
	h.prog.um.markDown("upstream.0", 1, "test")
	h.prog.um.mu.Unlock()
	candidates := make(chan map[string]*ctrld.UpstreamConfig, 1)
	proceed := make(chan struct{})
	waitForUpstreamRecoveryFn = func(p *prog, ctx context.Context, ups map[string]*ctrld.UpstreamConfig, diagnostic *recoveryDiagnostic) (string, error) {
		candidates <- ups
		<-proceed
		return p.waitForUpstreamRecovery(ctx, ups, diagnostic)
	}
	h.query(t, true)
	select {
	case ups := <-candidates:
		if len(ups) != 1 || ups["upstream.0"] != h.prog.cfg.Upstream["0"] {
			t.Fatalf("wrong recovery pool: %v", ups)
		}
	case <-time.After(time.Second):
		t.Fatal("general outage did not enter recovery")
	}
	if !h.prog.recoveryBypass.Load() {
		t.Fatal("general outage did not enable bypass")
	}
	close(proceed)
	scopeWait(t, h.finished)
	if h.prog.recoveryBypass.Load() || h.prog.recoveryRunning.Load() {
		t.Fatal("healthy default did not end recovery")
	}
	if !h.prog.um.isDown(upstreamOS) {
		t.Fatal("fixture OS resolver unexpectedly recovered")
	}
}

func TestOSOnlyConfigurationRetainsOSRecovery(t *testing.T) {
	h := newScopeTestHarness(t)
	h.prog.cfg.Upstream = nil
	h.markOSDown(t)
	waitForUpstreamRecoveryFn = func(p *prog, ctx context.Context, ups map[string]*ctrld.UpstreamConfig, diagnostic *recoveryDiagnostic) (string, error) {
		if len(ups) != 1 || ups[upstreamOS] != osUpstreamConfig {
			return "", context.Canceled
		}
		h.osAnswers.Store(true)
		return p.waitForUpstreamRecovery(ctx, ups, diagnostic)
	}
	h.query(t, true)
	scopeWait(t, h.finished)
	end := oneRecoveryEvent(t, h.logs, recoveryEndMessage)
	wantField(t, end, "outcome", "completed")
	wantField(t, end, "recovered_upstream", upstreamOS)
	if h.prog.recoveryBypass.Load() || h.prog.um.isDown(upstreamOS) {
		t.Fatal("OS-only recovery did not finish")
	}
}

func TestOSRecoveryRejectedBeforeHostWork(t *testing.T) {
	for _, intercept := range []bool{false, true} {
		t.Run(map[bool]string{false: "traditional", true: "intercept"}[intercept], func(t *testing.T) {
			h := newScopeTestHarness(t)
			dnsIntercept = intercept
			oldReset := recoveryResetDNSFn
			t.Cleanup(func() { recoveryResetDNSFn = oldReset })
			calls := 0
			recoveryResetDNSFn = func(*prog, bool, bool) { calls++ }
			refreshes := 0
			initializeOsResolverWithSystemNameserversFn = func(context.Context, bool, string) ([]string, []string) { refreshes++; return nil, nil }
			ensureInterceptDNSTargetFn = func(*prog, []string) { calls++ }
			waitForUpstreamRecoveryFn = func(*prog, context.Context, map[string]*ctrld.UpstreamConfig, *recoveryDiagnostic) (string, error) {
				calls++
				return "", context.Canceled
			}
			before := h.prog.recoveryGen.Load()
			h.prog.handleRecovery(RecoveryReasonOSFailure)
			if refreshes != 1 || calls != 0 || h.prog.recoveryGen.Load() != before || h.prog.recoveryRunning.Load() || h.prog.recoveryBypass.Load() {
				t.Fatal("rejected recovery failed to refresh only OS resolver discovery")
			}
		})
	}
}

func TestOSRecoveryKeepsExistingOwner(t *testing.T) {
	h := newScopeTestHarness(t)
	ctx, gen, _, ok := h.prog.beginRecovery(RecoveryReasonRegularFailure)
	if !ok {
		t.Fatal("could not establish prior owner")
	}
	t.Cleanup(func() { h.prog.completeRecoveryState(gen) })
	h.prog.handleRecovery(RecoveryReasonOSFailure)
	if ctx.Err() != nil || h.prog.recoveryGen.Load() != gen || !h.prog.recoveryOwnsState(gen) || !h.prog.recoveryBypass.Load() {
		t.Fatal("rejected OS recovery displaced the active owner")
	}
}

func TestOSRecoveryConfiguredPoolDoesNotBlockRegularFailure(t *testing.T) {
	h := newScopeTestHarness(t)
	h.markOSDown(t)
	h.prog.cfg.Upstream["unused"] = &ctrld.UpstreamConfig{Type: ctrld.ResolverTypeLegacy, Endpoint: "127.0.0.1:1"}
	h.prog.um.mu.Lock()
	h.prog.um.markDown("upstream.0", 1, "test")
	h.prog.um.mu.Unlock()
	h.query(t, true)
	scopeWait(t, h.finished)
	if len(jsonLogEvents(t, h.logs, recoveryBeginMessage)) != 0 {
		t.Fatal("OS admission ignored an unmarked configured candidate")
	}
	// Ordinary default failure still follows its original admission path.
	h.defaultAnswers.Store(false)
	h.query(t, false)
	scopeWait(t, h.finished)
	begin := oneRecoveryEvent(t, h.logs, recoveryBeginMessage)
	wantField(t, begin, "recovery_reason", "upstream_failure")
}

func TestOtherRecoveryPoolsRemainUnchanged(t *testing.T) {
	remote := &ctrld.UpstreamConfig{Type: ctrld.ResolverTypeDOH}
	internal := &ctrld.UpstreamConfig{Type: ctrld.ResolverTypeLegacy}
	p := &prog{cfg: &ctrld.Config{Upstream: map[string]*ctrld.UpstreamConfig{
		"0": remote, "internal_0": internal, "1": {Type: ctrld.ResolverTypeOS}, "2": nil,
	}}}
	want := map[string]*ctrld.UpstreamConfig{"upstream.0": remote, "upstream.internal_0": internal}
	for _, reason := range []RecoveryReason{RecoveryReasonRegularFailure, RecoveryReasonNetworkChange} {
		if got := p.buildRecoveryUpstreams(reason); !reflect.DeepEqual(got, want) {
			t.Fatalf("reason=%v got=%v want=%v", reason, got, want)
		}
	}
}

func TestScopeHarnessRestoresRecoveryWait(t *testing.T) {
	original := waitForUpstreamRecoveryFn
	t.Cleanup(func() { waitForUpstreamRecoveryFn = original })
	waitForUpstreamRecoveryFn = func(*prog, context.Context, map[string]*ctrld.UpstreamConfig, *recoveryDiagnostic) (string, error) {
		return "outer", nil
	}
	t.Run("overridden wait", func(t *testing.T) {
		newScopeTestHarness(t)
		waitForUpstreamRecoveryFn = func(*prog, context.Context, map[string]*ctrld.UpstreamConfig, *recoveryDiagnostic) (string, error) {
			return "inner", nil
		}
	})
	got, err := waitForUpstreamRecoveryFn(nil, context.Background(), nil, nil)
	if err != nil || got != "outer" {
		t.Fatalf("composed harness leaked its wait function: got %q, %v", got, err)
	}
}

func TestOSRecoveryCandidates(t *testing.T) {
	remote := &ctrld.UpstreamConfig{Type: ctrld.ResolverTypeDOH}
	internal := &ctrld.UpstreamConfig{Type: ctrld.ResolverTypeLegacy}
	osConfig := &ctrld.UpstreamConfig{Type: ctrld.ResolverTypeOS}
	for _, tc := range []struct {
		name       string
		configured map[string]*ctrld.UpstreamConfig
		want       map[string]*ctrld.UpstreamConfig
	}{
		{"configured", map[string]*ctrld.UpstreamConfig{"0": remote, "internal_0": internal, "1": osConfig, "2": nil}, map[string]*ctrld.UpstreamConfig{"upstream.0": remote}},
		{"custom_policy_or_unused", map[string]*ctrld.UpstreamConfig{"0": remote, "unused": internal}, map[string]*ctrld.UpstreamConfig{"upstream.0": remote, "upstream.unused": internal}},
		{"only_os", map[string]*ctrld.UpstreamConfig{"0": osConfig}, map[string]*ctrld.UpstreamConfig{upstreamOS: osUpstreamConfig}},
		{"only_internal", map[string]*ctrld.UpstreamConfig{"internal_0": internal}, map[string]*ctrld.UpstreamConfig{upstreamOS: osUpstreamConfig}},
		{"empty", nil, map[string]*ctrld.UpstreamConfig{upstreamOS: osUpstreamConfig}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &prog{cfg: &ctrld.Config{Upstream: tc.configured}}
			if got := p.buildRecoveryUpstreams(RecoveryReasonOSFailure); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}
