package cli

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"tailscale.com/net/netmon"

	"github.com/Control-D-Inc/ctrld"
)

func sourceTestState(route string, up bool, ips ...string) *netmon.State {
	flags := net.Flags(0)
	if up {
		flags = net.FlagUp
	}
	s := &netmon.State{
		DefaultRouteInterface: route,
		Interface:             map[string]netmon.Interface{"en0": {Interface: &net.Interface{Name: "en0", Flags: flags}}},
		InterfaceIPs:          map[string][]netip.Prefix{},
	}
	for _, ip := range ips {
		s.InterfaceIPs["en0"] = append(s.InterfaceIPs["en0"], netip.MustParsePrefix(ip))
	}
	return s
}

func captureTransitionLogs(t *testing.T) *syncBuffer {
	t.Helper()
	old := mainLog.Load()
	buf := &syncBuffer{}
	logger := sourceTestLogger(buf)
	mainLog.Store(logger)
	t.Cleanup(func() { mainLog.Store(old) })
	return buf
}

func sourceTestGlobals(t *testing.T) {
	t.Helper()
	// A transition reads the hardware ports and the virtual adapters, and no
	// test may start the commands behind them.
	stubHeaderSnapshotSources(t)
	stubSnapshotVirtualSet(t)
	v4, v6 := ctrld.GetDefaultLocalIPv4(), ctrld.GetDefaultLocalIPv6()
	valid, route := networkChangeValidInterfacesFn, networkChangeDefaultRouteIPFn
	reconcile, ignored := networkChangeReconcileFn, networkChangeIgnoredInterceptFn
	intercept := dnsIntercept
	dnsIntercept = true
	networkChangeValidInterfacesFn = func(context.Context) map[string]struct{} { return map[string]struct{}{"en0": {}} }
	networkChangeDefaultRouteIPFn = func(*prog) string { return "" }
	t.Cleanup(func() {
		ctrld.SetDefaultLocalIPv4(context.Background(), v4)
		ctrld.SetDefaultLocalIPv6(context.Background(), v6)
		networkChangeValidInterfacesFn, networkChangeDefaultRouteIPFn = valid, route
		networkChangeReconcileFn, networkChangeIgnoredInterceptFn = reconcile, ignored
		dnsIntercept = intercept
	})
}

func TestNetworkChangeSourceLifecycle(t *testing.T) {
	const v4, v6 = "192.0.2.10", "2001:db8::10"
	for _, tt := range []struct {
		name                      string
		newState                  *netmon.State
		preferred                 string
		want4, want6              string
		outcome, reason4, reason6 string
	}{
		{"dhcp_lease_replacement_keeps_ipv6", sourceTestState("en0", true, "192.0.2.20/24", v6+"/64"), "", "192.0.2.20", v6, "accepted", "address_removed", ""},
		{"dhcp_lease_replacement", sourceTestState("en0", true, "192.0.2.20/24"), "", "192.0.2.20", "", "accepted", "address_removed", "address_removed"},
		{"accepted_ipv4_loss", sourceTestState("en0", true, v6+"/64"), "", "", v6, "accepted", "address_removed", ""},
		{"accepted_ipv6_loss", sourceTestState("en0", true, v4+"/24"), v4, v4, "", "accepted", "", "address_removed"},
		{"stale_route_discovery", sourceTestState("en0", true, v6+"/64"), v4, "", v6, "accepted", "address_removed", ""},
		{"ignored_down_retains_addresses", sourceTestState("en0", false, v4+"/24", v6+"/64"), "", "", "", "ignored", "interface_down", "interface_down"},
		{"ignored_address_loss", sourceTestState("en0", true), "", "", "", "ignored", "address_removed", "address_removed"},
		{"skipped_no_active_interface", sourceTestState("", false, v4+"/24", v6+"/64"), "", "", "", "no_active_interface", "interface_down", "interface_down"},
		{"ignored_valid_sources", sourceTestState("en0", true, v4+"/24", v6+"/64"), "", v4, v6, "ignored", "", ""},
		{"accepted_valid_preferred_source", sourceTestState("en0", true, "192.0.2.20/24", v4+"/24", v6+"/64"), v4, v4, v6, "accepted", "", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sourceTestGlobals(t)
			logs := captureTransitionLogs(t)
			ctrld.SetDefaultLocalIPv4(context.Background(), net.ParseIP(v4))
			ctrld.SetDefaultLocalIPv6(context.Background(), net.ParseIP(v6))
			networkChangeDefaultRouteIPFn = func(*prog) string { return tt.preferred }
			p := sourceTestProg(&prog{cfg: &ctrld.Config{}, dnsInterceptState: &interceptStateStub{}})
			accepted, ignored := 0, 0
			assertSources := func() {
				t.Helper()
				if got := ctrld.GetDefaultLocalIPv4(); !got.Equal(net.ParseIP(tt.want4)) {
					t.Errorf("IPv4 = %v, want %s", got, tt.want4)
				}
				if got := ctrld.GetDefaultLocalIPv6(); !got.Equal(net.ParseIP(tt.want6)) {
					t.Errorf("IPv6 = %v, want %s", got, tt.want6)
				}
			}
			// These seams precede all DNS/PF writes and recovery timers, on every OS.
			networkChangeReconcileFn = func(_ *prog, _ context.Context, id uint64) {
				accepted++
				if id != 1 {
					t.Errorf("transition ID = %d", id)
				}
				assertSources()
			}
			networkChangeIgnoredInterceptFn = func(_ *prog, _ *netmon.ChangeDelta, _ time.Time) { ignored++; assertSources() }
			p.handleNetworkChange(context.Background(), &netmon.ChangeDelta{Old: sourceTestState("en0", true, v4+"/24", v6+"/64"), New: tt.newState}, true)
			assertSources()
			wantAccepted, wantIgnored := 0, 0
			if tt.outcome == "accepted" {
				wantAccepted = 1
			}
			if tt.outcome == "ignored" {
				wantIgnored = 1
			}
			if accepted != wantAccepted || ignored != wantIgnored {
				t.Fatalf("mutation boundaries: accepted=%d ignored=%d; want %d/%d", accepted, ignored, wantAccepted, wantIgnored)
			}
			var transition, warning map[string]any
			for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
				var event map[string]any
				if err := json.Unmarshal([]byte(line), &event); err != nil {
					t.Fatal(err)
				}
				switch event["message"] {
				case "Network transition":
					transition = event
				case "Removed stale resolver source":
					warning = event
				}
			}
			if transition["outcome"] != tt.outcome || transition["transition_id"] != float64(1) {
				t.Fatalf("transition: %v", transition)
			}
			wantWarning := tt.reason4 != "" || tt.reason6 != ""
			if (warning != nil) != wantWarning {
				t.Fatalf("warning = %v, want warning %v", warning, wantWarning)
			}
			if wantWarning && (warning["ipv4_clear_reason"] != tt.reason4 || warning["ipv6_clear_reason"] != tt.reason6 || warning["level"] != "warn") {
				t.Fatalf("warning reasons/level: %v", warning)
			}
		})
	}
}

func TestNetworkChangeDoesNotRestoreDownDefaultRouteSources(t *testing.T) {
	sourceTestGlobals(t)
	const v4, v6 = "192.0.2.10", "2001:db8::10"
	ctrld.SetDefaultLocalIPv4(context.Background(), net.ParseIP(v4))
	ctrld.SetDefaultLocalIPv6(context.Background(), net.ParseIP(v6))
	networkChangeDefaultRouteIPFn = func(*prog) string { return v4 }
	old := sourceTestState("en1", true, "2001:db8:1::10/64")
	old.Interface["en1"] = netmon.Interface{Interface: &net.Interface{Name: "en1", Flags: net.FlagUp}}
	old.InterfaceIPs["en1"] = []netip.Prefix{netip.MustParsePrefix(v4 + "/24"), netip.MustParsePrefix(v6 + "/64")}
	newState := sourceTestState("en1", true, "2001:db8:1::20/64")
	newState.Interface["en1"] = netmon.Interface{Interface: &net.Interface{Name: "en1"}}
	newState.InterfaceIPs["en1"] = old.InterfaceIPs["en1"]
	called := 0
	networkChangeReconcileFn = func(_ *prog, _ context.Context, _ uint64) {
		called++
		if ctrld.GetDefaultLocalIPv4() != nil || ctrld.GetDefaultLocalIPv6() != nil {
			t.Error("down-interface sources reintroduced before recovery")
		}
	}
	networkChangeIgnoredInterceptFn = func(_ *prog, _ *netmon.ChangeDelta, _ time.Time) { t.Fatal("accepted delta was ignored") }
	(sourceTestProg(&prog{cfg: &ctrld.Config{}, dnsInterceptState: &interceptStateStub{}})).handleNetworkChange(context.Background(), &netmon.ChangeDelta{Old: old, New: newState}, true)
	if called != 1 {
		t.Fatalf("reconciliation called %d times", called)
	}
}

func TestNetworkChangeSourceMovedToUpInterface(t *testing.T) {
	sourceTestGlobals(t)
	ctrld.SetDefaultLocalIPv4(context.Background(), net.ParseIP("192.0.2.10"))
	ctrld.SetDefaultLocalIPv6(context.Background(), nil)
	state := sourceTestState("en0", false, "192.0.2.10/24")
	state.Interface["utun0"] = netmon.Interface{Interface: &net.Interface{Name: "utun0", Flags: net.FlagUp}}
	state.InterfaceIPs["utun0"] = state.InterfaceIPs["en0"]
	called := 0
	networkChangeReconcileFn = func(_ *prog, _ context.Context, _ uint64) { t.Fatal("unexpected recovery") }
	networkChangeIgnoredInterceptFn = func(_ *prog, _ *netmon.ChangeDelta, _ time.Time) { called++ }
	(sourceTestProg(&prog{cfg: &ctrld.Config{}, dnsInterceptState: &interceptStateStub{}})).handleNetworkChange(context.Background(), &netmon.ChangeDelta{Old: state, New: state}, false)
	if called != 1 || !ctrld.GetDefaultLocalIPv4().Equal(net.ParseIP("192.0.2.10")) {
		t.Fatal("valid source on another up interface was cleared")
	}
}

func TestRecoveryTransitionDiagnostics(t *testing.T) {
	logs := captureTransitionLogs(t)
	stubHeaderSnapshotSources(t)
	original, intercept := recoveryResetDNSFn, dnsIntercept
	dnsIntercept = false
	t.Cleanup(func() { recoveryResetDNSFn = original; dnsIntercept = intercept })
	for _, superseded := range []bool{false, true} {
		p := sourceTestProg(&prog{cfg: &ctrld.Config{}})
		calls := 0
		recoveryResetDNSFn = func(p *prog, start, restore bool) {
			calls++
			if start || restore {
				t.Error("changed reset flags")
			}
			if superseded {
				p.beginRecovery(RecoveryReasonNetworkChange)
			} else {
				p.recoveryCancel()
			}
		}
		p.networkAcceptedGen.Store(42)
		p.handleRecoveryForTransition(RecoveryReasonNetworkChange, 42)
		if calls != 1 {
			t.Fatalf("resetDNS seam called %d times", calls)
		}
		if p.recoveryCancel != nil {
			p.recoveryCancel()
		}
	}
	for _, expected := range []string{`"transition_id":42`, `"recovery_generation":1`, `"message":"Recovery begin"`, `"outcome":"canceled"`, `"outcome":"superseded"`, `"message":"Recovery end"`} {
		if !strings.Contains(logs.String(), expected) {
			t.Errorf("missing %s in %s", expected, logs.String())
		}
	}
}

func TestRecoveryDebouncePreservesTransitionID(t *testing.T) {
	original := handleRecoveryForTransitionFn
	t.Cleanup(func() { handleRecoveryForTransitionFn = original })
	ids := make(chan uint64, 2)
	handleRecoveryForTransitionFn = func(_ *prog, reason RecoveryReason, id uint64) {
		if reason != RecoveryReasonNetworkChange {
			t.Error("wrong recovery reason")
		}
		ids <- id
	}
	p := sourceTestProg(&prog{cfg: &ctrld.Config{}})
	p.networkAcceptedGen.Store(11)
	p.debounceRecovery(11)
	p.networkAcceptedGen.Store(12)
	p.debounceRecovery(12)
	p.debounceRecovery(11) // a delayed older callback must not replace the new timer
	select {
	case id := <-ids:
		if id != 12 {
			t.Fatalf("recovery transition = %d, want 12", id)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("debounced recovery did not run")
	}
}

func TestTransitionWarningsSurviveDebugRotation(t *testing.T) {
	sourceTestGlobals(t)
	old := mainLog.Load()
	debug, warnings := newLogWriterWithSize(2048), newSmallLogWriter()
	// Runtime summaries occur after initialization, outside the preserved prefix.
	debug.Write([]byte(logWriterInitEndMarker))
	config := zap.NewProductionEncoderConfig()
	config.MessageKey = "message"
	logger := &ctrld.Logger{Logger: zap.New(zapcore.NewTee(
		zapcore.NewCore(zapcore.NewJSONEncoder(config), zapcore.AddSync(debug), zap.DebugLevel),
		newJournalCore(warnings),
	))}
	mainLog.Store(logger)
	t.Cleanup(func() { mainLog.Store(old) })
	ctrld.SetDefaultLocalIPv4(context.Background(), net.ParseIP("192.0.2.10"))
	ctrld.SetDefaultLocalIPv6(context.Background(), nil)
	state := sourceTestState("en0", false, "192.0.2.10/24")
	for range 100 {
		validateDefaultLocalIPsFromDelta(ctrld.LoggerCtx(context.Background(), mainLog.Load()), state, 7)
	}
	d := &recoveryDiagnostic{transitionID: 7, generation: 9, started: time.Now()}
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() { defer wg.Done(); d.failure(errors.New("private.customer.example secret payload")) }()
	}
	wg.Wait()
	d.end("completed")
	(&recoveryDiagnostic{transitionID: 8, generation: 10, started: time.Now()}).end("completed")
	journal(logger.Info()).Str("interface", "en0").Msg("Network snapshot")
	logger.Info().Msg("plain info line")
	for range 100 {
		logger.Debug().Msg(strings.Repeat("noise", 100))
	}
	text := warnings.buf.String()
	for _, msg := range []string{"Removed stale resolver source", "Recovery waiting for upstream; first failure"} {
		if strings.Count(text, msg) != 1 {
			t.Fatalf("expected one retained %q: %s", msg, text)
		}
		if strings.Contains(debug.buf.String(), msg) {
			t.Fatalf("debug buffer did not rotate %q", msg)
		}
	}
	if strings.Count(text, "Recovery end") != 2 || !strings.Contains(text, `"outcome":"completed"`) {
		t.Fatal("recovery completion must survive rotation beside its retained failure")
	}
	if strings.Contains(text, "private.customer") || strings.Contains(text, "secret payload") {
		t.Fatalf("raw payload or normal debug elevated: %s", text)
	}
	if strings.Count(text, "Network snapshot") != 1 {
		t.Fatalf("expected one retained marked info line: %s", text)
	}
	if strings.Contains(text, "plain info line") {
		t.Fatalf("unmarked info line must not be retained: %s", text)
	}
}

func TestRecoveryWaitLogsFirstFailure(t *testing.T) {
	logs := captureTransitionLogs(t)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	d := &recoveryDiagnostic{transitionID: 8, generation: 2, started: time.Now()}
	// Invalid resolver type fails construction before any network access.
	_, err := (sourceTestProg(&prog{})).waitForUpstreamRecovery(ctx, map[string]*ctrld.UpstreamConfig{"invalid": {Type: "invalid"}}, d)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait result = %v", err)
	}
	if strings.Count(logs.String(), "Recovery waiting for upstream; first failure") != 1 {
		t.Fatalf("missing first-failure summary: %s", logs.String())
	}
}

// sourceTestProg adapts the source fixtures to master's per-program logger.
func sourceTestProg(p *prog) *prog {
	p.logger.Store(mainLog.Load())
	return p
}

func sourceTestLogger(buf *syncBuffer) *ctrld.Logger {
	config := zap.NewProductionEncoderConfig()
	config.MessageKey = "message"
	return &ctrld.Logger{Logger: zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(config), zapcore.AddSync(buf), zap.DebugLevel))}
}
