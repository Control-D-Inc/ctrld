package cli

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Control-D-Inc/ctrld"
)

// The two events that bound one recovery pass.
const (
	recoveryBeginMessage = "Recovery begin"
	recoveryEndMessage   = "Recovery end"
)

// recoveredUpstreamName is the upstream that the stubbed probe reports.
const recoveredUpstreamName = upstreamPrefix + "0"

// recoveryEventHarness runs one whole recovery pass. It stubs every seam of
// the pass, because a real pass probes an upstream, reads the host resolvers,
// and rewrites the PF anchor.
type recoveryEventHarness struct {
	prog        *prog
	logs        *syncBuffer
	dhcpServers []string
	target      string
	recovered   string
}

func newRecoveryEventHarness(t *testing.T) *recoveryEventHarness {
	t.Helper()
	h := &recoveryEventHarness{
		logs:        captureDebugMainLog(t),
		prog:        &prog{cfg: &ctrld.Config{}, dnsInterceptState: &interceptStateStub{}},
		dhcpServers: []string{"192.168.10.1"},
		target:      "127.0.0.53",
		recovered:   recoveredUpstreamName,
	}
	h.prog.logger.Store(mainLog.Load())
	stubHeaderSnapshotSources(t)
	h.prog.um = newUpstreamMonitor(&ctrld.Config{}, mainLog.Load())
	h.prog.lastNetworkState.Store(sourceTestState("en0", true, "192.0.2.10/24"))
	// A stabilizing host defers the DHCP exemption, so the pass rewrites no
	// PF anchor.
	h.prog.pfStabilizing.Store(true)

	intercept := dnsIntercept
	discovery := initializeOsResolverWithSystemNameserversFn
	ensure := ensureInterceptDNSTargetFn
	wait := waitForUpstreamRecoveryFn
	t.Cleanup(func() {
		dnsIntercept = intercept
		initializeOsResolverWithSystemNameserversFn = discovery
		ensureInterceptDNSTargetFn = ensure
		waitForUpstreamRecoveryFn = wait
	})
	dnsIntercept = true
	initializeOsResolverWithSystemNameserversFn = func(context.Context, bool, string) ([]string, []string) {
		return effectiveNameserversOf(h.dhcpServers), h.dhcpServers
	}
	ensureInterceptDNSTargetFn = func(p *prog, _ []string) {
		p.interceptDNSTargetMu.Lock()
		defer p.interceptDNSTargetMu.Unlock()
		p.interceptDNSTargetSetValue = h.target
		p.publishInterceptTarget(h.target)
	}
	waitForUpstreamRecoveryFn = func(*prog, context.Context, map[string]*ctrld.UpstreamConfig, *recoveryDiagnostic) (string, error) {
		return h.recovered, nil
	}
	return h
}

// effectiveNameserversOf models the OS resolver list that the root package
// builds: every discovered server with a port, and a synthetic public resolver
// when the network gave no public one.
func effectiveNameserversOf(discovered []string) []string {
	effective := make([]string, 0, len(discovered)+1)
	for _, server := range discovered {
		effective = append(effective, server+":53")
	}
	return append(effective, "76.76.2.0:53")
}

// oneRecoveryEvent returns the single event with the given message.
func oneRecoveryEvent(t *testing.T, logs *syncBuffer, message string) map[string]any {
	t.Helper()
	events := jsonLogEvents(t, logs, message)
	if len(events) != 1 {
		t.Fatalf("%q events: got %d, want 1", message, len(events))
	}
	return events[0]
}

// snapshotTriggers lists the trigger of every snapshot event, in order.
func snapshotTriggers(t *testing.T, logs *syncBuffer) []string {
	t.Helper()
	var triggers []string
	for _, event := range jsonLogEvents(t, logs, networkSnapshotMessage) {
		trigger, _ := event["trigger"].(string)
		triggers = append(triggers, trigger)
	}
	return triggers
}

func Test_recoveryCompletedJournalsBeginAndEnd(t *testing.T) {
	h := newRecoveryEventHarness(t)

	h.prog.handleRecoveryForTransition(RecoveryReasonRegularFailure, 0)

	begin := oneRecoveryEvent(t, h.logs, recoveryBeginMessage)
	wantField(t, begin, "journal", true)
	wantField(t, begin, "level", "info")

	end := oneRecoveryEvent(t, h.logs, recoveryEndMessage)
	wantField(t, end, "journal", true)
	wantField(t, end, "outcome", "completed")
	wantField(t, end, "recovered_upstream", recoveredUpstreamName)
	wantField(t, end, "bypass_active", false)
	wantField(t, end, "intercept_target_action", "set")
	wantField(t, end, "dhcp_server_count", float64(1))
	if got, want := end["dhcp_servers"], []any{"192.168.10.1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("dhcp_servers = %v, want %v", got, want)
	}

	// The network of this recovery does not change, so the end snapshot equals
	// the begin snapshot and the writer drops it.
	triggers := snapshotTriggers(t, h.logs)
	if want := []string{"recovery_begin"}; !reflect.DeepEqual(triggers, want) {
		t.Fatalf("snapshot triggers = %v, want %v", triggers, want)
	}
}

// Test_recoveryEndReportsTheDiscoveredDHCPNameservers drives the real OS
// resolver initialization. The effective list carries a synthetic public
// resolver, and a reader who counts it reads a DHCP server that the network
// never gave.
func Test_recoveryEndReportsTheDiscoveredDHCPNameservers(t *testing.T) {
	h := newRecoveryEventHarness(t)
	previousRead := ctrld.NameserversFn
	ctrld.NameserversFn = func(context.Context) []string { return []string{"192.168.1.1"} }
	t.Cleanup(func() { ctrld.NameserversFn = previousRead })
	initializeOsResolverWithSystemNameserversFn = ctrld.InitializeOsResolverWithSystemNameserversReason

	h.prog.handleRecoveryForTransition(RecoveryReasonRegularFailure, 0)

	end := oneRecoveryEvent(t, h.logs, recoveryEndMessage)
	wantField(t, end, "dhcp_server_count", float64(1))
	if got, want := end["dhcp_servers"], []any{"192.168.1.1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("dhcp_servers = %v, want %v", got, want)
	}
}

// Test_recoveryJournalsTheReinitializedOSResolver covers the resolver line of
// a recovered network. The line names the nameservers that the recovery
// installed, and an outage report needs them.
func Test_recoveryJournalsTheReinitializedOSResolver(t *testing.T) {
	h := newRecoveryEventHarness(t)
	previousRead := ctrld.NameserversFn
	ctrld.NameserversFn = func(context.Context) []string { return []string{"192.168.1.1"} }
	t.Cleanup(func() { ctrld.NameserversFn = previousRead })

	h.prog.handleRecoveryForTransition(RecoveryReasonNetworkChange, 0)

	event := oneRecoveryEvent(t, h.logs, "Reinitialized OS resolver with nameservers: [192.168.1.1:53 76.76.2.0:53]")
	wantField(t, event, "journal", true)
	wantField(t, event, "level", "info")
}

// Test_recoveryEndSpeedsUpTheDNSConfigurationPoll covers the poll cadence
// after a recovery. The resolver table of the host settles late, and a poll
// every five minutes reports that change long after the outage.
func Test_recoveryEndSpeedsUpTheDNSConfigurationPoll(t *testing.T) {
	h := newRecoveryEventHarness(t)
	now := time.Date(2026, 9, 17, 9, 0, 0, 0, time.UTC)
	previousNow := networkEventsNowFn
	networkEventsNowFn = func() time.Time { return now }
	t.Cleanup(func() { networkEventsNowFn = previousNow })
	h.prog.dnsConfig = newDNSConfigPoller(func() ([]dnsResolverEntry, error) { return nil, nil })

	h.prog.handleRecoveryForTransition(RecoveryReasonRegularFailure, 0)

	if got := h.prog.dnsConfig.nextDelay(now); got != dnsConfigFastInterval {
		t.Fatalf("DNS configuration poll delay after a recovery = %s, want %s", got, dnsConfigFastInterval)
	}
}

func Test_recoveryJournalsTheRecoveredUpstream(t *testing.T) {
	h := newRecoveryEventHarness(t)
	h.prog.um.mu.Lock()
	h.prog.um.markDown(recoveredUpstreamName, 7, "timer")
	h.prog.um.mu.Unlock()

	h.prog.handleRecoveryForTransition(RecoveryReasonRegularFailure, 0)

	event := oneRecoveryEvent(t, h.logs, "Upstream \""+recoveredUpstreamName+"\" recovered; re-applying DNS settings")
	wantField(t, event, "journal", true)
	wantField(t, event, "upstream", recoveredUpstreamName)
	if _, ok := event["down_for_ms"]; !ok {
		t.Fatalf("event has no down_for_ms field: %v", event)
	}
}

// Test_recoveryBoundsTheRecoveredUpstreamName covers an upstream key that
// holds a token. The key is operator text, and the journal leaves the host
// for a support case, so no line may carry it.
func Test_recoveryBoundsTheRecoveredUpstreamName(t *testing.T) {
	const secret = "SECRET0123"
	h := newRecoveryEventHarness(t)
	h.recovered = upstreamPrefix + "doh-" + secret
	h.prog.um.mu.Lock()
	h.prog.um.markDown(h.recovered, 1, "timer")
	h.prog.um.mu.Unlock()

	h.prog.handleRecoveryForTransition(RecoveryReasonRegularFailure, 0)

	const boundedName = upstreamPrefix + "custom"
	event := oneRecoveryEvent(t, h.logs, "Upstream \""+boundedName+"\" recovered; re-applying DNS settings")
	wantField(t, event, "upstream", boundedName)
	wantField(t, oneRecoveryEvent(t, h.logs, recoveryEndMessage), "recovered_upstream", boundedName)
	if strings.Contains(h.logs.String(), secret) {
		t.Fatalf("a log line holds the upstream key: %s", h.logs.String())
	}
}

func Test_recoveryJournalsTheDHCPBypassLines(t *testing.T) {
	h := newRecoveryEventHarness(t)

	h.prog.handleRecoveryForTransition(RecoveryReasonRegularFailure, 0)

	for _, message := range []string{
		"DNS intercept recovery: enabling DHCP bypass (filters stay active)",
		"DNS intercept recovery: found DHCP nameservers: [192.168.10.1]",
		"DNS intercept recovery complete: disabling DHCP bypass, resuming normal flow",
	} {
		wantField(t, oneRecoveryEvent(t, h.logs, message), "journal", true)
	}
}

func Test_recoveryJournalsTheMissingDHCPNameservers(t *testing.T) {
	h := newRecoveryEventHarness(t)
	h.dhcpServers = nil

	h.prog.handleRecoveryForTransition(RecoveryReasonRegularFailure, 0)

	event := oneRecoveryEvent(t, h.logs, "DNS intercept recovery: no DHCP nameservers found")
	wantField(t, event, "journal", true)
	wantField(t, oneRecoveryEvent(t, h.logs, recoveryEndMessage), "dhcp_server_count", float64(0))
}

// wantOneRecoveryEndPerGeneration asserts the two lines that bound one pass:
// one end event and one snapshot beside it.
func wantOneRecoveryEndPerGeneration(t *testing.T, h *recoveryEventHarness) map[string]any {
	t.Helper()
	end := oneRecoveryEvent(t, h.logs, recoveryEndMessage)
	triggers := snapshotTriggers(t, h.logs)
	// Nothing changes between the begin and the end of these passes, so the
	// snapshot limiter drops the end snapshot as a repeat of the begin one.
	if want := []string{"recovery_begin"}; !reflect.DeepEqual(triggers, want) {
		t.Fatalf("snapshot triggers = %v, want %v", triggers, want)
	}
	return end
}

// Test_recoveryCanceledEndReportsTheCanceledPass covers the canceled outcome.
// A canceled pass releases the bypass, and support reads the end event to tell
// a canceled pass from a pass that never ended.
func Test_recoveryCanceledEndReportsTheCanceledPass(t *testing.T) {
	h := newRecoveryEventHarness(t)
	waitForUpstreamRecoveryFn = func(*prog, context.Context, map[string]*ctrld.UpstreamConfig, *recoveryDiagnostic) (string, error) {
		return "", context.Canceled
	}

	h.prog.handleRecoveryForTransition(RecoveryReasonRegularFailure, 0)

	end := wantOneRecoveryEndPerGeneration(t, h)
	wantField(t, end, "outcome", "canceled")
	wantField(t, end, "bypass_active", false)
	wantField(t, end, "recovered_upstream", "")
}

// Test_recoverySupersededEndReportsNoChange covers the superseded outcome. The
// successor owns the target and the bypass flag, so the end event of the
// superseded pass must not report the state of its successor.
func Test_recoverySupersededEndReportsNoChange(t *testing.T) {
	h := newRecoveryEventHarness(t)
	waitForUpstreamRecoveryFn = func(p *prog, _ context.Context, _ map[string]*ctrld.UpstreamConfig, _ *recoveryDiagnostic) (string, error) {
		// A network change took ownership while the probe ran.
		p.recoveryGen.Add(1)
		return recoveredUpstreamName, nil
	}

	h.prog.handleRecoveryForTransition(RecoveryReasonRegularFailure, 0)

	end := wantOneRecoveryEndPerGeneration(t, h)
	wantField(t, end, "outcome", "superseded")
	wantField(t, end, "bypass_active", false)
	wantField(t, end, "intercept_target_action", "unchanged")
}

func Test_recoveryCanceledWithNoSuccessorIsJournaled(t *testing.T) {
	logs := captureDebugMainLog(t)
	p := &prog{}
	p.logger.Store(mainLog.Load())
	setupInterceptRecovery(t, p)

	p.recoveryCanceledCleanup(p.recoveryGen.Add(1))

	event := oneRecoveryEvent(t, logs, "Recovery canceled with no successor; cleared recovery state and DHCP bypass")
	wantField(t, event, "journal", true)
}

func Test_interceptTargetAction(t *testing.T) {
	for _, tc := range []struct {
		name          string
		before, after string
		want          string
	}{
		{"no target at all", "", "", "unchanged"},
		{"target kept", "127.0.0.53", "127.0.0.53", "unchanged"},
		{"target written", "", "127.0.0.53", "set"},
		{"target moved", "127.0.0.53", "127.0.0.54", "set"},
		{"target dropped", "127.0.0.53", "", "removed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := interceptTargetAction(tc.before, tc.after); got != tc.want {
				t.Fatalf("interceptTargetAction(%q, %q) = %q, want %q", tc.before, tc.after, got, tc.want)
			}
		})
	}
}

func Test_noteNAT64ResultReportsChangesOnly(t *testing.T) {
	p := &prog{}
	p.logger.Store(mainLog.Load())
	const prefix = "64:ff9b::/96"

	for _, tc := range []struct {
		result string
		want   bool
	}{
		{prefix, true},
		{prefix, false},
		{"", true},
	} {
		if got := p.noteNAT64Result(tc.result); got != tc.want {
			t.Fatalf("noteNAT64Result(%q) = %v, want %v", tc.result, got, tc.want)
		}
	}
}
