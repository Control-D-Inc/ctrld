package cli

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/Control-D-Inc/ctrld"
	"tailscale.com/net/netmon"
)

// hostWokeTestState names the network that a wake event reports.
func hostWokeTestState() *netmon.State {
	return &netmon.State{
		DefaultRouteInterface: "en0",
		Interface: map[string]netmon.Interface{
			"en0":  {Interface: &net.Interface{Name: "en0", Flags: net.FlagUp}},
			"en5":  {Interface: &net.Interface{Name: "en5"}},
			"utun": {Interface: &net.Interface{Name: "utun", Flags: net.FlagUp}},
		},
		InterfaceIPs: map[string][]netip.Prefix{},
	}
}

// hostWokeTestClock hands the wake events a clock that the test moves.
func hostWokeTestClock(t *testing.T, clock *time.Time) {
	t.Helper()
	original := networkEventsNowFn
	t.Cleanup(func() { networkEventsNowFn = original })
	networkEventsNowFn = func() time.Time { return *clock }
}

// hostWokeTestHold captures the hold timer of the wake reporter, so a test
// decides when the hold ends.
func hostWokeTestHold(p *prog) *[]func() {
	var armed []func()
	p.wake.after = func(_ time.Duration, fn func()) { armed = append(armed, fn) }
	return &armed
}

// Test_noteHostWokeNetmonFirstWaitsForTheDetectorGap covers the order of the
// 2026-09-14 capture. netmon sees the time jump first and measures no gap, so
// its report waits for the detector, and the journal gets one event with the
// gap.
func Test_noteHostWokeNetmonFirstWaitsForTheDetectorGap(t *testing.T) {
	logs := captureDebugMainLog(t)
	clock := time.Date(2026, 9, 17, 7, 14, 0, 0, time.UTC)
	hostWokeTestClock(t, &clock)
	p := &prog{dnsConfig: newDNSConfigPoller(func() ([]dnsResolverEntry, error) { return nil, nil })}
	p.logger.Store(mainLog.Load())
	armed := hostWokeTestHold(p)

	p.noteHostWoke("netmon", 0, hostWokeTestState())
	if events := jsonLogEvents(t, logs, hostWokeMessage); len(events) != 0 {
		t.Fatalf("got %d Host woke events before the hold ended, want 0", len(events))
	}
	if got := p.dnsConfig.nextDelay(clock); got != dnsConfigFastInterval {
		t.Fatalf("DNS configuration poll delay after a wake = %s, want %s", got, dnsConfigFastInterval)
	}
	clock = clock.Add(2 * time.Second)
	p.noteHostWoke("detector", 90*time.Second, hostWokeTestState())
	for _, fire := range *armed {
		fire()
	}

	events := jsonLogEvents(t, logs, hostWokeMessage)
	if len(events) != 1 {
		t.Fatalf("got %d Host woke events, want one report with the gap of the detector", len(events))
	}
	wantField(t, events[0], "source", "detector")
	wantField(t, events[0], "gap_known", true)
	wantField(t, events[0], "gap_ms", float64(90000))
	wantField(t, events[0], "default_route", "en0")
	wantField(t, events[0], "interfaces_up", float64(2))
	wantField(t, events[0], "journal", true)

	clock = clock.Add(5 * time.Second)
	p.noteHostWoke("netmon", 0, hostWokeTestState())
	if events = jsonLogEvents(t, logs, hostWokeMessage); len(events) != 1 {
		t.Fatalf("got %d Host woke events, want no second report inside the window", len(events))
	}
}

// Test_noteHostWokeNetmonAloneReportsAfterTheHold covers a host without the
// detector. The netmon report goes out without a gap when the hold ends.
func Test_noteHostWokeNetmonAloneReportsAfterTheHold(t *testing.T) {
	logs := captureDebugMainLog(t)
	clock := time.Date(2026, 9, 17, 7, 14, 0, 0, time.UTC)
	hostWokeTestClock(t, &clock)
	p := &prog{}
	p.logger.Store(mainLog.Load())
	armed := hostWokeTestHold(p)

	p.noteHostWoke("netmon", 0, hostWokeTestState())
	if len(*armed) != 1 {
		t.Fatalf("holds armed = %d, want 1", len(*armed))
	}
	(*armed)[0]()

	events := jsonLogEvents(t, logs, hostWokeMessage)
	if len(events) != 1 {
		t.Fatalf("got %d Host woke events after the hold, want 1", len(events))
	}
	wantField(t, events[0], "source", "netmon")
	wantField(t, events[0], "gap_known", false)
	if _, measured := events[0]["gap_ms"]; measured {
		t.Fatalf("the netmon report carries a gap that it cannot measure: %v", events[0])
	}
}

// Test_noteHostWokeDetectorFirstReportsOneEvent covers the other order. The
// gap is known with the first report, so netmon adds nothing.
func Test_noteHostWokeDetectorFirstReportsOneEvent(t *testing.T) {
	logs := captureDebugMainLog(t)
	resume := time.Date(2026, 9, 17, 7, 14, 0, 0, time.UTC)
	clock := resume
	hostWokeTestClock(t, &clock)
	p := &prog{}
	p.logger.Store(mainLog.Load())
	armed := hostWokeTestHold(p)

	p.noteHostWoke("detector", 90*time.Second, hostWokeTestState())
	clock = resume.Add(2 * time.Second)
	p.noteHostWoke("netmon", 0, hostWokeTestState())

	events := jsonLogEvents(t, logs, hostWokeMessage)
	if len(events) != 1 || len(*armed) != 0 {
		t.Fatalf("got %d Host woke events and %d holds inside the window, want 1 and 0", len(events), len(*armed))
	}
	wantField(t, events[0], "source", "detector")
	wantField(t, events[0], "gap_ms", float64(90000))

	// netmon polls every 15 s, so the window has to outlast one poll.
	clock = resume.Add(29 * time.Second)
	p.noteHostWoke("netmon", 0, hostWokeTestState())
	if events = jsonLogEvents(t, logs, hostWokeMessage); len(events) != 1 || len(*armed) != 0 {
		t.Fatalf("got %d Host woke events and %d holds, want one report for a wake that netmon reports late", len(events), len(*armed))
	}

	clock = resume.Add(31 * time.Second)
	p.noteHostWoke("netmon", 0, hostWokeTestState())
	for _, fire := range *armed {
		fire()
	}
	if events = jsonLogEvents(t, logs, hostWokeMessage); len(events) != 2 {
		t.Fatalf("got %d Host woke events after the window, want 2", len(events))
	}
}

// networkEventsHarness drives the network callback on a clock that the test
// owns. Every host read stays behind a stub, so no test starts networksetup or
// reads the route table of the machine.
type networkEventsHarness struct {
	prog       *prog
	logs       *syncBuffer
	now        time.Time
	reconciled int
	ignored    int
}

func newNetworkEventsHarness(t *testing.T, valid ...string) *networkEventsHarness {
	t.Helper()
	sourceTestGlobals(t)
	stubHeaderSnapshotSources(t)
	stubSnapshotVirtualSet(t)
	h := &networkEventsHarness{
		prog: &prog{cfg: &ctrld.Config{}, dnsInterceptState: &interceptStateStub{}},
		logs: captureDebugMainLog(t),
		now:  time.Date(2026, 9, 17, 7, 14, 0, 0, time.UTC),
	}
	h.prog.logger.Store(mainLog.Load())
	oldNow := networkEventsNowFn
	networkEventsNowFn = func() time.Time { return h.now }
	t.Cleanup(func() { networkEventsNowFn = oldNow })
	validSet := make(map[string]struct{}, len(valid))
	for _, name := range valid {
		validSet[name] = struct{}{}
	}
	networkChangeValidInterfacesFn = func(context.Context) map[string]struct{} { return validSet }
	networkChangeReconcileFn = func(_ *prog, _ context.Context, _ uint64) { h.reconciled++ }
	networkChangeIgnoredInterceptFn = func(_ *prog, _ *netmon.ChangeDelta, _ time.Time) { h.ignored++ }
	return h
}

func (h *networkEventsHarness) handle(before, after *netmon.State, timeJumped bool) {
	h.prog.handleNetworkChange(context.Background(), &netmon.ChangeDelta{Old: before, New: after, TimeJumped: timeJumped}, true)
}

// stubNetmonCache gives every callback of the harness one cache snapshot.
// netmon caches major snapshots only, so the epoch of a minor callback stays
// at that snapshot.
func (h *networkEventsHarness) stubNetmonCache(t *testing.T, cache *netmon.State) {
	t.Helper()
	oldCurrent, oldRead := networkChangeCurrentStateFn, readNetworkSourceStateFn
	t.Cleanup(func() { networkChangeCurrentStateFn, readNetworkSourceStateFn = oldCurrent, oldRead })
	networkChangeCurrentStateFn = func(*netmon.ChangeDelta) *netmon.State { return cache }
	readNetworkSourceStateFn = func() (*netmon.State, error) { return cache, nil }
}

// handleMinor drives one minor callback. netmon puts the cached major snapshot
// in Old, whatever the callback before it reported.
func (h *networkEventsHarness) handleMinor(cache, after *netmon.State) {
	h.prog.handleNetworkChange(context.Background(), &netmon.ChangeDelta{Monitor: netmon.NewStatic(), Old: cache, New: after}, false)
}

// interfaceEventsFor counts the journal events of one interface.
func (h *networkEventsHarness) interfaceEventsFor(t *testing.T, name string) int {
	t.Helper()
	count := 0
	for _, event := range jsonLogEvents(t, h.logs, interfaceChangedMessage) {
		if event["interface"] == name {
			count++
		}
	}
	return count
}

// eventsAtLevel selects the captured events of one message and one level.
func (h *networkEventsHarness) eventsAtLevel(t *testing.T, message, level string) []map[string]any {
	t.Helper()
	var selected []map[string]any
	for _, event := range jsonLogEvents(t, h.logs, message) {
		if event["level"] == level {
			selected = append(selected, event)
		}
	}
	return selected
}

var networkEventsHardwareIface = deltaTestInterface{
	name: "en0", up: true, mac: "aa:bb:cc:dd:ee:01", mtu: 1500, ips: []string{"192.0.2.10/24"},
}

// networkEventsAddressChange returns a delta that moves the address of en0.
func networkEventsAddressChange(t *testing.T) (before, after *netmon.State) {
	t.Helper()
	return deltaTestState(t, "en0", networkEventsHardwareIface),
		deltaTestState(t, "en0", deltaTestInterface{
			name: "en0", up: true, mac: "aa:bb:cc:dd:ee:01", mtu: 1500, ips: []string{"192.0.2.20/24"},
		})
}

// transitionEvent returns the one transition event of a callback.
func (h *networkEventsHarness) transitionEvent(t *testing.T) map[string]any {
	t.Helper()
	events := jsonLogEvents(t, h.logs, networkTransitionMessage)
	if len(events) != 1 {
		t.Fatalf("got %d %q events, want 1", len(events), networkTransitionMessage)
	}
	return events[0]
}

// wantNoField fails when an event carries a field that it must not.
func wantNoField(t *testing.T, event map[string]any, field string) {
	t.Helper()
	if value, carried := event[field]; carried {
		t.Fatalf("field %q: got %v, want no field", field, value)
	}
}

// noiseDeltaStates returns a delta that moves the AirDrop link-local address.
func noiseDeltaStates(t *testing.T, step int) (before, after *netmon.State) {
	t.Helper()
	airdrop := func(address int) deltaTestInterface {
		return deltaTestInterface{name: "awdl0", up: true, mtu: 1484, ips: []string{fmt.Sprintf("fe80::%d/64", address)}}
	}
	return deltaTestState(t, "en0", networkEventsHardwareIface, airdrop(step)),
		deltaTestState(t, "en0", networkEventsHardwareIface, airdrop(step+1))
}

func wantStringsField(t *testing.T, event map[string]any, field string, want ...string) {
	t.Helper()
	values, ok := event[field].([]any)
	if !ok {
		t.Fatalf("field %q: got %v, want a list", field, event[field])
	}
	got := make([]string, 0, len(values))
	for _, value := range values {
		text, isText := value.(string)
		if !isText {
			t.Fatalf("field %q: got %v, want strings", field, event[field])
		}
		got = append(got, text)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("field %q: got %v, want %v", field, got, want)
	}
}

func Test_networkEventsNoiseDeltaSkipsTheHandler(t *testing.T) {
	h := newNetworkEventsHarness(t, "en0")

	before, after := noiseDeltaStates(t, 1)
	h.handle(before, after, false)

	if h.reconciled != 0 || h.ignored != 0 {
		t.Fatalf("noise delta ran the handler: reconciled=%d ignored=%d, want 0/0", h.reconciled, h.ignored)
	}
	debugLines := h.eventsAtLevel(t, noiseDeltaMessage, "debug")
	if len(debugLines) != 1 {
		t.Fatalf("got %d debug %q lines, want 1", len(debugLines), noiseDeltaMessage)
	}
	wantStringsField(t, debugLines[0], "interfaces", "awdl0")
	if events := jsonLogEvents(t, h.logs, networkTransitionMessage); len(events) != 0 {
		t.Fatalf("got %d %q events for a noise delta, want 0", len(events), networkTransitionMessage)
	}
}

func Test_networkEventsNoiseStormEmitsOneSummaryPerWindow(t *testing.T) {
	h := newNetworkEventsHarness(t, "en0")
	start := h.now

	for step := 0; step <= 10; step++ {
		h.now = start.Add(time.Duration(step) * time.Minute)
		before, after := noiseDeltaStates(t, step)
		h.handle(before, after, false)
	}

	summaries := h.eventsAtLevel(t, noiseDeltaMessage, "info")
	if len(summaries) != 2 {
		t.Fatalf("got %d journal %q events, want 2", len(summaries), noiseDeltaMessage)
	}
	wantField(t, summaries[0], "journal", true)
	wantField(t, summaries[0], "count", float64(1))
	wantField(t, summaries[1], "count", float64(10))
	wantField(t, summaries[1], "first_at", start.Add(time.Minute).Format(time.RFC3339))
	wantField(t, summaries[1], "last_at", start.Add(10*time.Minute).Format(time.RFC3339))
	wantStringsField(t, summaries[1], "interfaces", "awdl0")
}

func Test_networkEventsLogsEveryChangedInterface(t *testing.T) {
	h := newNetworkEventsHarness(t, "en0", "en5")
	before := deltaTestState(t, "en0",
		deltaTestInterface{name: "en0", up: true, mtu: 1500, ips: []string{"192.0.2.10/24", "2001:db8::10/64"}},
		deltaTestInterface{name: "en5", up: true, mtu: 1500, ips: []string{"198.51.100.10/24"}},
	)
	before.HaveV4, before.HaveV6 = true, true
	after := deltaTestState(t, "en0",
		deltaTestInterface{name: "en0", up: true, mtu: 1500, ips: []string{"192.0.2.20/24"}},
		deltaTestInterface{name: "en5", up: true, mtu: 1500, ips: []string{"198.51.100.20/24"}},
	)
	after.HaveV4, after.HaveV6 = true, false

	h.handle(before, after, false)

	changes := jsonLogEvents(t, h.logs, interfaceChangedMessage)
	if len(changes) != 2 {
		t.Fatalf("got %d %q events, want 2", len(changes), interfaceChangedMessage)
	}
	for index, name := range []string{"en0", "en5"} {
		wantField(t, changes[index], "journal", true)
		wantField(t, changes[index], "level", "info")
		wantField(t, changes[index], "interface", name)
		wantField(t, changes[index], "action", "ip_removed")
		wantField(t, changes[index], "class", "hardware")
		wantField(t, changes[index], "transition_id", float64(1))
		wantField(t, changes[index], "mtu", float64(1500))
	}
	wantField(t, changes[0], "is_default_route", true)
	wantField(t, changes[1], "is_default_route", false)
	wantStringsField(t, changes[0], "ips_before", "192.0.2.10/24", "2001:db8::10/64")
	wantStringsField(t, changes[0], "ips_after", "192.0.2.20/24")

	transitions := jsonLogEvents(t, h.logs, networkTransitionMessage)
	if len(transitions) != 1 {
		t.Fatalf("got %d %q events, want 1", len(transitions), networkTransitionMessage)
	}
	wantField(t, transitions[0], "journal", true)
	wantField(t, transitions[0], "level", "info")
	wantField(t, transitions[0], "outcome", "accepted")
	wantField(t, transitions[0], "time_jumped", false)
	wantField(t, transitions[0], "have_v4_before", true)
	wantField(t, transitions[0], "have_v4_after", true)
	wantField(t, transitions[0], "have_v6_before", true)
	wantField(t, transitions[0], "have_v6_after", false)
	wantStringsField(t, transitions[0], "changed_interfaces", "en0", "en5")
	if h.reconciled != 1 {
		t.Fatalf("reconciled = %d, want 1", h.reconciled)
	}
	if snapshots := jsonLogEvents(t, h.logs, networkSnapshotMessage); len(snapshots) != 1 {
		t.Fatalf("got %d %q events, want 1", len(snapshots), networkSnapshotMessage)
	}
}

func Test_networkEventsTimeJumpReportsTheWake(t *testing.T) {
	h := newNetworkEventsHarness(t, "en0")
	armed := hostWokeTestHold(h.prog)
	before, after := noiseDeltaStates(t, 1)

	h.handle(before, after, true)
	for _, fire := range *armed {
		fire()
	}

	wakes := jsonLogEvents(t, h.logs, hostWokeMessage)
	if len(wakes) != 1 {
		t.Fatalf("got %d %q events, want 1", len(wakes), hostWokeMessage)
	}
	wantField(t, wakes[0], "journal", true)
	wantField(t, wakes[0], "source", "netmon")
	wantField(t, wakes[0], "gap_known", false)
	wantField(t, wakes[0], "default_route", "en0")
	if _, measured := wakes[0]["gap_ms"]; measured {
		t.Fatalf("the netmon report carries a gap that it cannot measure: %v", wakes[0])
	}
}

func Test_networkEventsStoreTheIPv6Flag(t *testing.T) {
	h := newNetworkEventsHarness(t, "en0")
	// The one-time probe wins over the first store, so consume it first.
	available := ctrld.HasIPv6(context.Background())
	t.Cleanup(func() { ctrld.SetIPv6Available(available) })
	ctrld.SetIPv6Available(true)

	before := deltaTestState(t, "en0", networkEventsHardwareIface)
	before.HaveV6 = true
	after := deltaTestState(t, "en0", deltaTestInterface{
		name: "en0", up: true, mac: "aa:bb:cc:dd:ee:01", mtu: 1500, ips: []string{"192.0.2.20/24"},
	})
	after.HaveV6 = false

	h.handle(before, after, false)

	if ctrld.HasIPv6(context.Background()) {
		t.Fatal("HasIPv6 = true after a callback with have_v6 false, want false")
	}
}

// Test_networkEventsMinorDeltaDiffsAgainstTheStateBeforeIt covers a difference
// that lasts. The cached major snapshot holds no link-local address of en0, so
// a diff against the cache reports the same change in every minor callback.
func Test_networkEventsMinorDeltaDiffsAgainstTheStateBeforeIt(t *testing.T) {
	h := newNetworkEventsHarness(t, "en0")
	en0WithLinkLocal := deltaTestInterface{
		name: "en0", up: true, mac: "aa:bb:cc:dd:ee:01", mtu: 1500,
		ips: []string{"192.0.2.10/24", "fe80::a/64"},
	}
	airdrop := func(address int) deltaTestInterface {
		return deltaTestInterface{name: "awdl0", up: true, mtu: 1484, ips: []string{fmt.Sprintf("fe80::%d/64", address)}}
	}
	cache := deltaTestState(t, "en0", networkEventsHardwareIface, airdrop(1))
	h.stubNetmonCache(t, cache)

	h.handleMinor(cache, deltaTestState(t, "en0", en0WithLinkLocal, airdrop(2)))
	h.handleMinor(cache, deltaTestState(t, "en0", en0WithLinkLocal, airdrop(3)))

	if got := h.interfaceEventsFor(t, "en0"); got != 1 {
		t.Fatalf("got %d %q events for en0, want 1", got, interfaceChangedMessage)
	}
	if noise := h.eventsAtLevel(t, noiseDeltaMessage, "debug"); len(noise) != 1 {
		t.Fatalf("got %d debug %q lines, want 1 for the second delta", len(noise), noiseDeltaMessage)
	}
}

// Test_networkEventsNoiseDeltaReadsNoPlatformMeta pins the class-first order.
// The macOS meta read starts two subprocesses per call, so a storm of noise
// deltas must not reach it.
func Test_networkEventsNoiseDeltaReadsNoPlatformMeta(t *testing.T) {
	h := newNetworkEventsHarness(t, "en0")
	reads := countPlatformMetaReads(t)

	before, after := noiseDeltaStates(t, 1)
	h.handle(before, after, false)

	if *reads != 0 {
		t.Fatalf("a noise delta read the platform meta %d times, want 0", *reads)
	}
}

// countPlatformMetaReads counts the platform meta reads of a test. One read
// starts two subprocesses on macOS, so the count is the cost of a delta.
func countPlatformMetaReads(t *testing.T) *int {
	t.Helper()
	reads := 0
	original := platformInterfaceMetaFn
	t.Cleanup(func() { platformInterfaceMetaFn = original })
	platformInterfaceMetaFn = func(string) (class, hardwarePort, service string) {
		reads++
		return "", "", ""
	}
	return &reads
}

// Test_networkEventsNoiseStormEndsWithTheNextTransition covers the last window
// of a storm. The count of the deltas that a real change follows must not wait
// for the next storm.
func Test_networkEventsNoiseStormEndsWithTheNextTransition(t *testing.T) {
	h := newNetworkEventsHarness(t, "en0")
	start := h.now

	for step := 0; step < 4; step++ {
		h.now = start.Add(time.Duration(step) * time.Minute)
		before, after := noiseDeltaStates(t, step)
		h.handle(before, after, false)
	}
	h.now = start.Add(5 * time.Minute)
	before, after := networkEventsAddressChange(t)
	h.handle(before, after, false)

	summaries := h.eventsAtLevel(t, noiseDeltaMessage, "info")
	if len(summaries) != 2 {
		t.Fatalf("got %d journal %q events, want the first delta and the end of the storm", len(summaries), noiseDeltaMessage)
	}
	wantField(t, summaries[1], "count", float64(3))
	wantField(t, summaries[1], "first_at", start.Add(time.Minute).Format(time.RFC3339))
	wantField(t, summaries[1], "last_at", start.Add(3*time.Minute).Format(time.RFC3339))
	wantStringsField(t, summaries[1], "interfaces", "awdl0")
}

// Test_networkEventsStoreTheNetworkBeforeTheHeaderRender proves that the
// callback stores its network under the source lock and renders the header
// after the unlock, so the header read of the hardware ports starts no
// process under the lock.
func Test_networkEventsStoreTheNetworkBeforeTheHeaderRender(t *testing.T) {
	h := newNetworkEventsHarness(t, "en0")
	lockHeld, renders := false, 0
	original := defaultRoutesFn
	t.Cleanup(func() { defaultRoutesFn = original })
	// The header render reads the routes, so this seam runs where the
	// callback renders the header.
	defaultRoutesFn = func() (defaultRoute, defaultRoute) {
		renders++
		if h.prog.networkSourceMu.TryLock() {
			h.prog.networkSourceMu.Unlock()
		} else {
			lockHeld = true
		}
		return defaultRoute{Gateway: "192.0.2.1"}, defaultRoute{}
	}

	before, after := networkEventsAddressChange(t)
	h.handle(before, after, false)

	if renders == 0 {
		t.Fatal("the callback rendered no header")
	}
	if lockHeld {
		t.Fatal("the header render ran under the source lock")
	}
	if h.prog.lastNetworkState.Load() != after {
		t.Fatal("the callback did not store its network")
	}
}

// Test_networkEventsIgnoredTransitionStaysOutOfTheJournal pins the level of an
// ignored delta. Such a delta arrives many times per minute, so it belongs in
// the debug stream and not in the journal.
func Test_networkEventsIgnoredTransitionStaysOutOfTheJournal(t *testing.T) {
	h := newNetworkEventsHarness(t, "en0")
	before := deltaTestState(t, "en0", networkEventsHardwareIface,
		deltaTestInterface{name: "en5", up: true, mtu: 1500, ips: []string{"198.51.100.10/24"}})
	after := deltaTestState(t, "en0", networkEventsHardwareIface,
		deltaTestInterface{name: "en5", up: true, mtu: 1500, ips: []string{"198.51.100.20/24"}})

	h.handle(before, after, false)

	transition := h.transitionEvent(t)
	wantField(t, transition, "outcome", transitionOutcomeIgnored)
	wantField(t, transition, "level", "debug")
	wantNoField(t, transition, "journal")
	if snapshots := jsonLogEvents(t, h.logs, networkSnapshotMessage); len(snapshots) != 0 {
		t.Fatalf("got %d %q events for an ignored delta, want 0", len(snapshots), networkSnapshotMessage)
	}
	if h.ignored != 1 || h.reconciled != 0 {
		t.Fatalf("ignored delta: ignored=%d reconciled=%d, want 1/0", h.ignored, h.reconciled)
	}
}

// Test_networkEventsSupersededTransitionEntersTheJournal pins the level of a
// delta that a newer accepted delta replaced. Support reads it to tell a lost
// reconcile from one that never started.
func Test_networkEventsSupersededTransitionEntersTheJournal(t *testing.T) {
	h := newNetworkEventsHarness(t, "en0")
	h.prog.networkAcceptedGen.Store(5)

	before, after := networkEventsAddressChange(t)
	h.handle(before, after, false)

	transition := h.transitionEvent(t)
	wantField(t, transition, "outcome", "superseded")
	wantField(t, transition, "level", "info")
	wantField(t, transition, "journal", true)
	if h.reconciled != 0 {
		t.Fatalf("a superseded delta reconciled %d times, want 0", h.reconciled)
	}
}

// Test_networkEventsSupersededSnapshotReportsTheOutcome covers the delta whose
// snapshot netmon already replaced. The callback logged nothing at all, so the
// journal showed a silent gap between two deltas.
func Test_networkEventsSupersededSnapshotReportsTheOutcome(t *testing.T) {
	h := newNetworkEventsHarness(t, "en0")
	cache := deltaTestState(t, "en0", networkEventsHardwareIface)
	h.stubNetmonCache(t, cache)
	reads := countPlatformMetaReads(t)
	stale, after := networkEventsAddressChange(t)

	// netmon holds a newer snapshot than the one that this callback carries.
	h.prog.handleNetworkChange(context.Background(), &netmon.ChangeDelta{Monitor: netmon.NewStatic(), Old: stale, New: after}, false)

	transition := h.transitionEvent(t)
	wantField(t, transition, "outcome", "snapshot_superseded")
	wantField(t, transition, "level", "debug")
	wantNoField(t, transition, "journal")
	wantStringsField(t, transition, "changed_interfaces", "en0")
	if events := jsonLogEvents(t, h.logs, interfaceChangedMessage); len(events) != 0 {
		t.Fatalf("got %d %q events for a superseded snapshot, want 0", len(events), interfaceChangedMessage)
	}
	if h.reconciled != 0 || h.ignored != 0 {
		t.Fatalf("superseded snapshot ran the handler: reconciled=%d ignored=%d, want 0/0", h.reconciled, h.ignored)
	}
	if *reads != 0 {
		t.Fatalf("a superseded snapshot read the platform meta %d times, want 0", *reads)
	}
}

// Test_networkEventsLogsTheInterfacesOutsideTheNoiseClass covers a mixed
// delta. An AirDrop change beside a real one must not fill the journal, but
// the transition still names every interface that changed.
func Test_networkEventsLogsTheInterfacesOutsideTheNoiseClass(t *testing.T) {
	h := newNetworkEventsHarness(t, "en0")
	before := deltaTestState(t, "en0", networkEventsHardwareIface,
		deltaTestInterface{name: "awdl0", up: true, mtu: 1484, ips: []string{"fe80::1/64"}})
	after := deltaTestState(t, "en0",
		deltaTestInterface{name: "en0", up: true, mac: "aa:bb:cc:dd:ee:01", mtu: 1500, ips: []string{"192.0.2.20/24"}},
		deltaTestInterface{name: "awdl0", up: true, mtu: 1484, ips: []string{"fe80::2/64"}})

	h.handle(before, after, false)

	events := jsonLogEvents(t, h.logs, interfaceChangedMessage)
	if len(events) != 1 {
		t.Fatalf("got %d %q events, want one for the hardware port", len(events), interfaceChangedMessage)
	}
	wantField(t, events[0], "interface", "en0")
	wantField(t, events[0], "class", "hardware")
	wantStringsField(t, h.transitionEvent(t), "changed_interfaces", "awdl0", "en0")
}

// reorderTestState builds a state with en0 on one address and awdl0 on one
// link-local address, so a test can replay callbacks out of order.
func reorderTestState(en0 string, awdl string) *netmon.State {
	return &netmon.State{
		Interface: map[string]netmon.Interface{
			"en0":   {Interface: &net.Interface{Name: "en0", Flags: net.FlagUp}},
			"awdl0": {Interface: &net.Interface{Name: "awdl0", Flags: net.FlagUp}},
		},
		InterfaceIPs: map[string][]netip.Prefix{
			"en0":   {netip.MustParsePrefix(en0)},
			"awdl0": {netip.MustParsePrefix(awdl)},
		},
		DefaultRouteInterface: "en0",
		HaveV4:                true,
	}
}

// firstV4Of returns the first IPv4 address of one interface of a state.
func firstV4Of(state *netmon.State, name string) net.IP {
	for _, prefix := range state.InterfaceIPs[name] {
		if prefix.Addr().Is4() {
			return net.IP(prefix.Addr().AsSlice())
		}
	}
	return nil
}

// Test_networkEventsSupersededCallbackKeepsTheBaseline replays the callbacks
// out of order: B runs, a late A arrives while the monitor already caches C,
// then C runs. The late A must not become the baseline of C, or the address
// change from B to C looks like AirDrop noise and the stale source stays.
func Test_networkEventsSupersededCallbackKeepsTheBaseline(t *testing.T) {
	h := newNetworkEventsHarness(t, "en0")
	stateA := reorderTestState("192.0.2.20/24", "fe80::1/64")
	stateB := reorderTestState("192.0.2.10/24", "fe80::1/64")
	stateC := reorderTestState("192.0.2.20/24", "fe80::2/64")
	cache := stateB
	oldCurrent := networkChangeCurrentStateFn
	t.Cleanup(func() { networkChangeCurrentStateFn = oldCurrent })
	networkChangeCurrentStateFn = func(*netmon.ChangeDelta) *netmon.State { return cache }
	networkChangeReconcileFn = func(p *prog, _ context.Context, _ uint64) {
		h.reconciled++
		ctrld.SetDefaultLocalIPv4(context.Background(), firstV4Of(p.networkSourceState, "en0"))
	}
	monitor := netmon.NewStatic()

	h.prog.handleNetworkChange(context.Background(), &netmon.ChangeDelta{Monitor: monitor, Old: stateA, New: stateB}, true)
	cache = stateC
	h.prog.handleNetworkChange(context.Background(), &netmon.ChangeDelta{Monitor: monitor, Old: &netmon.State{}, New: stateA}, true)
	h.prog.handleNetworkChange(context.Background(), &netmon.ChangeDelta{Monitor: monitor, Old: stateB, New: stateC}, true)

	if h.reconciled != 2 {
		t.Fatalf("reconciles = %d, want 2: the late callback must not hide the change from B to C", h.reconciled)
	}
	if got := ctrld.GetDefaultLocalIPv4().String(); got != "192.0.2.20" {
		t.Fatalf("resolver source = %s, want 192.0.2.20", got)
	}
}

// orderTestState builds a state for the callback order tests: en0 on one
// address, plus extra interfaces with their addresses and their up flag.
func orderTestState(route, en0 string, extra map[string][]string, down map[string]bool) *netmon.State {
	state := &netmon.State{
		Interface:             map[string]netmon.Interface{},
		InterfaceIPs:          map[string][]netip.Prefix{},
		DefaultRouteInterface: route,
		HaveV4:                true,
	}
	add := func(name string, up bool, ips []string) {
		flags := net.Flags(0)
		if up {
			flags = net.FlagUp
		}
		state.Interface[name] = netmon.Interface{Interface: &net.Interface{Name: name, Flags: flags}}
		for _, ip := range ips {
			state.InterfaceIPs[name] = append(state.InterfaceIPs[name], netip.MustParsePrefix(ip))
		}
	}
	if en0 != "" {
		add("en0", true, []string{en0})
	}
	for name, ips := range extra {
		add(name, !down[name], ips)
	}
	return state
}

// Test_networkEventsMajorAfterItsMinorKeepsItsChanges runs a minor callback
// of the new epoch before the major callback that opened the epoch. netmon
// starts one goroutine per callback, so this order happens. The major must
// still report the address change and reconcile.
func Test_networkEventsMajorAfterItsMinorKeepsItsChanges(t *testing.T) {
	for _, order := range []string{"in_order", "minor_first", "minor_first_time_jumped"} {
		t.Run(order, func(t *testing.T) {
			h := newNetworkEventsHarness(t, "en0")
			hostWokeTestHold(h.prog)
			s0 := orderTestState("en0", "192.0.2.10/24", map[string][]string{"awdl0": {"fe80::1/64"}}, nil)
			s2 := orderTestState("en0", "192.0.2.20/24", map[string][]string{"awdl0": {"fe80::1/64"}}, nil)
			s3 := orderTestState("en0", "192.0.2.20/24", map[string][]string{"awdl0": {"fe80::2/64"}}, nil)
			h.stubNetmonCache(t, s2)
			monitor := netmon.NewStatic()
			major := &netmon.ChangeDelta{Monitor: monitor, Old: s0, New: s2, TimeJumped: order == "minor_first_time_jumped"}
			minor := &netmon.ChangeDelta{Monitor: monitor, Old: s2, New: s3}
			if order == "in_order" {
				h.prog.handleNetworkChange(context.Background(), major, true)
				h.prog.handleNetworkChange(context.Background(), minor, false)
			} else {
				h.prog.handleNetworkChange(context.Background(), minor, false)
				h.prog.handleNetworkChange(context.Background(), major, true)
			}

			if h.reconciled != 1 {
				t.Fatalf("reconciled = %d, want 1 for the move of en0 from .10 to .20", h.reconciled)
			}
			if got := h.interfaceEventsFor(t, "en0"); got != 1 {
				t.Fatalf("en0 interface events = %d, want 1", got)
			}
			if h.prog.networkDeltaState != s3 {
				t.Fatal("the baseline must stay at the newest state of the epoch")
			}
		})
	}
}

// Test_networkEventsEpochChangeReportsAMinorChangeOnce closes an epoch with a
// major callback whose Old is the cache of the epoch. The interface that a
// minor callback of that epoch reported must not appear again.
func Test_networkEventsEpochChangeReportsAMinorChangeOnce(t *testing.T) {
	h := newNetworkEventsHarness(t, "en0")
	s0 := orderTestState("en0", "192.0.2.10/24", nil, nil)
	s1 := orderTestState("en0", "192.0.2.10/24", map[string][]string{"ipsec0": {"10.0.0.2/32"}}, nil)
	s2 := orderTestState("en0", "192.0.2.20/24", map[string][]string{"ipsec0": {"10.0.0.2/32"}}, nil)
	cache := s0
	oldCurrent, oldRead := networkChangeCurrentStateFn, readNetworkSourceStateFn
	t.Cleanup(func() { networkChangeCurrentStateFn, readNetworkSourceStateFn = oldCurrent, oldRead })
	networkChangeCurrentStateFn = func(*netmon.ChangeDelta) *netmon.State { return cache }
	readNetworkSourceStateFn = func() (*netmon.State, error) { return cache, nil }
	monitor := netmon.NewStatic()

	h.prog.handleNetworkChange(context.Background(), &netmon.ChangeDelta{Monitor: monitor, Old: s0, New: s1}, false)
	cache = s2
	h.prog.handleNetworkChange(context.Background(), &netmon.ChangeDelta{Monitor: monitor, Old: s0, New: s2}, true)

	if got := h.interfaceEventsFor(t, "ipsec0"); got != 1 {
		t.Fatalf("ipsec0 interface events = %d, want 1", got)
	}
	if got := h.interfaceEventsFor(t, "en0"); got != 1 {
		t.Fatalf("en0 interface events = %d, want 1", got)
	}
}

// Test_networkEventsNewValidInterfaceReconciles plugs a valid interface in
// with its address in one delta while the other valid interface is down. The
// new interface is active, so the change must reconcile.
func Test_networkEventsNewValidInterfaceReconciles(t *testing.T) {
	h := newNetworkEventsHarness(t, "en0", "en7")
	before := orderTestState("", "", map[string][]string{"en0": nil}, map[string]bool{"en0": true})
	before.HaveV4 = false
	after := orderTestState("en7", "", map[string][]string{"en0": nil, "en7": {"192.0.2.30/24"}}, map[string]bool{"en0": true})

	h.handle(before, after, false)

	if h.reconciled != 1 {
		event := h.transitionEvent(t)
		t.Fatalf("reconciled = %d, want 1; outcome %v", h.reconciled, event["outcome"])
	}
}
