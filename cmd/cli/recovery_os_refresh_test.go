package cli

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/Control-D-Inc/ctrld"
)

// standardRecoveryHarness runs handleRecovery in Standard mode with the DNS
// reset and the system nameserver reads stubbed, and records their order.
type standardRecoveryHarness struct {
	*recoveryEventHarness
	mu     sync.Mutex
	events []string
}

func (h *standardRecoveryHarness) record(event string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.events = append(h.events, event)
}

func (h *standardRecoveryHarness) snapshot() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string{}, h.events...)
}

func (h *standardRecoveryHarness) reads() int {
	n := 0
	for _, e := range h.snapshot() {
		if e == "read" {
			n++
		}
	}
	return n
}

func newStandardRecoveryHarness(t *testing.T) *standardRecoveryHarness {
	t.Helper()
	h := &standardRecoveryHarness{recoveryEventHarness: newRecoveryEventHarness(t)}
	dnsIntercept = false // restored by the event harness
	oldReset, oldSet, oldRead, oldIntervals := recoveryResetDNSFn, recoverySetDNSFn, initializeOsResolver, osResolverRecoveryRefreshIntervals
	t.Cleanup(func() {
		recoveryResetDNSFn, recoverySetDNSFn, initializeOsResolver, osResolverRecoveryRefreshIntervals = oldReset, oldSet, oldRead, oldIntervals
	})
	recoveryResetDNSFn = func(*prog, bool, bool) { h.record("reset") }
	recoverySetDNSFn = func(*prog, []string) { h.record("setDNS") }
	initializeOsResolver = func(bool, string) []string {
		h.record("read")
		return []string{"[fd66:6:6::1]:53", "76.76.2.0:53"}
	}
	osResolverRecoveryRefreshIntervals = []time.Duration{refreshTestInterval}
	return h
}

const refreshTestInterval = 5 * time.Millisecond

// errUpstreamStillDown ends a test recovery before it re-applies DNS settings,
// so the test never touches the host's DNS configuration.
var errUpstreamStillDown = errors.New("upstream still down")

// After a network change, Standard mode removes its DNS settings to expose the
// new network's resolvers. It must read them right away and keep reading them
// while it waits: an IPv6-only network publishes its resolver by RDNSS, and an
// IPv4-only upstream there only comes back once macOS starts its CLAT, which
// needs ctrld's OS-resolver fallback to reach that resolver (#628).
func TestNetworkChangeRecoveryRefreshesOSResolver(t *testing.T) {
	h := newStandardRecoveryHarness(t)
	var readsAtWaitStart int
	waitForUpstreamRecoveryFn = func(_ *prog, ctx context.Context, _ map[string]*ctrld.UpstreamConfig, _ *recoveryDiagnostic) (string, error) {
		readsAtWaitStart = h.reads()
		deadline := time.Now().Add(2 * time.Second)
		for h.reads() < readsAtWaitStart+3 {
			if time.Now().After(deadline) {
				return "", errors.New("the resolvers were not re-read during the wait")
			}
			time.Sleep(time.Millisecond)
		}
		return "", errUpstreamStillDown
	}

	h.prog.handleRecovery(RecoveryReasonNetworkChange)

	events := h.snapshot()
	if len(events) < 2 || events[0] != "reset" || events[1] != "read" {
		t.Fatalf("events = %v, want the DNS reset followed by a resolver read", events)
	}
	if readsAtWaitStart != 1 {
		t.Fatalf("resolver reads before the wait = %d, want 1", readsAtWaitStart)
	}
	if got := h.reads(); got < readsAtWaitStart+3 {
		t.Fatalf("resolver reads during the wait = %d, want at least 3", got-readsAtWaitStart)
	}

	// The refresh ends with the wait.
	after := h.reads()
	time.Sleep(10 * refreshTestInterval)
	if got := h.reads(); got != after {
		t.Fatalf("resolver reads went on after the wait: %d -> %d", after, got)
	}
}

// A recovery for an upstream failure keeps the network it is on, so it does
// not re-read the resolvers, as before.
func TestUpstreamFailureRecoveryKeepsOSResolver(t *testing.T) {
	h := newStandardRecoveryHarness(t)
	waitForUpstreamRecoveryFn = func(_ *prog, _ context.Context, _ map[string]*ctrld.UpstreamConfig, _ *recoveryDiagnostic) (string, error) {
		time.Sleep(10 * refreshTestInterval)
		return "", errUpstreamStillDown
	}

	h.prog.handleRecovery(RecoveryReasonRegularFailure)

	if got := h.reads(); got != 0 {
		t.Fatalf("resolver reads = %d (events %v), want none", got, h.snapshot())
	}
}

// Once an upstream answers, the refresher stops before the completion re-reads
// the resolvers and re-applies the DNS settings, so no read races the restore.
func TestNetworkChangeRecoveryStopsRefreshBeforeCompletion(t *testing.T) {
	h := newStandardRecoveryHarness(t)
	waitForUpstreamRecoveryFn = func(_ *prog, _ context.Context, _ map[string]*ctrld.UpstreamConfig, _ *recoveryDiagnostic) (string, error) {
		readsAtWaitStart := h.reads()
		deadline := time.Now().Add(2 * time.Second)
		for h.reads() < readsAtWaitStart+2 {
			if time.Now().After(deadline) {
				return "", errors.New("the resolvers were not re-read during the wait")
			}
			time.Sleep(time.Millisecond)
		}
		h.record("recovered")
		return h.recovered, nil
	}
	// The restore outlasts several refresh gaps, so a refresher still running
	// would read during it.
	recoverySetDNSFn = func(*prog, []string) {
		h.record("setDNS")
		time.Sleep(10 * refreshTestInterval)
	}

	h.prog.handleRecovery(RecoveryReasonNetworkChange)

	events := h.snapshot()
	i := slices.Index(events, "recovered")
	if i < 0 {
		t.Fatalf("events = %v, want the upstream to recover", events)
	}
	if got, want := events[i+1:], []string{"read", "setDNS"}; !slices.Equal(got, want) {
		t.Fatalf("events after the recovery = %v, want %v (all: %v)", got, want, events)
	}
}

// The refresher reads at the configured gaps and repeats the last one, so a
// long outage reads at the last, longest gap rather than at the first.
func TestNetworkChangeRecoveryRefreshBacksOff(t *testing.T) {
	h := newStandardRecoveryHarness(t)
	osResolverRecoveryRefreshIntervals = []time.Duration{refreshTestInterval, time.Hour}
	waitForUpstreamRecoveryFn = func(_ *prog, _ context.Context, _ map[string]*ctrld.UpstreamConfig, _ *recoveryDiagnostic) (string, error) {
		time.Sleep(20 * refreshTestInterval)
		return "", errUpstreamStillDown
	}

	h.prog.handleRecovery(RecoveryReasonNetworkChange)

	// The immediate read after the reset, then one at the first gap.
	if got := h.reads(); got != 2 {
		t.Fatalf("resolver reads = %d (events %v), want 2", got, h.snapshot())
	}
}

// The read after the reset finds the new network's nameservers, so the OS
// resolver no longer counts as read before the network change.
func TestNetworkChangeRecoveryReadClearsStaleOSResolver(t *testing.T) {
	h := newStandardRecoveryHarness(t)
	h.prog.markOSResolverStale()
	var staleAtWait bool
	waitForUpstreamRecoveryFn = func(p *prog, _ context.Context, _ map[string]*ctrld.UpstreamConfig, _ *recoveryDiagnostic) (string, error) {
		staleAtWait = p.osResolverStale()
		return "", errUpstreamStillDown
	}

	h.prog.handleRecovery(RecoveryReasonNetworkChange)

	if staleAtWait {
		t.Fatal("OS resolver still stale after the post-reset read found nameservers")
	}
}
