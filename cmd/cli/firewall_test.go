package cli

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
	"github.com/Control-D-Inc/ctrld/internal/firewall"
)

func TestExtractHostFromEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     string
	}{
		{name: "https URL", endpoint: "https://dns.controld.com/abcdef", want: "dns.controld.com"},
		{name: "URL with userinfo", endpoint: "https://user:pass@dns.controld.com/abcdef", want: "dns.controld.com"},
		{name: "URL with IPv6 literal", endpoint: "https://[2606:4700:4700::1111]:443/dns-query", want: "2606:4700:4700::1111"},
		{name: "host port", endpoint: "1.2.3.4:53", want: "1.2.3.4"},
		{name: "bare IP", endpoint: "1.2.3.4", want: "1.2.3.4"},
		{name: "DNS stamp", endpoint: "sdns://AgcAAAAAAAAAAA", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractHostFromEndpoint(tt.endpoint); got != tt.want {
				t.Fatalf("extractHostFromEndpoint(%q) = %q, want %q", tt.endpoint, got, tt.want)
			}
		})
	}
}

func TestParseAllowedDestinations(t *testing.T) {
	tests := []struct {
		name         string
		entries      []string
		want         []string
		wantRejected []string
		wantWide     []string
	}{
		{
			name:    "bare IPv4 becomes a host prefix",
			entries: []string{"203.0.113.10"},
			want:    []string{"203.0.113.10/32"},
		},
		{
			name:    "bare IPv6 becomes a host prefix",
			entries: []string{"2606:1a40::1"},
			want:    []string{"2606:1a40::1/128"},
		},
		{
			name:    "CIDRs of both families",
			entries: []string{"198.51.100.0/24", "2001:db8::/48"},
			want:    []string{"198.51.100.0/24", "2001:db8::/48"},
		},
		{
			name:    "IPv4-in-IPv6 is unmapped to its IPv4 form",
			entries: []string{"::ffff:203.0.113.10", "::ffff:198.51.100.0/120"},
			want:    []string{"203.0.113.10/32", "198.51.100.0/24"},
		},
		{
			name:    "surrounding whitespace is tolerated",
			entries: []string{"  203.0.113.10  ", "\t198.51.100.0/24"},
			want:    []string{"203.0.113.10/32", "198.51.100.0/24"},
		},
		{
			name:    "empty entries are skipped without being reported",
			entries: []string{"", "   ", "203.0.113.10"},
			want:    []string{"203.0.113.10/32"},
		},
		{
			name:         "one bad entry does not void the rest",
			entries:      []string{"203.0.113.10", "not-an-ip", "198.51.100.0/33", "example.com"},
			want:         []string{"203.0.113.10/32"},
			wantRejected: []string{"not-an-ip", "198.51.100.0/33", "example.com"},
		},
		{
			name:    "no entries",
			entries: nil,
		},
		{
			// A full-range prefix is accepted - the organization is entitled to one -
			// but it lets every destination of that family bypass Firewall Mode, so it
			// has to be reported rather than disappearing into a count.
			name: "full-range prefixes are reported as wide",
			// Masking happens in normalizeExceptions, so the parsed form is still
			// the entry as sent; the mask is what makes it a full range.
			entries:  []string{"1.2.3.4/0", "::/0", "203.0.113.10"},
			want:     []string{"1.2.3.4/0", "::/0", "203.0.113.10/32"},
			wantWide: []string{"1.2.3.4/0", "::/0"},
		},
		{
			// unmapPrefix turns this into 0.0.0.0/0, which the raw entry does not look
			// like at all.
			name:     "an IPv4-mapped full range is reported after unmapping",
			entries:  []string{"::ffff:0:0/96"},
			want:     []string{"0.0.0.0/0"},
			wantWide: []string{"0.0.0.0/0"},
		},
		{
			// /8 and /32 are the floors themselves: a whole classical IPv4 network
			// and a whole IPv6 RIR allocation are wide, but both are things an
			// organization can legitimately mean, so neither is reported.
			name:    "prefixes at the floor are not reported as wide",
			entries: []string{"198.51.100.0/24", "10.0.0.0/8", "2001:db8::/48", "2001:db8::/32"},
			want:    []string{"198.51.100.0/24", "10.0.0.0/8", "2001:db8::/48", "2001:db8::/32"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefixes, rejected, wide := parseAllowedDestinations(tt.entries)
			if got := strings.Join(prefixStrings(prefixes), ","); got != strings.Join(tt.want, ",") {
				t.Errorf("prefixes = %q, want %q", got, strings.Join(tt.want, ","))
			}
			if got := strings.Join(rejected, ","); got != strings.Join(tt.wantRejected, ",") {
				t.Errorf("rejected = %q, want %q", got, strings.Join(tt.wantRejected, ","))
			}
			if got := strings.Join(prefixStrings(wide), ","); got != strings.Join(tt.wantWide, ",") {
				t.Errorf("wide = %q, want %q", got, strings.Join(tt.wantWide, ","))
			}
		})
	}
}

// progWithAllowList builds a prog with Firewall Mode's allowlist in place and a
// logger attached, so the allowed-destination paths can be exercised without any
// platform enforcement.
func progWithAllowList() *prog {
	p := &prog{allowList: firewall.New()}
	p.logger.Store(discardLogger())
	return p
}

// discardLogger returns a logger that writes nowhere.
//
// Firewall Mode's paths start background workers that log as soon as they run,
// concurrently with the test goroutine. The package-wide test logger writes into
// a shared strings.Builder (see TestMain) that is neither safe for concurrent
// writes nor for a write racing another test's read of it, so tests that spawn
// those workers must not share it.
func discardLogger() *ctrld.Logger {
	return &ctrld.Logger{Logger: zap.NewNop()}
}

// mirrorCall records one attempt to change platform enforcement: a delta, or a
// full replace (replace is true, and added carries the whole desired set).
type mirrorCall struct {
	added   []string
	removed []string
	replace bool
}

// stubMirror replaces both platform mirrors for the duration of a test,
// recording every change they are handed and failing while *failing is true. The
// recorded calls are what proves a rejected change is retried rather than
// forgotten.
func stubMirror(t *testing.T, calls *[]mirrorCall, failing *bool) {
	t.Helper()
	origMirror, origReplace := firewallMirrorExceptionsFn, firewallReplaceExceptionsFn
	t.Cleanup(func() {
		firewallMirrorExceptionsFn, firewallReplaceExceptionsFn = origMirror, origReplace
	})
	firewallMirrorExceptionsFn = func(_ *prog, added, removed []netip.Prefix) error {
		*calls = append(*calls, mirrorCall{added: prefixStrings(added), removed: prefixStrings(removed)})
		if *failing {
			return errors.New("platform enforcement rejected the change")
		}
		return nil
	}
	firewallReplaceExceptionsFn = func(_ *prog, desired []netip.Prefix) error {
		*calls = append(*calls, mirrorCall{added: prefixStrings(desired), replace: true})
		if *failing {
			return errors.New("platform enforcement rejected the replacement")
		}
		return nil
	}
}

func (c mirrorCall) String() string {
	kind := "delta"
	if c.replace {
		kind = "replace"
	}
	return kind + " added=" + strings.Join(c.added, ",") + " removed=" + strings.Join(c.removed, ",")
}

// TestAllowedDestinationsRetriedAfterMirrorFailure is the regression guard for
// committing a change in memory that platform enforcement refused: an addition
// that pf/WFP rejected must be retried by the next refresh, even though that
// refresh carries an identical list from the API and so produces no new delta.
// Without a separate applied snapshot, the destination would stay blocked with
// the logs claiming it was applied.
func TestAllowedDestinationsRetriedAfterMirrorFailure(t *testing.T) {
	p := progWithAllowList()
	var calls []mirrorCall
	failing := true
	stubMirror(t, &calls, &failing)

	p.rc = &controld.ResolverConfig{DestinationIPs: []string{"203.0.113.10"}}
	p.syncAllowedDestinations()
	if len(calls) != 1 || strings.Join(calls[0].added, ",") != "203.0.113.10/32" {
		t.Fatalf("first refresh: calls = %v", calls)
	}

	// An identical refresh must retry the rejected addition.
	p.syncAllowedDestinations()
	if len(calls) != 2 {
		t.Fatalf("identical refresh after a failure did not retry: calls = %v", calls)
	}
	if strings.Join(calls[1].added, ",") != "203.0.113.10/32" {
		t.Fatalf("retry carried the wrong delta: %v", calls[1])
	}
	if got := p.pendingDestinations(p.allowList); got != 1 {
		t.Fatalf("pendingDestinations = %d, want 1 while the mirror is failing", got)
	}

	// Once the platform accepts it, the change stops being retried.
	failing = false
	p.syncAllowedDestinations()
	if len(calls) != 3 {
		t.Fatalf("recovery refresh did not reach the mirror: calls = %v", calls)
	}
	p.syncAllowedDestinations()
	if len(calls) != 3 {
		t.Fatalf("an applied set was mirrored again: calls = %v", calls)
	}
	if got := p.pendingDestinations(p.allowList); got != 0 {
		t.Fatalf("pendingDestinations = %d, want 0 after a successful mirror", got)
	}
}

// TestAllowedDestinationRemovalRetriedAfterMirrorFailure is the same guarantee
// for the direction that matters more: a withdrawn destination whose removal the
// platform rejected must keep being retried, or it stays permitted for good.
func TestAllowedDestinationRemovalRetriedAfterMirrorFailure(t *testing.T) {
	p := progWithAllowList()
	var calls []mirrorCall
	failing := false
	stubMirror(t, &calls, &failing)

	p.rc = &controld.ResolverConfig{DestinationIPs: []string{"203.0.113.10", "198.51.100.0/24"}}
	p.syncAllowedDestinations()
	if len(calls) != 1 {
		t.Fatalf("initial apply: calls = %v", calls)
	}

	// The organization withdraws one entry and the removal is rejected.
	failing = true
	p.rc = &controld.ResolverConfig{DestinationIPs: []string{"203.0.113.10"}}
	p.syncAllowedDestinations()
	if len(calls) != 2 || strings.Join(calls[1].removed, ",") != "198.51.100.0/24" {
		t.Fatalf("withdrawal: calls = %v", calls)
	}

	// The next refresh sends the same (already reduced) list; the removal must
	// still be retried rather than treated as done.
	p.syncAllowedDestinations()
	if len(calls) != 3 || strings.Join(calls[2].removed, ",") != "198.51.100.0/24" {
		t.Fatalf("identical refresh after a failed removal: calls = %v", calls)
	}

	failing = false
	p.syncAllowedDestinations()
	p.syncAllowedDestinations()
	if len(calls) != 4 {
		t.Fatalf("removal kept being retried after it succeeded: calls = %v", calls)
	}
	if got := p.pendingDestinations(p.allowList); got != 0 {
		t.Fatalf("pendingDestinations = %d, want 0", got)
	}
}

// TestResyncRetriedUntilPlatformAcceptsIt covers enforcement starting over state
// ctrld cannot describe - most importantly a macOS persist pf table that outlived
// the previous run. The whole set is replaced rather than added, and a replace
// the platform rejected must be retried: otherwise a destination the organization
// withdrew while ctrld was stopped stays in that table forever, with nothing
// pending to reveal it.
func TestResyncRetriedUntilPlatformAcceptsIt(t *testing.T) {
	p := progWithAllowList()
	var calls []mirrorCall
	failing := true
	stubMirror(t, &calls, &failing)

	p.rc = &controld.ResolverConfig{DestinationIPs: []string{"203.0.113.10"}}
	p.markDestinationsForResync()
	p.syncAllowedDestinations()

	if len(calls) != 1 || !calls[0].replace {
		t.Fatalf("a resync must replace the whole set, not apply a delta: calls = %v", calls)
	}
	if got := p.pendingDestinations(p.allowList); got == 0 {
		t.Fatal("a rejected replace was reported as nothing pending")
	}

	// Retried, still as a replace: until it succeeds nothing about what the
	// platform holds is known, so a delta would leave stale entries behind.
	p.reconcileAllowedDestinations()
	if len(calls) != 2 || !calls[1].replace {
		t.Fatalf("rejected replace was not retried: calls = %v", calls)
	}

	failing = false
	p.reconcileAllowedDestinations()
	if len(calls) != 3 || !calls[2].replace {
		t.Fatalf("recovery did not replace the set: calls = %v", calls)
	}
	if got := p.pendingDestinations(p.allowList); got != 0 {
		t.Fatalf("pendingDestinations = %d after a successful replace, want 0", got)
	}

	// Once the platform is known-good, later changes go back to deltas.
	p.rc = &controld.ResolverConfig{DestinationIPs: []string{"203.0.113.10", "198.51.100.0/24"}}
	p.syncAllowedDestinations()
	if len(calls) != 4 || calls[3].replace {
		t.Fatalf("a later change should be a delta: calls = %v", calls)
	}
}

// TestResyncWithEmptyListRetriedUntilAccepted is the same guarantee for an
// organization with no entries at all: the platform still owes ctrld a flush of
// whatever it inherited, so an empty desired set is not "nothing to do".
func TestResyncWithEmptyListRetriedUntilAccepted(t *testing.T) {
	p := progWithAllowList()
	var calls []mirrorCall
	failing := true
	stubMirror(t, &calls, &failing)

	p.rc = &controld.ResolverConfig{}
	p.markDestinationsForResync()
	p.syncAllowedDestinations()

	if len(calls) != 1 || !calls[0].replace || len(calls[0].added) != 0 {
		t.Fatalf("empty list did not ask the platform to empty itself: calls = %v", calls)
	}
	if got := p.pendingDestinations(p.allowList); got == 0 {
		t.Fatal("a rejected flush of an empty set was reported as nothing pending")
	}

	p.reconcileAllowedDestinations()
	if len(calls) != 2 {
		t.Fatalf("rejected flush was not retried: calls = %v", calls)
	}

	failing = false
	p.reconcileAllowedDestinations()
	if got := p.pendingDestinations(p.allowList); got != 0 {
		t.Fatalf("pendingDestinations = %d after the flush succeeded, want 0", got)
	}
}

// TestRetiredGenerationDoesNotTouchEnforcement pins the teardown boundary: a
// maintenance worker holds the allowlist and generation of the run that started
// it, and once that generation is over - Firewall Mode turned off, or a reload -
// it must not mirror anything, or it would reinstall permits into enforcement
// that is being removed or now belongs to another run.
func TestRetiredGenerationDoesNotTouchEnforcement(t *testing.T) {
	p := progWithAllowList()
	var calls []mirrorCall
	failing := false
	stubMirror(t, &calls, &failing)

	gen := p.startFirewallGeneration()
	p.rc = &controld.ResolverConfig{DestinationIPs: []string{"203.0.113.10"}}
	p.syncAllowedDestinations()
	if len(calls) != 1 {
		t.Fatalf("initial apply: calls = %v", calls)
	}

	// Firewall Mode goes off: the generation ends and the applied set is dropped,
	// which is exactly the state that used to make a stale worker reinstall.
	stale := p.allowList
	p.retireFirewallDestinations()
	p.allowList = nil

	p.reconcileDestinations(stale, gen)
	if len(calls) != 1 {
		t.Fatalf("a retired generation reached platform enforcement: calls = %v", calls)
	}

	// A new generation may act again.
	p.allowList = stale
	newGen := p.startFirewallGeneration()
	p.reconcileDestinations(stale, newGen)
	if len(calls) != 2 {
		t.Fatalf("the current generation was blocked: calls = %v", calls)
	}
}

// TestSyncAllowedDestinationsFollowsResolverConfig covers what a configuration
// refresh has to deliver: a destination added to the organization's list becomes
// reachable without ctrld having resolved it, and one removed from the list stops
// being reachable on the next refresh.
func TestSyncAllowedDestinationsFollowsResolverConfig(t *testing.T) {
	p := progWithAllowList()
	direct := netip.MustParseAddr("203.0.113.10")
	inRange := netip.MustParseAddr("198.51.100.7")

	// Refresh before the organization has any entries.
	p.rc = &controld.ResolverConfig{}
	p.syncAllowedDestinations()
	if p.allowList.Contains(direct) {
		t.Fatalf("%s allowed with an empty organization list", direct)
	}

	// The organization adds an address and a CIDR.
	p.rc = &controld.ResolverConfig{DestinationIPs: []string{"203.0.113.10", "198.51.100.0/24"}}
	p.syncAllowedDestinations()
	if !p.allowList.Contains(direct) || !p.allowList.Contains(inRange) {
		t.Fatalf("allowed destinations not reachable: %s=%v %s=%v",
			direct, p.allowList.Contains(direct), inRange, p.allowList.Contains(inRange))
	}

	// The organization removes the CIDR; the remaining entry is untouched.
	p.rc = &controld.ResolverConfig{DestinationIPs: []string{"203.0.113.10"}}
	p.syncAllowedDestinations()
	if p.allowList.Contains(inRange) {
		t.Fatalf("%s still allowed after its entry was removed", inRange)
	}
	if !p.allowList.Contains(direct) {
		t.Fatalf("%s should still be allowed", direct)
	}

	// The organization clears the list entirely.
	p.rc = &controld.ResolverConfig{}
	p.syncAllowedDestinations()
	if p.allowList.Contains(direct) {
		t.Fatalf("%s still allowed after the list was cleared", direct)
	}
}

// TestApplyAllowedDestinationsFirewallModeOff pins that devices with Firewall
// Mode disabled are unaffected: there is no allowlist to apply the list to, and
// the refresh path must not panic on the nil one.
func TestApplyAllowedDestinationsFirewallModeOff(t *testing.T) {
	p := &prog{rc: &controld.ResolverConfig{DestinationIPs: []string{"203.0.113.10"}}}
	p.logger.Store(discardLogger())
	p.syncAllowedDestinations()
	if p.allowList != nil {
		t.Fatal("applying allowed destinations created an allowlist while firewall mode is off")
	}
}

// TestSyncFirewallModeAppliesAllowedDestinations covers the startup and reload
// path: turning Firewall Mode on builds a fresh allowlist, which must be seeded
// with the organization's list from the resolver config the run started with -
// otherwise the destinations stay blocked until the next hourly refresh.
func TestSyncFirewallModeAppliesAllowedDestinations(t *testing.T) {
	p := &prog{cfg: &ctrld.Config{}}
	p.cfg.Service.FirewallMode = "on"
	p.logger.Store(discardLogger())
	p.rc = &controld.ResolverConfig{DestinationIPs: []string{"203.0.113.10"}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p.syncFirewallMode(ctx)
	if p.allowList == nil {
		t.Fatal("firewall mode on did not create an allowlist")
	}
	if !p.allowList.Contains(netip.MustParseAddr("203.0.113.10")) {
		t.Fatal("allowed destination not applied when firewall mode came up")
	}

	// Turning the mode off drops the set with the allowlist, and forgets what
	// enforcement was holding so a later re-enable reinstalls everything.
	p.cfg.Service.FirewallMode = "off"
	p.syncFirewallMode(ctx)
	if p.allowList != nil {
		t.Fatal("firewall mode off did not clear the allowlist")
	}
	if got := p.pendingDestinations(p.allowList); got != 0 {
		t.Fatalf("pendingDestinations = %d with firewall mode off, want 0", got)
	}

	p.cfg.Service.FirewallMode = "on"
	p.syncFirewallMode(ctx)
	if !p.allowList.Contains(netip.MustParseAddr("203.0.113.10")) {
		t.Fatal("allowed destination not re-applied after firewall mode was turned back on")
	}
}

// TestAllowedDestinationsSurviveConcurrentReload drives the interleaving the race
// detector caught: apiConfigReload applies the organization's destinations on the
// refresh goroutine while a config reload replaces - or clears - the allowlist on
// another.
//
// The apply path used to read p.allowList twice, once to check it for nil and
// again to call SetExceptions on it, with a parse in between. A reload that
// turned Firewall Mode off inside that gap left the second read nil, and ctrld
// panicked on a refresh that had nothing wrong with it.
func TestAllowedDestinationsSurviveConcurrentReload(t *testing.T) {
	origMirror, origReplace := firewallMirrorExceptionsFn, firewallReplaceExceptionsFn
	t.Cleanup(func() {
		firewallMirrorExceptionsFn, firewallReplaceExceptionsFn = origMirror, origReplace
	})
	firewallMirrorExceptionsFn = func(*prog, []netip.Prefix, []netip.Prefix) error { return nil }
	firewallReplaceExceptionsFn = func(*prog, []netip.Prefix) error { return nil }

	p := &prog{cfg: &ctrld.Config{}}
	p.logger.Store(discardLogger())
	p.rc = &controld.ResolverConfig{DestinationIPs: []string{"203.0.113.10", "198.51.100.0/24"}}
	p.cfg.Service.FirewallMode = "on"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.syncFirewallMode(ctx)

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			p.syncAllowedDestinations()
		}
	}()

	// Firewall Mode off then on is what clears p.allowList and installs a fresh
	// one, which is the whole of the reload path this refresh can collide with.
	for range 20 {
		p.cfg.Service.FirewallMode = "off"
		p.syncFirewallMode(ctx)
		p.cfg.Service.FirewallMode = "on"
		p.syncFirewallMode(ctx)
	}
	close(stop)
	<-done

	// The churn must not have cost the set: the run that is live at the end owes
	// the platform exactly what the API last sent.
	p.syncAllowedDestinations()
	p.destinationsMu.Lock()
	applied := prefixStrings(p.appliedDestinations)
	p.destinationsMu.Unlock()
	if got := strings.Join(applied, ","); got != "198.51.100.0/24,203.0.113.10/32" {
		t.Errorf("applied destinations = %q, want the full set after the reload churn", got)
	}
}

// TestAllowedDestinationLogsKeepAddressesOutOfWarnings holds the whole
// allowed-destination path to one policy: Warn and Info carry counts, addresses
// appear only at Debug.
//
// Warn logs are persisted and travel in support bundles exactly like Info ones,
// and both a rejected entry and an accepted one are an organization's network
// topology - "10.0.0.0/33" names a real network as surely as the entry next to
// it. logDestinationChange already followed this rule; the rejection and
// wide-prefix warnings are the paths that can leak around it.
func TestAllowedDestinationLogsKeepAddressesOutOfWarnings(t *testing.T) {
	var calls []mirrorCall
	failing := false
	stubMirror(t, &calls, &failing)

	core, logs := observer.New(zapcore.DebugLevel)
	p := progWithAllowList()
	p.logger.Store(&ctrld.Logger{Logger: zap.New(core)})

	const (
		bad     = "10.0.0.0/33"     // near-miss topology: a real network, a bad mask
		wide    = "0.0.0.0/0"       // accepted, and blankets the whole family
		ordinal = "203.0.113.10/32" // an ordinary accepted entry
	)
	p.rc = &controld.ResolverConfig{DestinationIPs: []string{bad, wide, "203.0.113.10"}}
	p.syncAllowedDestinations()

	var warned, wideWarned bool
	for _, entry := range logs.FilterLevelExact(zapcore.WarnLevel).All() {
		line := entry.Message + fmt.Sprint(entry.ContextMap())
		for _, addr := range []string{bad, wide, ordinal, "203.0.113.10"} {
			if strings.Contains(line, addr) {
				t.Errorf("a Warn line carries the address %q, which support bundles then carry too:\n  %s", addr, line)
			}
		}
		if strings.Contains(entry.Message, "not a valid IP address or CIDR") {
			warned = true
			if got := entry.ContextMap()["rejected"]; got != int64(1) {
				t.Errorf("rejected count = %v, want 1", got)
			}
		}
		if strings.Contains(entry.Message, "very wide range") {
			wideWarned = true
			if got := entry.ContextMap()["bits"]; got != int64(0) {
				t.Errorf("wide prefix bits = %v, want 0 for a full range", got)
			}
		}
	}
	if !warned {
		t.Error("an unusable entry was dropped without any warning")
	}
	if !wideWarned {
		t.Error("a full-range destination was accepted without any warning; the bypass would be invisible")
	}

	// The values are still recoverable by whoever turns Debug on to look.
	var debugged string
	for _, entry := range logs.FilterLevelExact(zapcore.DebugLevel).All() {
		debugged += entry.Message + fmt.Sprint(entry.ContextMap())
	}
	if !strings.Contains(debugged, bad) {
		t.Errorf("the rejected entry %q appears in no Debug line, so nothing can diagnose it", bad)
	}
	if !strings.Contains(debugged, wide) {
		t.Errorf("the wide entry %q appears in no Debug line", wide)
	}
}

// TestFirewallPermanentAllowListPermitsControlDEndpoints is the regression guard
// for the Windows lockout described on controld.APIEndpointIPs.
//
// Firewall Mode learns destinations from queries ctrld's own listener answered.
// The addresses asserted here are the ones each endpoint falls back to when DNS
// does not work at all - which is the state a ctrld blocked by its own filters is
// in - so they are exactly the ones no lookup can ever teach it.
func TestFirewallPermanentAllowListPermitsControlDEndpoints(t *testing.T) {
	for _, dev := range []bool{false, true} {
		t.Run(map[bool]string{false: "prod", true: "dev"}[dev], func(t *testing.T) {
			origDev := cdDev
			cdDev = dev
			t.Cleanup(func() { cdDev = origDev })

			al := firewall.New()
			p := &prog{cfg: &ctrld.Config{}}
			p.logger.Store(mainLog.Load())
			p.initFirewallAllowList(context.Background(), al)

			apiIPs := controld.APIEndpointIPs(dev)
			if len(apiIPs) == 0 {
				t.Fatal("no ControlD API addresses to permit")
			}

			endpoints := map[string][]string{
				// The API transport's direct addresses.
				"API": apiIPs,
				// The upgrade download server's fallback. performUpgrade runs the
				// download in a detached child process, and WFP's block-all filters
				// carry no process condition, so the service blocks its own upgrade.
				"download server": {downloadServerIp},
			}
			for what, ips := range endpoints {
				for _, ipStr := range ips {
					ip, err := netip.ParseAddr(ipStr)
					if err != nil {
						t.Fatalf("the %s address %q does not parse: %v", what, ipStr, err)
					}
					if !al.Contains(ip) {
						t.Errorf("the ControlD %s address %s is not permitted; Firewall Mode would block ctrld's own socket to it", what, ip)
					}
				}
			}
		})
	}
}
