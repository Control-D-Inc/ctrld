//go:build darwin

package cli

import (
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/firewall"
)

// progWithForwardedSources builds a prog whose config declares the given
// forwarded-workload source subnets. A logger is attached so the invalid-entry
// warning path is safe to exercise.
func progWithForwardedSources(sources ...string) *prog {
	p := &prog{cfg: &ctrld.Config{
		Listener: map[string]*ctrld.ListenerConfig{"0": {IP: "127.0.0.1", Port: 53}},
	}}
	p.cfg.Service.FirewallForwardedSources = sources
	p.logger.Store(mainLog.Load())
	return p
}

// TestIsHypervisorVMNetIface verifies only vendor-specific VM/NAT interfaces
// qualify for auto-detection - never generic bridges (bridge*, which macOS also
// uses for Thunderbolt/aggregated links), physical uplinks, loopback, or VPN tunnels.
func TestIsHypervisorVMNetIface(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"vmnet8", true},     // VMware Fusion
		{"vmenet0", true},    // Apple Virtualization.framework / UTM
		{"vnic0", true},      // Parallels
		{"vboxnet0", true},   // VirtualBox
		{"bridge0", false},   // generic bridge (Thunderbolt/aggregated) - NOT auto-trusted
		{"bridge100", false}, // Multipass/Docker generic bridge - opt-in only
		{"en0", false},       // physical uplink
		{"lo0", false},       // loopback
		{"utun3", false},     // VPN tunnel
		{"awdl0", false},     // Apple Wireless Direct Link
	}
	for _, tt := range tests {
		if got := isHypervisorVMNetIface(tt.name); got != tt.want {
			t.Errorf("isHypervisorVMNetIface(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// TestBuildPFForwardedSourceRulesFor_Basic verifies the rules emit, for each source:
// a route-to-lo0 redirect of the guest's plaintext DNS (udp+tcp) and a DoT block;
// that auto-detected sources are scoped "on <iface>" while configured sources match
// on CIDR alone; and crucially NOT an interface-wide or destination-wide permit that
// would let the guest bypass policy.
func TestBuildPFForwardedSourceRulesFor_Basic(t *testing.T) {
	sources := []forwardedSource{
		{prefix: netip.MustParsePrefix("192.168.105.0/24"), iface: "vmnet8"}, // auto-detected
		{prefix: netip.MustParsePrefix("10.211.55.0/24")},                    // configured (no iface)
	}
	rules := buildPFForwardedSourceRulesFor(sources, "127.0.0.1")

	wants := []string{
		// Auto-detected: scoped to its ingress interface.
		"pass in quick on vmnet8 route-to lo0 inet proto udp from 192.168.105.0/24 to ! 127.0.0.1 port 53",
		"pass in quick on vmnet8 route-to lo0 inet proto tcp from 192.168.105.0/24 to ! 127.0.0.1 port 53",
		"block return in quick on vmnet8 inet proto { tcp, udp } from 192.168.105.0/24 to any port 853",
		// Configured: CIDR-only (admin opt-in), no "on <iface>".
		"pass in quick route-to lo0 inet proto udp from 10.211.55.0/24 to ! 127.0.0.1 port 53",
		"block return in quick inet proto { tcp, udp } from 10.211.55.0/24 to any port 853",
	}
	for _, w := range wants {
		if !strings.Contains(rules, w) {
			t.Errorf("missing rule:\n  %s\nin:\n%s", w, rules)
		}
	}

	// Address family must match the source literal. An "inet6 ... from <IPv4 CIDR>"
	// rule makes pfctl reject the whole anchor, which would take DNS interception
	// down with it, so no inet6 rule may name an IPv4 source.
	for _, line := range strings.Split(rules, "\n") {
		if strings.Contains(line, "inet6") && (strings.Contains(line, "192.168.105.0/24") || strings.Contains(line, "10.211.55.0/24")) {
			t.Errorf("inet6 rule with an IPv4 source - pf address-family mismatch:\n  %s", line)
		}
	}

	// Security boundary: every "pass" for a source must be the port-53 redirect;
	// no rule may grant a source an unrestricted destination.
	for _, line := range strings.Split(rules, "\n") {
		if strings.HasPrefix(line, "pass") && !strings.Contains(line, "port 53") {
			t.Errorf("forwarded-source pass rule is not scoped to DNS - possible policy bypass:\n  %s", line)
		}
		if strings.HasPrefix(line, "pass") && strings.HasSuffix(strings.TrimSpace(line), "to any") {
			t.Errorf("forwarded-source rules must not contain a blanket 'to any' permit:\n  %s", line)
		}
	}
}

// TestBuildPFForwardedSourceRulesFor_Empty verifies that with no sources the
// builder returns "", leaving anchor behavior unchanged.
func TestBuildPFForwardedSourceRulesFor_Empty(t *testing.T) {
	if got := buildPFForwardedSourceRulesFor(nil, "127.0.0.1"); got != "" {
		t.Errorf("expected empty output with no sources, got:\n%s", got)
	}
}

// TestFirewallForwardedSources_InvalidDropped verifies a malformed CIDR and a
// non-IPv4 CIDR are dropped (with a warning) without voiding the valid config
// entries, that host bits are normalized to the network address, and that configured
// sources carry no interface. Rejecting IPv6 at parse time is what keeps the emitted
// rules single-family: a mixed-family rule makes pfctl reject the whole anchor.
func TestFirewallForwardedSources_InvalidDropped(t *testing.T) {
	p := progWithForwardedSources("192.168.64.7/24", "not-a-cidr", "fd00::/64", "10.0.0.0/8")
	got := p.firewallForwardedSources()

	want := map[string]bool{"192.168.64.0/24": true, "10.0.0.0/8": true}
	if len(got) != len(want) {
		t.Fatalf("got %d sources, want %d: %v", len(got), len(want), got)
	}
	for _, src := range got {
		if !want[src.prefix.String()] {
			t.Errorf("unexpected prefix %s (invalid entries should be dropped)", src.prefix)
		}
		if src.iface != "" {
			t.Errorf("configured source %s must have no interface, got %q", src.prefix, src.iface)
		}
		if !src.prefix.Addr().Is4() {
			t.Errorf("non-IPv4 source %s must be dropped (interception is IPv4-only)", src.prefix)
		}
	}
}

// TestBuildPFForwardedSourceRulesFor_SkipsNonIPv4 verifies an IPv6 source produces no
// rules even if one reaches the builder, so a stray entry can never introduce a
// mixed-family rule that pfctl would reject the whole anchor over.
func TestBuildPFForwardedSourceRulesFor_SkipsNonIPv4(t *testing.T) {
	v6 := forwardedSource{prefix: netip.MustParsePrefix("fd00::/64")}
	if got := buildPFForwardedSourceRulesFor([]forwardedSource{v6}, "127.0.0.1"); got != "" {
		t.Errorf("IPv6-only source must produce no rules, got:\n%s", got)
	}

	v4 := forwardedSource{prefix: netip.MustParsePrefix("192.168.64.0/24"), iface: "vmnet8"}
	rules := buildPFForwardedSourceRulesFor([]forwardedSource{v6, v4}, "127.0.0.1")
	if strings.Contains(rules, "fd00::") {
		t.Errorf("IPv6 source must be skipped in a mixed set:\n%s", rules)
	}
	if !strings.Contains(rules, "from 192.168.64.0/24 to ! 127.0.0.1 port 53") {
		t.Errorf("IPv4 source must still produce its rules:\n%s", rules)
	}
	for _, line := range strings.Split(rules, "\n") {
		if strings.HasPrefix(line, "pass") || strings.HasPrefix(line, "block") {
			if strings.Contains(line, "inet6") {
				t.Errorf("no inet6 rule may be emitted for IPv4-only sources:\n  %s", line)
			}
		}
	}
}

// TestPFForwardedSourceRules_Syntax runs the real pf parser over the generated rules.
// This is the check string assertions cannot make: pfctl rejects an ENTIRE ruleset
// over one malformed or mixed-address-family rule, so a bad forwarded-source rule
// would take DNS interception down with it rather than just failing to trust a guest.
//
// Two rulesets are parsed: the forwarded-source rules alone (self-contained, so this
// arm is environment-independent) and the full anchor ctrld would load.
func TestPFForwardedSourceRules_Syntax(t *testing.T) {
	// lo0 as the auto-detected ingress interface: any interface name parses, and lo0
	// is the one guaranteed to exist on every runner.
	sources := []forwardedSource{
		{prefix: netip.MustParsePrefix("192.168.105.0/24"), iface: "lo0"}, // auto-detected, scoped
		{prefix: netip.MustParsePrefix("10.211.55.0/24")},                 // configured, CIDR-only
	}

	t.Run("forwarded rules alone", func(t *testing.T) {
		rules := buildPFForwardedSourceRulesFor(sources, "127.0.0.1")
		if rules == "" {
			t.Fatal("no forwarded-source rules generated")
		}
		pfctlParseCheck(t, rules)
	})

	t.Run("full anchor", func(t *testing.T) {
		p := progWithForwardedSources("192.168.64.0/24", "10.211.55.0/24")
		p.allowList = firewall.New()
		rules := p.buildPFAnchorRules(nil)
		if !strings.Contains(rules, "from 192.168.64.0/24 to ! ") {
			t.Fatalf("forwarded-source rules missing from anchor under test:\n%s", rules)
		}
		pfctlParseCheck(t, stripPFGroupRules(rules))
	})
}

// pfctlParseCheck validates a ruleset with the real pf parser in ctrld's anchor
// context, failing the test on any parse error. pfctl needs /dev/pf, so the check
// skips (rather than fails) where the runner cannot open it.
func pfctlParseCheck(t *testing.T, ruleset string) {
	t.Helper()

	pfctl, err := exec.LookPath("pfctl")
	if err != nil {
		t.Skip("pfctl not available:", err)
	}
	file := filepath.Join(t.TempDir(), "ctrld-rules-test.conf")
	if err := os.WriteFile(file, []byte(ruleset), 0600); err != nil {
		t.Fatalf("write ruleset under test: %v", err)
	}

	// -n parses and validates without loading anything.
	out, err := exec.Command(pfctl, "-a", pfAnchorName, "-n", "-f", file).CombinedOutput()
	if err == nil {
		return
	}
	msg := strings.TrimSpace(string(out))
	if strings.Contains(msg, "Permission denied") || strings.Contains(msg, "Operation not permitted") ||
		strings.Contains(msg, "/dev/pf") {
		t.Skipf("pfctl cannot open /dev/pf on this runner (%v): %s", err, msg)
	}
	t.Errorf("pfctl rejected the generated ruleset (%v):\n%s\n--- ruleset ---\n%s", err, msg, ruleset)
}

// stripPFGroupRules drops rules scoped to ctrld's runtime group. That group is created
// by the installed service (dscl), so on a dev box or CI runner pfctl reports "unknown
// group _ctrld" for them - an environment fact, not a defect in the generated rules.
// Only those lines are removed, so pf's ordering requirement (translation rules before
// filtering rules) still holds for what remains.
func stripPFGroupRules(ruleset string) string {
	lines := strings.Split(ruleset, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "#") && strings.Contains(trimmed, "group "+pfGroupName) {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// TestForwardedSources_UnionDedup verifies the effective set unions auto-detected
// and configured subnets, de-duplicated by prefix. Auto-detection is
// environment-dependent, so this asserts config entries are always included and
// that duplicate config entries collapse to one - deterministic regardless of host.
func TestForwardedSources_UnionDedup(t *testing.T) {
	p := progWithForwardedSources("192.168.199.0/24", "192.168.199.0/24")
	got := p.forwardedSources()

	count := 0
	for _, src := range got {
		if src.prefix.String() == "192.168.199.0/24" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("configured subnet appears %d times, want exactly 1 (union must dedup):\n%v", count, got)
	}
}

// TestForwardedSourceDescriptions verifies the log rendering names each subnet's
// origin, including the interface an auto-detected source is scoped to. Configured
// entries used to be invisible in the log, which left admins unable to confirm
// firewall_forwarded_sources took effect.
func TestForwardedSourceDescriptions(t *testing.T) {
	got := forwardedSourceDescriptions([]forwardedSource{
		{prefix: netip.MustParsePrefix("192.168.105.0/24"), iface: "vmenet0"},
		{prefix: netip.MustParsePrefix("192.168.252.0/24")},
	})
	want := []string{
		"192.168.105.0/24 (auto-detected on vmenet0)",
		"192.168.252.0/24 (configured)",
	}
	if !equalStringSets(got, want) {
		t.Errorf("descriptions = %v, want %v", got, want)
	}

	if got := forwardedSourceDescriptions(nil); len(got) != 0 {
		t.Errorf("empty set must render no descriptions, got %v", got)
	}
}

// TestForwardedSourceSetKey verifies the signature is order-independent, distinguishes
// interface scope, and changes when the set changes - the basis for detecting VM
// start/stop at runtime.
func TestForwardedSourceSetKey(t *testing.T) {
	a := netip.MustParsePrefix("192.168.64.0/24")
	b := netip.MustParsePrefix("10.211.55.0/24")

	// Order-independent.
	k1 := forwardedSourceSetKey([]forwardedSource{{prefix: a, iface: "vmnet8"}, {prefix: b}})
	k2 := forwardedSourceSetKey([]forwardedSource{{prefix: b}, {prefix: a, iface: "vmnet8"}})
	if k1 != k2 {
		t.Errorf("key must be order-independent: %q vs %q", k1, k2)
	}

	// A guest appearing changes the key (empty -> one source).
	if forwardedSourceSetKey(nil) == k1 {
		t.Error("adding a source must change the key")
	}

	// A guest stopping changes the key (two sources -> one).
	k3 := forwardedSourceSetKey([]forwardedSource{{prefix: b}})
	if k3 == k1 {
		t.Error("removing a source must change the key")
	}

	// Same prefix on a different interface is a distinct trust and must differ.
	kIface := forwardedSourceSetKey([]forwardedSource{{prefix: a, iface: "vmnet8"}})
	kNoIface := forwardedSourceSetKey([]forwardedSource{{prefix: a}})
	if kIface == kNoIface {
		t.Error("interface scope must affect the key")
	}
}

// TestApplyForwardedSourceChange_Lifecycle walks the guest start/stop lifecycle
// deterministically (no pf, no hypervisor): initial build, guest start, no-change
// re-check, second guest start, guest stop, scope change, and back to none. Each
// anchor reload succeeds here. It asserts both halves of the contract - whether the
// anchor needs rebuilding, and which subnets' pf states must be dropped because
// their trust changed.
func TestApplyForwardedSourceChange_Lifecycle(t *testing.T) {
	vmA := forwardedSource{prefix: netip.MustParsePrefix("192.168.105.0/24"), iface: "vmnet8"}
	vmB := forwardedSource{prefix: netip.MustParsePrefix("10.211.55.0/24"), iface: "vnic0"}
	cfgB := forwardedSource{prefix: vmB.prefix} // same subnet, configured (no iface scope)

	steps := []struct {
		name        string
		cur         []forwardedSource
		wantChanged bool
		wantGained  []string
		wantLost    []string
	}{
		{name: "initial state, no guests", cur: nil, wantChanged: false},
		{
			name: "first guest starts", cur: []forwardedSource{vmA},
			wantChanged: true, wantGained: []string{"192.168.105.0/24"},
		},
		{name: "network change, nothing moved", cur: []forwardedSource{vmA}, wantChanged: false},
		{
			// Reordered plus a new guest: order must not register as a change.
			name: "second guest starts", cur: []forwardedSource{vmB, vmA},
			wantChanged: true, wantGained: []string{"10.211.55.0/24"},
		},
		{
			name: "first guest stops", cur: []forwardedSource{vmB},
			wantChanged: true, wantLost: []string{"192.168.105.0/24"},
		},
		{
			// Same subnet, different scope: a distinct trust, so its states must be
			// dropped even though the subnet itself neither appeared nor vanished.
			name: "guest subnet loses its interface scope", cur: []forwardedSource{cfgB},
			wantChanged: true,
			wantGained:  []string{"10.211.55.0/24"},
			wantLost:    []string{"10.211.55.0/24"},
		},
		{
			name: "last guest stops", cur: nil,
			wantChanged: true, wantLost: []string{"10.211.55.0/24"},
		},
		{name: "still no guests", cur: nil, wantChanged: false},
	}

	state := &pfFirewallState{}
	reloads := 0
	okReload := func() error { reloads++; return nil }
	wantReloads := 0
	for _, step := range steps {
		gained, lost, changed, err := state.applyForwardedSourceChange(step.cur, okReload)
		if err != nil {
			t.Fatalf("%s: unexpected reload error: %v", step.name, err)
		}
		if changed != step.wantChanged {
			t.Errorf("%s: changed = %v, want %v", step.name, changed, step.wantChanged)
		}
		if got := prefixStrings(gained); !equalStringSets(got, step.wantGained) {
			t.Errorf("%s: gained trust = %v, want %v", step.name, got, step.wantGained)
		}
		if got := prefixStrings(lost); !equalStringSets(got, step.wantLost) {
			t.Errorf("%s: lost trust = %v, want %v", step.name, got, step.wantLost)
		}
		// The anchor must be rebuilt exactly on the transitions, never on a re-check.
		if step.wantChanged {
			wantReloads++
		}
		if reloads != wantReloads {
			t.Errorf("%s: anchor reloads = %d, want %d", step.name, reloads, wantReloads)
		}
	}
}

// TestApplyForwardedSourceChange_FailureThenRetry is the convergence guarantee: a
// failed anchor write/load must NOT advance the applied snapshot, so the very next
// reconcile (at the latest the next watchdog tick) retries the same transition
// instead of seeing the new key and going quiet with the old anchor still installed.
func TestApplyForwardedSourceChange_FailureThenRetry(t *testing.T) {
	guest := netip.MustParsePrefix("192.168.105.0/24")
	cur := []forwardedSource{{prefix: guest, iface: "vmnet8"}}

	state := &pfFirewallState{}
	loadErr := errors.New("pfctl: syntax error")
	attempts := 0
	failing := func() error { attempts++; return loadErr }
	succeeding := func() error { attempts++; return nil }

	// Attempt 1: guest starts, reload fails. The caller is told what changed (so it
	// can log it) but must not treat it as applied.
	gained, lost, changed, err := state.applyForwardedSourceChange(cur, failing)
	if !changed || !errors.Is(err, loadErr) {
		t.Fatalf("failed reload: changed = %v, err = %v, want true / the load error", changed, err)
	}
	if got := prefixStrings(gained); !equalStringSets(got, []string{guest.String()}) {
		t.Errorf("failed reload: gained trust = %v, want %v", got, []string{guest.String()})
	}
	if len(lost) != 0 {
		t.Errorf("failed reload: lost trust = %v, want none", prefixStrings(lost))
	}
	if state.lastForwardedKey != "" || state.lastForwardedSources != nil {
		t.Fatalf("failed reload must not advance the applied snapshot, got key %q sources %v",
			state.lastForwardedKey, state.lastForwardedSources)
	}

	// Attempt 2: nothing else moved, but the change is still pending - it must be
	// retried and reported identically, not swallowed.
	gained, _, changed, err = state.applyForwardedSourceChange(cur, failing)
	if !changed || err == nil {
		t.Fatalf("retry after failure: changed = %v, err = %v, want true / an error", changed, err)
	}
	if got := prefixStrings(gained); !equalStringSets(got, []string{guest.String()}) {
		t.Errorf("retry after failure: gained trust = %v, want %v", got, []string{guest.String()})
	}

	// Attempt 3: pf accepts the anchor - now the snapshot advances and the affected
	// subnet's states are reported for killing.
	gained, _, changed, err = state.applyForwardedSourceChange(cur, succeeding)
	if !changed || err != nil {
		t.Fatalf("successful reload: changed = %v, err = %v, want true / nil", changed, err)
	}
	if got := prefixStrings(gained); !equalStringSets(got, []string{guest.String()}) {
		t.Errorf("successful reload: gained trust = %v, want %v", got, []string{guest.String()})
	}
	if state.lastForwardedKey == "" {
		t.Fatal("successful reload must record the applied source set")
	}

	// Attempt 4: converged - no further rebuild, and no reload call at all.
	before := attempts
	if _, _, changed, err := state.applyForwardedSourceChange(cur, succeeding); changed || err != nil {
		t.Errorf("after convergence: changed = %v, err = %v, want false / nil", changed, err)
	}
	if attempts != before {
		t.Errorf("after convergence: reload was called %d extra time(s), want 0", attempts-before)
	}

	// A failure while *removing* trust must likewise not be latched: the subnet stays
	// recorded as applied until pf accepts the anchor without it.
	if _, lost, changed, err := state.applyForwardedSourceChange(nil, failing); !changed || err == nil {
		t.Errorf("guest stop with failing reload: changed = %v, err = %v, want true / an error", changed, err)
	} else if got := prefixStrings(lost); !equalStringSets(got, []string{guest.String()}) {
		t.Errorf("guest stop with failing reload: lost trust = %v, want %v", got, []string{guest.String()})
	}
	if state.lastForwardedKey == "" {
		t.Error("failed removal must keep the previously applied set recorded")
	}
	if _, lost, _, err := state.applyForwardedSourceChange(nil, succeeding); err != nil {
		t.Errorf("guest stop retry: unexpected error %v", err)
	} else if got := prefixStrings(lost); !equalStringSets(got, []string{guest.String()}) {
		t.Errorf("guest stop retry: lost trust = %v, want %v", got, []string{guest.String()})
	}
	if state.lastForwardedKey != "" || state.lastForwardedSources != nil {
		t.Errorf("after successful removal the applied set must be empty, got key %q sources %v",
			state.lastForwardedKey, state.lastForwardedSources)
	}
}

// TestReconcileForwardedSources_GatedOff verifies the reconcile entry point is inert
// when firewall mode is off or pf state was never initialized, so the network-change
// and watchdog call sites never touch pf outside firewall mode.
func TestReconcileForwardedSources_GatedOff(t *testing.T) {
	// Firewall mode off (no allowList) - must return before touching pf state.
	off := progWithForwardedSources("192.168.64.0/24")
	off.platformFirewallState = &pfFirewallState{}
	off.dnsInterceptState = &pfState{anchorFile: pfAnchorFile, anchorName: pfAnchorName}
	off.reconcileForwardedSources()
	if state := off.platformFirewallState.(*pfFirewallState); state.lastForwardedKey != "" {
		t.Errorf("reconcile must not record a source set when firewall mode is off, got %q", state.lastForwardedKey)
	}

	// Firewall mode on but pf firewall state not initialized - must not panic.
	noState := progWithForwardedSources("192.168.64.0/24")
	noState.allowList = firewall.New()
	noState.dnsInterceptState = &pfState{anchorFile: pfAnchorFile, anchorName: pfAnchorName}
	noState.reconcileForwardedSources()

	// Firewall mode on but intercept inactive - no anchor to rebuild.
	noIntercept := progWithForwardedSources("192.168.64.0/24")
	noIntercept.allowList = firewall.New()
	noIntercept.platformFirewallState = &pfFirewallState{}
	noIntercept.reconcileForwardedSources()
	if state := noIntercept.platformFirewallState.(*pfFirewallState); state.lastForwardedKey != "" {
		t.Errorf("reconcile must not record a source set without intercept, got %q", state.lastForwardedKey)
	}
}

// equalStringSets compares two string slices ignoring order and nil-vs-empty.
func equalStringSets(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := make(map[string]int, len(got))
	for _, s := range got {
		seen[s]++
	}
	for _, s := range want {
		seen[s]--
		if seen[s] < 0 {
			return false
		}
	}
	return true
}

// TestDetectForwardedSources_OnlyPrivate verifies detection returns only private
// IPv4 vendor-VM subnets, each tagged with a vendor interface. Environment-dependent,
// so it asserts a property rather than an exact set.
func TestDetectForwardedSources_OnlyPrivate(t *testing.T) {
	p := &prog{cfg: &ctrld.Config{}}
	p.logger.Store(mainLog.Load())
	for _, src := range p.detectForwardedSources() {
		if !src.prefix.Addr().Is4() {
			t.Errorf("detected non-IPv4 forwarded source: %s", src.prefix)
		}
		if !src.prefix.Addr().IsPrivate() {
			t.Errorf("detected non-private forwarded source (must never auto-trust public): %s", src.prefix)
		}
		if !isHypervisorVMNetIface(src.iface) {
			t.Errorf("detected source on non-vendor interface %q", src.iface)
		}
	}
}

// TestPFBuildAnchorRules_ForwardedSourcesGating verifies the forwarded-source rules
// appear in the full anchor only when firewall mode is active, and when a configured
// source is present it appears before the blanket allowlist block so the redirect
// wins. A configured source makes the "on" case deterministic regardless of host.
func TestPFBuildAnchorRules_ForwardedSourcesGating(t *testing.T) {
	// Firewall OFF (no allowList): a configured source must NOT appear.
	off := progWithForwardedSources("192.168.64.0/24")
	if rules := off.buildPFAnchorRules(nil); strings.Contains(rules, "192.168.64.0/24 to ! ") {
		t.Errorf("forwarded-source rules must not be emitted when firewall mode is off:\n%s", rules)
	}

	// Firewall ON: allowList present → rules appear, before the blanket block.
	on := progWithForwardedSources("192.168.64.0/24")
	on.allowList = firewall.New()
	rules := on.buildPFAnchorRules(nil)

	fwdIdx := strings.Index(rules, "from 192.168.64.0/24 to ! 127.0.0.1 port 53")
	blockIdx := strings.Index(rules, "block return out quick inet proto { tcp, udp } from any to any")
	if fwdIdx < 0 {
		t.Fatalf("configured forwarded-source redirect missing when firewall mode is on:\n%s", rules)
	}
	if blockIdx < 0 {
		t.Fatalf("blanket firewall block missing:\n%s", rules)
	}
	if fwdIdx >= blockIdx {
		t.Errorf("forwarded-source redirect (%d) must come before the blanket block (%d)", fwdIdx, blockIdx)
	}
}

// TestBuildPFFirewallRulesDeclaresExceptionTable pins the pf side of the
// organization's Allowed Destination IP list.
//
// Every cmd/cli test of the allowed-destination paths stubs the platform mirror,
// so nothing else reaches this generator: the table the mirror populates could
// stop being declared, or lose its pass rules, and the mirror would keep
// reporting success while every approved destination stayed blocked. Both
// families are asserted - a list is not usable if only one of them passes.
func TestBuildPFFirewallRulesDeclaresExceptionTable(t *testing.T) {
	rules := buildPFFirewallRules()

	wants := []string{
		// Declared persist, like the dynamic table: pfctl -T add/delete/replace
		// against an undeclared table fails, and persist is what keeps the table
		// alive while it holds no addresses.
		"table <" + pfFirewallExceptionTable + "> persist",
		"pass out quick inet proto { tcp, udp } from any to <" + pfFirewallExceptionTable + ">",
		"pass out quick inet6 proto { tcp, udp } from any to <" + pfFirewallExceptionTable + ">",
	}
	for _, want := range wants {
		if !strings.Contains(rules, want) {
			t.Errorf("missing rule:\n  %s\nin:\n%s", want, rules)
		}
	}

	// The exception table is separate from the dynamic one on purpose: the flushes
	// that discard DNS-resolved IPs must leave administratively allowed
	// destinations in place.
	if pfFirewallExceptionTable == pfFirewallTable {
		t.Fatal("the exception table and the dynamic table are the same table; a flush would drop the organization's list")
	}
}

// TestPFExceptionTableChunks covers the argv-length split. The organization's
// list is API-supplied and unbounded, and every entry becomes an argv element, so
// a long enough list would blow past ARG_MAX and fail as a whole.
func TestPFExceptionTableChunks(t *testing.T) {
	entries := make([]string, pfExceptionTableOpChunk*2+1)
	for i := range entries {
		entries[i] = "203.0.113.10/32"
	}

	if got := pfExceptionTableChunks("replace", nil); len(got) != 0 {
		t.Errorf("chunks for an empty list = %d, want 0", len(got))
	}

	short := pfExceptionTableChunks("replace", entries[:2])
	if len(short) != 1 || short[0].op != "replace" || len(short[0].entries) != 2 {
		t.Fatalf("a list that fits was split: %+v", short)
	}

	// A split replace must replace once and add the rest. Splitting it into three
	// replaces would leave pf holding only the final chunk, with the organization's
	// other destinations silently dropped while the mirror reported success.
	split := pfExceptionTableChunks("replace", entries)
	if len(split) != 3 {
		t.Fatalf("chunks = %d, want 3 for %d entries at %d per call", len(split), len(entries), pfExceptionTableOpChunk)
	}
	if split[0].op != "replace" {
		t.Errorf("first chunk op = %q, want replace", split[0].op)
	}
	for _, chunk := range split[1:] {
		if chunk.op != "add" {
			t.Errorf("chunk after the first has op %q, want add: a second replace discards the first", chunk.op)
		}
	}
	var total int
	for _, chunk := range split {
		total += len(chunk.entries)
	}
	if total != len(entries) {
		t.Errorf("chunked entries = %d, want %d: the split dropped entries", total, len(entries))
	}

	// delete is per-entry, so every chunk keeps the operation.
	for _, chunk := range pfExceptionTableChunks("delete", entries) {
		if chunk.op != "delete" {
			t.Errorf("delete chunk op = %q, want delete", chunk.op)
		}
	}
}
