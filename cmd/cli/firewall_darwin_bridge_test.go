//go:build darwin

package cli

import (
	"net"
	"net/netip"
	"testing"

	"github.com/Control-D-Inc/ctrld/internal/firewall"
)

// vmnetBridgeIfconfig is ifconfig output for a vmnet.framework bridge: the RFC1918
// gateway lives here, and the vendor-named vmenet0 is an address-less member. This is
// the shape that name-only detection could never see.
const vmnetBridgeIfconfig = `bridge100: flags=8a63<UP,BROADCAST,SMART,RUNNING,ALLMULTI,SIMPLEX,MULTICAST> mtu 1500
	options=3<RXCSUM,TXCSUM>
	ether 5e:cf:7f:9a:1b:64
	inet 192.168.64.1 netmask 0xffffff00 broadcast 192.168.64.255
	Configuration:
		id 0:0:0:0:0:0 priority 0 hellotime 0 fwddelay 0
		maxage 0 holdcnt 0 proto stp maxaddr 100 timeout 1200
		root id 0:0:0:0:0:0 priority 0 ifcost 0 port 0
		ipfilter disabled flags 0x0
	member: vmenet0 flags=3<LEARNING,DISCOVER>
	        ifmaxaddr 0 port 22 priority 0 path cost 0
	nd6 options=201<PERFORMNUD,DAD>
	media: <unknown type>
	status: active
`

// thunderboltBridgeIfconfig is ifconfig output for the Thunderbolt bridge macOS
// creates by default. It can carry an RFC1918 address, and its members are physical
// interfaces - trusting it would force-route unrelated same-subnet traffic.
const thunderboltBridgeIfconfig = `bridge0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	options=63<RXCSUM,TXCSUM,TSO4,TSO6>
	ether 36:12:8a:1f:2b:00
	inet 192.168.10.5 netmask 0xffffff00 broadcast 192.168.10.255
	Configuration:
		id 0:0:0:0:0:0 priority 0 hellotime 0 fwddelay 0
	member: en1 flags=3<LEARNING,DISCOVER>
	        ifmaxaddr 0 port 9 priority 0 path cost 0
	member: en2 flags=3<LEARNING,DISCOVER>
	        ifmaxaddr 0 port 10 priority 0 path cost 0
	nd6 options=201<PERFORMNUD,DAD>
	media: <unknown type>
	status: inactive
`

func TestParseBridgeMembers(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want []string
	}{
		{"vmnet.framework bridge", vmnetBridgeIfconfig, []string{"vmenet0"}},
		{"thunderbolt bridge", thunderboltBridgeIfconfig, []string{"en1", "en2"}},
		{"no members", "bridge2: flags=8822<BROADCAST,SMART,SIMPLEX,MULTICAST> mtu 1500\n\tether 1a:2b:3c\n", nil},
		{"empty output", "", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseBridgeMembers(tc.out)
			if len(got) != len(tc.want) {
				t.Fatalf("parseBridgeMembers() = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("member[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestBridgeHasVMMember(t *testing.T) {
	tests := []struct {
		name    string
		members []string
		want    bool
	}{
		{"vmnet.framework member", []string{"vmenet0"}, true},
		{"parallels member", []string{"vnic0"}, true},
		{"mixed with vm member", []string{"en1", "vmenet2"}, true},
		{"physical members only", []string{"en1", "en2"}, false},
		{"no members", nil, false},
		// A name that merely looks bridge-ish proves nothing.
		{"bridge member", []string{"bridge1"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := bridgeHasVMMember(tc.members); got != tc.want {
				t.Errorf("bridgeHasVMMember(%v) = %v, want %v", tc.members, got, tc.want)
			}
		})
	}
}

func mustAddrs(t *testing.T, cidrs ...string) []net.Addr {
	t.Helper()
	var out []net.Addr
	for _, c := range cidrs {
		ip, ipnet, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatalf("bad test CIDR %q: %v", c, err)
		}
		out = append(out, &net.IPNet{IP: ip, Mask: ipnet.Mask})
	}
	return out
}

// TestForwardedSourcesForIface covers the trust decision, including every case that
// must NOT be auto-trusted. This is a security boundary: anything that qualifies here
// gets its guest traffic passed to allowed public destinations.
func TestForwardedSourcesForIface(t *testing.T) {
	tests := []struct {
		name     string
		iface    string
		addrs    []string
		members  []string
		wantCIDR []string
	}{
		{
			// The case name-only detection missed: address on the bridge, vendor
			// interface bridged into it. This is UTM/Docker/Multipass/Fusion 12.1+.
			name:     "bridge with vmenet member is trusted",
			iface:    "bridge100",
			addrs:    []string{"192.168.64.1/24"},
			members:  []string{"vmenet0"},
			wantCIDR: []string{"192.168.64.0/24"},
		},
		{
			// The reason membership is required rather than the bridge name.
			name:    "thunderbolt bridge is not trusted",
			iface:   "bridge0",
			addrs:   []string{"192.168.10.5/24"},
			members: []string{"en1", "en2"},
		},
		{
			name:     "vendor-named interface with its own address is trusted",
			iface:    "vnic0",
			addrs:    []string{"10.211.55.2/24"},
			wantCIDR: []string{"10.211.55.0/24"},
		},
		{
			// vmenet* under vmnet.framework: up, but no address of its own.
			name:  "address-less vendor interface yields nothing",
			iface: "vmenet0",
			addrs: nil,
		},
		{
			// The RFC1918 boundary: a VM network on a public range is never trusted.
			name:    "public range on a VM bridge is not trusted",
			iface:   "bridge100",
			addrs:   []string{"93.184.216.34/24"},
			members: []string{"vmenet0"},
		},
		{
			// Interception is IPv4-only; an IPv6-only VM bridge must not qualify.
			name:    "ipv6 only is not trusted",
			iface:   "bridge100",
			addrs:   []string{"fd00::1/64"},
			members: []string{"vmenet0"},
		},
		{
			name:  "physical uplink is not trusted",
			iface: "en0",
			addrs: []string{"192.168.1.20/24"},
		},
		{
			name:  "vpn tunnel is not trusted",
			iface: "utun4",
			addrs: []string{"10.2.0.2/24"},
		},
		{
			name:     "mixed addresses keep only the private ipv4 one",
			iface:    "bridge101",
			addrs:    []string{"fd00::1/64", "192.168.105.1/24"},
			members:  []string{"vmenet1"},
			wantCIDR: []string{"192.168.105.0/24"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			members := func(string) []string { return tc.members }
			got, reason := forwardedSourcesForIface(tc.iface, mustAddrs(t, tc.addrs...), members)
			if len(got) != len(tc.wantCIDR) {
				t.Fatalf("got %d sources %v, want %d %v", len(got), got, len(tc.wantCIDR), tc.wantCIDR)
			}
			for i, want := range tc.wantCIDR {
				if got[i].prefix != netip.MustParsePrefix(want) {
					t.Errorf("prefix[%d] = %s, want %s", i, got[i].prefix, want)
				}
				// Rules must be scoped to the interface traffic actually arrives on.
				if got[i].iface != tc.iface {
					t.Errorf("source %s scoped to %q, want %q", got[i].prefix, got[i].iface, tc.iface)
				}
			}
			if len(got) > 0 && reason == "" {
				t.Error("a trusted source must report why it qualified")
			}
		})
	}
}

// TestForwardedSourcesForIface_NoMemberLookupWithoutAddress verifies the ifconfig call
// is skipped for a bridge that cannot qualify anyway. Detection runs on every anchor
// build and every watchdog tick, so this keeps a typical host at zero subprocesses.
func TestForwardedSourcesForIface_NoMemberLookupWithoutAddress(t *testing.T) {
	called := false
	members := func(string) []string {
		called = true
		return []string{"vmenet0"}
	}

	if got, _ := forwardedSourcesForIface("bridge100", nil, members); got != nil {
		t.Errorf("address-less bridge must yield nothing, got %v", got)
	}
	if called {
		t.Error("member list must not be queried for a bridge with no RFC1918 address")
	}

	// A public-range bridge is equally hopeless, and equally must not exec.
	called = false
	if got, _ := forwardedSourcesForIface("bridge100", mustAddrs(t, "93.184.216.34/24"), members); got != nil {
		t.Errorf("public-range bridge must yield nothing, got %v", got)
	}
	if called {
		t.Error("member list must not be queried for a bridge with no RFC1918 address")
	}
}

// TestParseForwardedSourceConfig covers the parse/reject split: usable entries survive
// alongside bad ones, and each rejection carries a reason to report.
func TestParseForwardedSourceConfig(t *testing.T) {
	sources, rejected := parseForwardedSourceConfig([]string{
		"192.168.64.7/24", // host bits get normalized
		"not-a-cidr",      // malformed
		"fd00::/64",       // not IPv4
		" 10.0.0.0/8 ",    // surrounding space tolerated
	})

	wantSources := map[string]bool{"192.168.64.0/24": true, "10.0.0.0/8": true}
	if len(sources) != len(wantSources) {
		t.Fatalf("got %d usable sources %v, want %d", len(sources), sources, len(wantSources))
	}
	for _, src := range sources {
		if !wantSources[src.prefix.String()] {
			t.Errorf("unexpected usable prefix %s", src.prefix)
		}
		if src.iface != "" {
			t.Errorf("configured source %s must have no interface scope, got %q", src.prefix, src.iface)
		}
	}

	if len(rejected) != 2 {
		t.Fatalf("got %d rejections %v, want 2", len(rejected), rejected)
	}
	for _, r := range rejected {
		if r.value != "not-a-cidr" && r.value != "fd00::/64" {
			t.Errorf("unexpected rejected value %q", r.value)
		}
		if r.reason == "" {
			t.Errorf("rejection of %q carries no reason", r.value)
		}
	}
}

func TestParseForwardedSourceConfig_Empty(t *testing.T) {
	sources, rejected := parseForwardedSourceConfig(nil)
	if sources != nil || rejected != nil {
		t.Errorf("empty config must yield nothing, got %v / %v", sources, rejected)
	}
}

// TestRejectedForwardedSourcesKey verifies the signature ignores order, so re-parsing
// an unchanged config is recognised as nothing new, while a changed set is not.
func TestRejectedForwardedSourcesKey(t *testing.T) {
	a := []rejectedForwardedSource{{value: "x", reason: "r1"}, {value: "y", reason: "r2"}}
	b := []rejectedForwardedSource{{value: "y", reason: "r2"}, {value: "x", reason: "r1"}}
	if rejectedForwardedSourcesKey(a) != rejectedForwardedSourcesKey(b) {
		t.Error("key must be order-independent")
	}
	if rejectedForwardedSourcesKey(nil) != "" {
		t.Error("no rejections must produce an empty key")
	}
	c := []rejectedForwardedSource{{value: "x", reason: "r1"}}
	if rejectedForwardedSourcesKey(a) == rejectedForwardedSourcesKey(c) {
		t.Error("different rejection sets must produce different keys")
	}
}

// resetForwardedSourceWarnTracker clears the process-wide warning dedupe so each test
// starts from "nothing reported yet".
func resetForwardedSourceWarnTracker(t *testing.T) {
	t.Helper()
	forwardedSourceWarnTracker.mu.Lock()
	forwardedSourceWarnTracker.key = ""
	forwardedSourceWarnTracker.mu.Unlock()
}

func trackedRejectionKey() string {
	forwardedSourceWarnTracker.mu.Lock()
	defer forwardedSourceWarnTracker.mu.Unlock()
	return forwardedSourceWarnTracker.key
}

// TestWarnRejectedForwardedSources_OnlyOnChange verifies a standing bad entry is
// reported once rather than on every watchdog tick, and that a newly-introduced one is
// still reported after a config reload.
//
// The dedupe must not depend on pfFirewallState: no state is installed here, matching
// the window where Firewall Mode is on but pf enforcement is still deferred until
// intercept mode starts.
func TestWarnRejectedForwardedSources_OnlyOnChange(t *testing.T) {
	resetForwardedSourceWarnTracker(t)
	p := progWithForwardedSources("not-a-cidr", "192.168.64.0/24")

	// First parse reports; the signature is now recorded.
	p.firewallForwardedSources()
	first := trackedRejectionKey()
	if first == "" {
		t.Fatal("a rejected entry must be recorded as reported")
	}

	// Re-parsing the same config (every anchor build, every 30s tick) must not change
	// what is recorded - that is what stops the repeated warning.
	for i := 0; i < 5; i++ {
		p.firewallForwardedSources()
	}
	if got := trackedRejectionKey(); got != first {
		t.Errorf("recorded rejection key changed on re-parse: %q -> %q", first, got)
	}

	// A config reload that introduces a different bad entry must be reported.
	p.cfg.Service.FirewallForwardedSources = []string{"also-not-a-cidr"}
	p.firewallForwardedSources()
	if trackedRejectionKey() == first {
		t.Error("a newly-introduced bad entry must be reported, not suppressed")
	}

	// Fixing the config clears the recorded set, so a later regression reports again.
	p.cfg.Service.FirewallForwardedSources = []string{"192.168.64.0/24"}
	p.firewallForwardedSources()
	if got := trackedRejectionKey(); got != "" {
		t.Errorf("a clean config must clear the recorded rejections, got %q", got)
	}
}

// TestCurrentForwardedSources_GatedOnFirewallMode verifies no detection or config
// parsing happens with Firewall Mode off. Anchor rebuilds run on tunnel changes,
// watchdog restores and VPN DNS updates regardless of firewall mode, so an ungated
// call would enumerate interfaces, exec ifconfig and re-report bad config entries on
// every one of them.
func TestCurrentForwardedSources_GatedOnFirewallMode(t *testing.T) {
	resetForwardedSourceWarnTracker(t)
	p := progWithForwardedSources("not-a-cidr", "192.168.64.0/24")

	// Firewall mode off: nothing detected, and the bad entry is not even looked at.
	if got := p.currentForwardedSources(); got != nil {
		t.Errorf("firewall mode off must yield no sources, got %v", got)
	}
	if got := trackedRejectionKey(); got != "" {
		t.Errorf("config must not be parsed with firewall mode off, but a rejection was recorded: %q", got)
	}

	// With firewall mode on (allowList present), the configured entry is honoured and
	// the bad one reported.
	p.allowList = firewall.New()
	got := p.currentForwardedSources()
	if len(got) != 1 || got[0].prefix != netip.MustParsePrefix("192.168.64.0/24") {
		t.Errorf("firewall mode on must yield the configured source, got %v", got)
	}
	if trackedRejectionKey() == "" {
		t.Error("the unusable entry must be reported once firewall mode is on")
	}
}

// TestRecordAppliedForwardedSources verifies a full-anchor rebuild can baseline the
// reconcile snapshot, so the next reconcile does not redo the same change.
func TestRecordAppliedForwardedSources(t *testing.T) {
	p := progWithForwardedSources()
	state := &pfFirewallState{}
	p.platformFirewallState = state

	sources := []forwardedSource{{prefix: netip.MustParsePrefix("192.168.64.0/24"), iface: "bridge100"}}
	p.recordAppliedForwardedSources(sources)

	if state.lastForwardedKey != forwardedSourceSetKey(sources) {
		t.Errorf("snapshot key = %q, want %q", state.lastForwardedKey, forwardedSourceSetKey(sources))
	}
	if len(state.lastForwardedSources) != 1 || state.lastForwardedSources[0] != sources[0] {
		t.Errorf("snapshot sources = %v, want %v", state.lastForwardedSources, sources)
	}

	// A reconcile against the same set must now find nothing to do: no second rebuild,
	// no killed states, no transition logged for something already in effect.
	reloads := 0
	_, _, changed, err := state.applyForwardedSourceChange(sources, func() error { reloads++; return nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if changed {
		t.Error("reconcile treated an already-applied set as a change")
	}
	if reloads != 0 {
		t.Errorf("anchor was rebuilt %d times for an unchanged set, want 0", reloads)
	}
}

// TestRecordAppliedForwardedSources_NoState verifies recording is a no-op when
// firewall mode is off, since the rebuild paths call it unconditionally.
func TestRecordAppliedForwardedSources_NoState(t *testing.T) {
	p := progWithForwardedSources()
	p.recordAppliedForwardedSources([]forwardedSource{{prefix: netip.MustParsePrefix("10.0.0.0/8")}})
}
