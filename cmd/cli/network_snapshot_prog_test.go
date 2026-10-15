package cli

import (
	"context"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/Control-D-Inc/ctrld"
	"tailscale.com/net/netmon"
)

// stubSnapshotPlatformMeta makes the platform names of each interface a
// fixture, so no test depends on the ports of the host.
func stubSnapshotPlatformMeta(t *testing.T, meta map[string]interfaceMeta) {
	t.Helper()
	orig := platformInterfaceMetaFn
	t.Cleanup(func() { platformInterfaceMetaFn = orig })
	platformInterfaceMetaFn = func(name string) (class, hardwarePort, service string) {
		info := meta[name]
		return info.Class, info.HardwarePort, info.Service
	}
}

// stubSnapshotVirtualSet names the virtual adapters of the fixture host.
func stubSnapshotVirtualSet(t *testing.T, names ...string) {
	t.Helper()
	orig := virtualInterfaceSetFn
	t.Cleanup(func() { virtualInterfaceSetFn = orig })
	virtual := make(map[string]struct{}, len(names))
	for _, name := range names {
		virtual[name] = struct{}{}
	}
	virtualInterfaceSetFn = func() map[string]struct{} { return virtual }
}

// stubSnapshotGateways replaces the route table read, because the gateways of
// the host are not a fixture.
func stubSnapshotGateways(t *testing.T, v4, v6 string) {
	t.Helper()
	stubSnapshotRoutes(t, defaultRoute{Gateway: v4}, defaultRoute{Gateway: v6})
}

// stubSnapshotRoutes replaces the route table read with one default route per
// family.
func stubSnapshotRoutes(t *testing.T, v4, v6 defaultRoute) {
	t.Helper()
	orig := defaultRoutesFn
	t.Cleanup(func() { defaultRoutesFn = orig })
	defaultRoutesFn = func() (defaultRoute, defaultRoute) { return v4, v6 }
}

// stubSnapshotDNS64 reports a dual-stack host, so the NAT64 check starts no
// discovery and touches no name server.
func stubSnapshotDNS64(t *testing.T) {
	t.Helper()
	orig := dns64NetworkClassFn
	t.Cleanup(func() { dns64NetworkClassFn = orig })
	dns64NetworkClassFn = func() (hasUsableIPv4, hasCLAT bool, err error) { return true, false, nil }
}

// stubSnapshotSources sets the local source addresses and puts the values of
// the host back when the test ends.
func stubSnapshotSources(t *testing.T, v4, v6 string) {
	t.Helper()
	origV4, origV6 := ctrld.GetDefaultLocalIPv4(), ctrld.GetDefaultLocalIPv6()
	t.Cleanup(func() {
		ctrld.SetDefaultLocalIPv4(context.Background(), origV4)
		ctrld.SetDefaultLocalIPv6(context.Background(), origV6)
	})
	ctrld.SetDefaultLocalIPv4(context.Background(), net.ParseIP(v4))
	ctrld.SetDefaultLocalIPv6(context.Background(), net.ParseIP(v6))
}

// tetheredSnapshotProg returns a prog on a phone hotspot over the cable.
func tetheredSnapshotProg(t *testing.T) *prog {
	t.Helper()
	stubSnapshotDNS64(t)
	stubSnapshotGateways(t, "172.20.10.1", "")
	stubSnapshotPlatformMeta(t, map[string]interfaceMeta{
		"en7": {HardwarePort: hardwarePortIPhoneUSB, Service: "iPhone USB"},
	})
	stubSnapshotVirtualSet(t)
	stubSnapshotSources(t, "172.20.10.5", "")

	p := &prog{}
	p.logger.Store(mainLog.Load())
	p.lastNetworkState.Store(&netmon.State{
		DefaultRouteInterface: "en7",
		HaveV4:                true,
		Interface: map[string]netmon.Interface{
			"en7": {Interface: &net.Interface{Name: "en7", Flags: net.FlagUp}},
			"lo0": {Interface: &net.Interface{Name: "lo0", Flags: net.FlagUp}},
		},
		InterfaceIPs: map[string][]netip.Prefix{
			"en7": {netip.MustParsePrefix("172.20.10.5/28")},
			"lo0": {netip.MustParsePrefix("127.0.0.1/8")},
		},
	})
	p.recoveryBypass.Store(true)
	p.pfStabilizing.Store(true)
	p.interceptDNSTargetSetValue = "127.0.0.1"
	p.publishInterceptTarget("127.0.0.1")
	return p
}

func Test_networkSnapshotFromTheStoredState(t *testing.T) {
	p := tetheredSnapshotProg(t)

	snapshot := p.networkSnapshot()

	checks := []struct {
		field     string
		got, want any
	}{
		{"default_route_v4", snapshot.DefaultRouteV4, "en7"},
		{"default_route_v6", snapshot.DefaultRouteV6, ""},
		{"gateway_v4", snapshot.GatewayV4, "172.20.10.1"},
		{"have_v4", snapshot.HaveV4, true},
		{"source_ipv4", snapshot.SourceIPv4, "172.20.10.5"},
		{"source_ipv6", snapshot.SourceIPv6, ""},
		{"intercept_target", snapshot.InterceptTarget, "127.0.0.1"},
		{"dns_less_target", snapshot.DNSLessTarget, true},
		{"bypass_active", snapshot.BypassActive, true},
		{"recovery_running", snapshot.RecoveryRunning, false},
		{"pf_stabilizing", snapshot.PFStabilizing, true},
		{"link_type", snapshot.LinkType, "usb_tether"},
		{"tethered", snapshot.Tethered, true},
		{"nat64_prefix", snapshot.NAT64Prefix, ""},
		{"clat_present", snapshot.CLATPresent, false},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.field, c.got, c.want)
		}
	}

	want := []snapshotInterface{
		{Name: "en7", Class: "hardware", Up: true, IPs: []string{"172.20.10.5/28"}, HardwarePort: hardwarePortIPhoneUSB, Service: "iPhone USB"},
		{Name: "lo0", Class: "loopback", Up: true, IPs: []string{"127.0.0.1/8"}},
	}
	if !reflect.DeepEqual(snapshot.Interfaces, want) {
		t.Errorf("interfaces = %+v, want %+v", snapshot.Interfaces, want)
	}
}

// Test_networkSnapshotReadsTheNetworkWithoutAStoredState covers the first
// header of a run. No network callback reached ctrld yet, so the snapshot must
// read the interfaces itself and name the families it finds.
func Test_networkSnapshotReadsTheNetworkWithoutAStoredState(t *testing.T) {
	stubSnapshotDNS64(t)
	stubSnapshotGateways(t, "192.0.2.1", "")
	stubSnapshotPlatformMeta(t, nil)
	stubSnapshotSources(t, "", "")
	stubLogHeaderNetworkRead(t, "en9")
	p := &prog{}
	p.logger.Store(mainLog.Load())

	snapshot := p.networkSnapshot()

	if len(snapshot.Interfaces) != 1 || snapshot.Interfaces[0].Name != "en9" || !snapshot.Interfaces[0].Up {
		t.Fatalf("interfaces = %+v, want one up en9", snapshot.Interfaces)
	}
	if !snapshot.HaveV4 {
		t.Error("have_v4 = false, want true for a global unicast v4 address")
	}
	if snapshot.HaveV6 {
		t.Error("have_v6 = true, want false without a v6 address")
	}
}

// Test_reachableAddressFamiliesGradesTheV6AddressLikeNetmon covers a host on a
// unique local address. The network monitor counts such an address as usable,
// so a fresh read must count it too.
func Test_reachableAddressFamiliesGradesTheV6AddressLikeNetmon(t *testing.T) {
	for _, tt := range []struct {
		name   string
		ips    []string
		wantV6 bool
	}{
		{name: "unique_local", ips: []string{"fd00::2/64"}, wantV6: true},
		{name: "tailscale_range", ips: []string{"fd7a:115c:a1e0::2/128"}},
		{name: "global", ips: []string{"2001:db8::2/64"}, wantV6: true},
		{name: "link_local", ips: []string{"fe80::2/64"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			state := snapshotTestState("en0", snapshotTestInterface{"en0", true, tt.ips})

			_, haveV6 := reachableAddressFamilies(state)

			if haveV6 != tt.wantV6 {
				t.Errorf("have_v6 = %v, want %v for %v", haveV6, tt.wantV6, tt.ips)
			}
		})
	}
}

func Test_networkSnapshotLogsOneJournalLine(t *testing.T) {
	logs := captureDebugMainLog(t)
	p := tetheredSnapshotProg(t)

	p.logNetworkSnapshot("start")

	events := jsonLogEvents(t, logs, networkSnapshotMessage)
	if len(events) != 1 {
		t.Fatalf("%q lines = %d, want 1", networkSnapshotMessage, len(events))
	}
	wantField(t, events[0], "trigger", "start")
	wantField(t, events[0], journalField, true)
	wantField(t, events[0], "level", "info")
	network, ok := events[0]["network"].(map[string]any)
	if !ok {
		t.Fatalf("network = %v, want an object", events[0]["network"])
	}
	wantField(t, network, "default_route_v4", "en7")
	wantField(t, network, "tethered", true)
	wantField(t, network, "link_type", "usb_tether")
}

// snapshotTestClock hands out the time that a test sets, because the snapshot
// limit counts seconds between two lines.
type snapshotTestClock struct {
	now time.Time
}

// stubSnapshotClock puts the clock of the snapshot limit under the control of
// one test.
func stubSnapshotClock(t *testing.T) *snapshotTestClock {
	t.Helper()
	clock := &snapshotTestClock{now: time.Date(2026, 9, 17, 10, 0, 0, 0, time.UTC)}
	orig := snapshotNowFn
	t.Cleanup(func() { snapshotNowFn = orig })
	snapshotNowFn = func() time.Time { return clock.now }
	return clock
}

func (c *snapshotTestClock) advance(d time.Duration) { c.now = c.now.Add(d) }

// snapshotTriggerLines names the trigger of every snapshot line, in order.
func snapshotTriggerLines(t *testing.T, logs *syncBuffer) []string {
	t.Helper()
	var triggers []string
	for _, event := range jsonLogEvents(t, logs, networkSnapshotMessage) {
		trigger, _ := event["trigger"].(string)
		triggers = append(triggers, trigger)
	}
	return triggers
}

// Test_logNetworkSnapshotSkipsAnEqualSnapshot covers a recovery on a network
// that did not change. The begin and the end of that recovery render the same
// object, so the second line carries nothing.
func Test_logNetworkSnapshotSkipsAnEqualSnapshot(t *testing.T) {
	logs := captureDebugMainLog(t)
	clock := stubSnapshotClock(t)
	p := tetheredSnapshotProg(t)

	p.logNetworkSnapshot("recovery_begin")
	clock.advance(5 * time.Minute)
	p.logNetworkSnapshot("recovery_end")

	if got := snapshotTriggerLines(t, logs); !slices.Equal(got, []string{"recovery_begin"}) {
		t.Errorf("snapshot triggers = %v, want the first line alone", got)
	}
}

// Test_logNetworkSnapshotCapsTheRate covers a flapping interface. Two
// snapshots that differ in no route and in no resolver give one line per
// minute.
func Test_logNetworkSnapshotCapsTheRate(t *testing.T) {
	logs := captureDebugMainLog(t)
	clock := stubSnapshotClock(t)
	p := tetheredSnapshotProg(t)

	p.logNetworkSnapshot("transition")
	clock.advance(30 * time.Second)
	p.recoveryRunning.Store(true)
	p.logNetworkSnapshot("transition")
	clock.advance(30 * time.Second)
	p.logNetworkSnapshot("transition")

	if got := snapshotTriggerLines(t, logs); len(got) != 2 {
		t.Errorf("snapshot lines = %d, want 2: %v", len(got), got)
	}
}

// Test_logNetworkSnapshotWritesARouteChangeAtOnce covers the change that
// explains an outage. The cap must not hold it back.
func Test_logNetworkSnapshotWritesARouteChangeAtOnce(t *testing.T) {
	logs := captureDebugMainLog(t)
	clock := stubSnapshotClock(t)
	p := tetheredSnapshotProg(t)

	p.logNetworkSnapshot("transition")
	clock.advance(time.Second)
	stubSnapshotRoutes(t, defaultRoute{Gateway: "192.168.1.1", Interface: "en0"}, defaultRoute{})
	p.logNetworkSnapshot("transition")
	clock.advance(time.Second)
	p.recoveryRunning.Store(true)
	p.logNetworkSnapshot("recovery_begin")

	if got := snapshotTriggerLines(t, logs); !slices.Equal(got, []string{"transition", "transition"}) {
		t.Errorf("snapshot triggers = %v, want the two transitions", got)
	}
}

// Test_logNetworkSnapshotAlwaysWritesTheStartLine covers the first line of a
// run. A reader needs the network of the start, whatever came before it.
func Test_logNetworkSnapshotAlwaysWritesTheStartLine(t *testing.T) {
	logs := captureDebugMainLog(t)
	clock := stubSnapshotClock(t)
	p := tetheredSnapshotProg(t)

	p.logNetworkSnapshot("transition")
	clock.advance(time.Second)
	p.logNetworkSnapshot(snapshotTriggerStart)

	if got := snapshotTriggerLines(t, logs); !slices.Equal(got, []string{"transition", "start"}) {
		t.Errorf("snapshot triggers = %v, want the transition and the start", got)
	}
}

func Test_interfaceMetaFor(t *testing.T) {
	stubSnapshotVirtualSet(t, "bridge100")
	stubSnapshotPlatformMeta(t, map[string]interfaceMeta{
		"lo0":  {Class: "hardware"},
		"en0":  {HardwarePort: "Wi-Fi", Service: "Wi-Fi"},
		"eth0": {Class: "hardware", HardwarePort: "Intel I219-V"},
	})

	for _, tt := range []struct {
		name string
		want interfaceMeta
	}{
		{"lo0", interfaceMeta{Class: "loopback", LinkType: "unknown"}},
		{"awdl0", interfaceMeta{Class: "airdrop", LinkType: "unknown"}},
		{"utun3", interfaceMeta{Class: "tunnel", LinkType: "tunnel"}},
		{"en0", interfaceMeta{Class: "hardware", HardwarePort: "Wi-Fi", Service: "Wi-Fi", LinkType: "wifi"}},
		{"bridge100", interfaceMeta{Class: "virtual", LinkType: "unknown"}},
		{"eth0", interfaceMeta{Class: "hardware", HardwarePort: "Intel I219-V", LinkType: "unknown"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := interfaceMetaFor(tt.name); got != tt.want {
				t.Errorf("interfaceMetaFor(%q) = %+v, want %+v", tt.name, got, tt.want)
			}
		})
	}
}
