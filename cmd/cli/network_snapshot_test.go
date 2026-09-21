package cli

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"tailscale.com/net/netmon"
)

// snapshotTestInterface names one interface of a test network state.
type snapshotTestInterface struct {
	name string
	up   bool
	ips  []string
}

// snapshotTestState builds a netmon state with several interfaces, because the
// shared helper of the transition tests holds one interface only.
func snapshotTestState(route string, interfaces ...snapshotTestInterface) *netmon.State {
	state := &netmon.State{
		DefaultRouteInterface: route,
		Interface:             map[string]netmon.Interface{},
		InterfaceIPs:          map[string][]netip.Prefix{},
	}
	for _, iface := range interfaces {
		flags := net.Flags(0)
		if iface.up {
			flags = net.FlagUp
		}
		state.Interface[iface.name] = netmon.Interface{Interface: &net.Interface{Name: iface.name, Flags: flags}}
		for _, ip := range iface.ips {
			state.InterfaceIPs[iface.name] = append(state.InterfaceIPs[iface.name], netip.MustParsePrefix(ip))
		}
	}
	return state
}

func snapshotTestMeta(meta map[string]interfaceMeta) interfaceMetaFunc {
	return func(name string) interfaceMeta { return meta[name] }
}

func Test_tetheredNetwork(t *testing.T) {
	for _, tt := range []struct {
		name         string
		gatewayV4    string
		hardwarePort string
		hostIPs      []string
		want         bool
	}{
		{name: "hotspot_gateway", gatewayV4: "172.20.10.1", hardwarePort: "Wi-Fi", want: true},
		{name: "hotspot_range_end", gatewayV4: "172.20.10.15", hardwarePort: "Wi-Fi", want: true},
		{name: "above_hotspot_range", gatewayV4: "172.20.10.16", hardwarePort: "Wi-Fi"},
		{name: "below_hotspot_range", gatewayV4: "172.20.9.255", hardwarePort: "Wi-Fi"},
		{name: "home_gateway", gatewayV4: "192.168.1.1", hardwarePort: "Wi-Fi"},
		{name: "iphone_usb_port", gatewayV4: "192.168.1.1", hardwarePort: "iPhone USB", want: true},
		{name: "no_gateway_no_port"},
		{name: "unparsable_gateway", gatewayV4: "not-an-address"},
		{name: "v6_gateway", gatewayV4: "fe80::1", hardwarePort: "Ethernet"},
		{name: "hotspot_host_address_without_a_gateway", hostIPs: []string{"172.20.10.4/28"}, want: true},
		{name: "hotspot_host_address_of_a_second_address", hostIPs: []string{"fe80::1/64", "172.20.10.4/28"}, want: true},
		{name: "home_host_address_without_a_gateway", hostIPs: []string{"192.168.1.20/24"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			hostIPs := make([]netip.Prefix, 0, len(tt.hostIPs))
			for _, ip := range tt.hostIPs {
				hostIPs = append(hostIPs, netip.MustParsePrefix(ip))
			}
			if got := tetheredNetwork(tt.gatewayV4, tt.hardwarePort, hostIPs); got != tt.want {
				t.Fatalf("tetheredNetwork(%q, %q, %v) = %v, want %v", tt.gatewayV4, tt.hardwarePort, tt.hostIPs, got, tt.want)
			}
		})
	}
}

// Test_buildNetworkSnapshot_tetheredWithoutAGateway covers Linux and Windows.
// Both read no route table in this release, so the address of the host is the
// only sign of a phone hotspot.
func Test_buildNetworkSnapshot_tetheredWithoutAGateway(t *testing.T) {
	state := snapshotTestState("wlan0", snapshotTestInterface{"wlan0", true, []string{"172.20.10.4/28"}})

	snapshot := buildNetworkSnapshot(snapshotInputs{State: state})

	if !snapshot.Tethered {
		t.Error("tethered = false, want true for a host address of the hotspot range")
	}
}

// Test_usableV6 pins the grade of a v6 address to the rule of the network
// monitor. A fresh read and a monitor callback must report the same have_v6.
func Test_usableV6(t *testing.T) {
	for _, tt := range []struct {
		address string
		want    bool
	}{
		{"2001:db8::1", true},
		{"2606:4700:4700::1111", true},
		{"fd00::1", true},
		{"fd7a:115c:a1e0::1", false},
		{"fe80::1", false},
		{"::1", false},
		{"192.0.2.10", false},
	} {
		t.Run(tt.address, func(t *testing.T) {
			if got := usableV6(netip.MustParseAddr(tt.address).Unmap()); got != tt.want {
				t.Errorf("usableV6(%q) = %v, want %v", tt.address, got, tt.want)
			}
		})
	}
}

func Test_linkTypeFor(t *testing.T) {
	for _, tt := range []struct {
		name         string
		hardwarePort string
		class        string
		want         string
	}{
		{"wifi_port", "Wi-Fi", "hardware", "wifi"},
		{"ethernet_port", "Ethernet", "hardware", "ethernet"},
		{"thunderbolt_port", "Thunderbolt Ethernet Slot 1", "hardware", "ethernet"},
		{"usb_lan_port", "USB 10/100/1000 LAN", "hardware", "ethernet"},
		{"thunderbolt_bridge", "Thunderbolt Bridge", "hardware", "ethernet"},
		{"iphone_usb_port", "iPhone USB", "hardware", "usb_tether"},
		{"tunnel_class", "", "tunnel", "tunnel"},
		// The Windows adapter description reaches linkTypeFor as the port
		// name, and a wired word in it wins over the tunnel class.
		{"ethernet_word_wins_over_tunnel_class", "SSL VPN Virtual Ethernet Adapter", "tunnel", "ethernet"},
		{"no_port_no_class", "", "", "unknown"},
		{"unknown_port", "Bluetooth PAN", "hardware", "unknown"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := linkTypeFor(tt.hardwarePort, tt.class); got != tt.want {
				t.Fatalf("linkTypeFor(%q, %q) = %q, want %q", tt.hardwarePort, tt.class, got, tt.want)
			}
		})
	}
}

func Test_buildNetworkSnapshot_tetheredWiFiHotspot(t *testing.T) {
	state := snapshotTestState("en0", snapshotTestInterface{"en0", true, []string{"172.20.10.2/28"}})
	state.HaveV4 = true

	snapshot := buildNetworkSnapshot(snapshotInputs{
		State:   state,
		RouteV4: defaultRoute{Gateway: "172.20.10.1", Interface: "en0"},
		Meta:    snapshotTestMeta(map[string]interfaceMeta{"en0": {Class: "hardware", HardwarePort: "Wi-Fi", Service: "Wi-Fi"}}),
	})

	if !snapshot.Tethered {
		t.Error("tethered = false, want true for the hotspot gateway")
	}
	if snapshot.LinkType != "wifi" {
		t.Errorf("link_type = %q, want %q", snapshot.LinkType, "wifi")
	}
	if snapshot.DefaultRouteV4 != "en0" || snapshot.DefaultRouteV6 != "" {
		t.Errorf("default routes = %q/%q, want en0 and empty", snapshot.DefaultRouteV4, snapshot.DefaultRouteV6)
	}
	if !snapshot.HaveV4 || snapshot.HaveV6 {
		t.Errorf("have_v4/have_v6 = %v/%v, want true/false", snapshot.HaveV4, snapshot.HaveV6)
	}
	want := []snapshotInterface{{Name: "en0", Class: "hardware", Up: true, IPs: []string{"172.20.10.2/28"}, HardwarePort: "Wi-Fi", Service: "Wi-Fi"}}
	if !slices.EqualFunc(snapshot.Interfaces, want, sameSnapshotInterface) {
		t.Errorf("interfaces = %+v, want %+v", snapshot.Interfaces, want)
	}
}

func Test_buildNetworkSnapshot_usbTether(t *testing.T) {
	state := snapshotTestState("en7", snapshotTestInterface{"en7", true, []string{"172.20.10.3/28"}})

	snapshot := buildNetworkSnapshot(snapshotInputs{
		State: state,
		Meta:  snapshotTestMeta(map[string]interfaceMeta{"en7": {Class: "hardware", HardwarePort: "iPhone USB", Service: "iPhone USB"}}),
	})

	if snapshot.LinkType != "usb_tether" {
		t.Errorf("link_type = %q, want %q", snapshot.LinkType, "usb_tether")
	}
	if !snapshot.Tethered {
		t.Error("tethered = false, want true for the iPhone USB port")
	}
}

func Test_buildNetworkSnapshot_tunnelDefaultRoute(t *testing.T) {
	state := snapshotTestState("utun3", snapshotTestInterface{"utun3", true, []string{"100.64.0.2/32"}})

	snapshot := buildNetworkSnapshot(snapshotInputs{
		State: state,
		Meta:  snapshotTestMeta(map[string]interfaceMeta{"utun3": {Class: "tunnel"}}),
	})

	if snapshot.LinkType != "tunnel" {
		t.Errorf("link_type = %q, want %q", snapshot.LinkType, "tunnel")
	}
	if snapshot.Tethered {
		t.Error("tethered = true, want false without a hotspot gateway")
	}
}

// Test_buildNetworkSnapshot_defaultRouteV4WithoutARouteTable covers the
// platforms that read no route table. The v4 route falls back to the interface
// of the network monitor, and that interface must hold a usable v4 address.
func Test_buildNetworkSnapshot_defaultRouteV4WithoutARouteTable(t *testing.T) {
	for _, tt := range []struct {
		name     string
		ips      []string
		wantV4   string
		otherIPs []string
	}{
		{name: "dual_stack", ips: []string{"192.0.2.10/24", "2001:db8::10/64"}, wantV4: "en0"},
		{name: "v4_only", ips: []string{"192.0.2.10/24", "fe80::1/64"}, wantV4: "en0"},
		{name: "v6_only", ips: []string{"2001:db8::10/64"}},
		{name: "link_local_only", ips: []string{"169.254.1.2/16", "fe80::1/64"}},
		{name: "loopback_only", ips: []string{"127.0.0.1/8"}},
		{name: "address_on_another_interface", ips: nil, otherIPs: []string{"192.0.2.20/24", "2001:db8::20/64"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			state := snapshotTestState("en0",
				snapshotTestInterface{"en0", true, tt.ips},
				snapshotTestInterface{"en1", true, tt.otherIPs})

			snapshot := buildNetworkSnapshot(snapshotInputs{State: state})

			if snapshot.DefaultRouteV4 != tt.wantV4 {
				t.Errorf("default_route_v4 = %q, want %q", snapshot.DefaultRouteV4, tt.wantV4)
			}
			if snapshot.DefaultRouteV6 != "" {
				t.Errorf("default_route_v6 = %q, want an empty value without a route table", snapshot.DefaultRouteV6)
			}
		})
	}
}

// Test_buildNetworkSnapshot_defaultRoutesComeFromTheRouteTable covers a host
// whose v6 default route leaves over a tunnel. The v6 route must name that
// tunnel, not the interface of the v4 route.
func Test_buildNetworkSnapshot_defaultRoutesComeFromTheRouteTable(t *testing.T) {
	state := snapshotTestState("en0",
		snapshotTestInterface{"en0", true, []string{"192.0.2.10/24", "2001:db8::10/64"}},
		snapshotTestInterface{"utun4", true, []string{"2001:db8:1::2/64"}})

	snapshot := buildNetworkSnapshot(snapshotInputs{
		State:   state,
		RouteV4: defaultRoute{Gateway: "192.0.2.1", Interface: "en0"},
		RouteV6: defaultRoute{Gateway: "fe80::1%utun4", Interface: "utun4"},
	})

	if snapshot.DefaultRouteV4 != "en0" || snapshot.DefaultRouteV6 != "utun4" {
		t.Errorf("default routes = %q/%q, want en0 and utun4", snapshot.DefaultRouteV4, snapshot.DefaultRouteV6)
	}
	if snapshot.GatewayV4 != "192.0.2.1" || snapshot.GatewayV6 != "fe80::1%utun4" {
		t.Errorf("gateways = %q/%q, want the gateways of the route table", snapshot.GatewayV4, snapshot.GatewayV6)
	}
}

func Test_buildNetworkSnapshot_sortsInterfacesAndTakesMeta(t *testing.T) {
	state := snapshotTestState("en0",
		snapshotTestInterface{"en1", false, []string{"192.0.2.11/24"}},
		snapshotTestInterface{"awdl0", true, []string{"fe80::2/64"}},
		snapshotTestInterface{"en0", true, []string{"192.0.2.10/24"}})

	snapshot := buildNetworkSnapshot(snapshotInputs{
		State: state,
		Meta: snapshotTestMeta(map[string]interfaceMeta{
			"en0":   {Class: "hardware", HardwarePort: "Wi-Fi", Service: "Wi-Fi"},
			"awdl0": {Class: "airdrop"},
			"en1":   {Class: "hardware", HardwarePort: "Ethernet", Service: "Ethernet"},
		}),
	})

	want := []snapshotInterface{
		{Name: "awdl0", Class: "airdrop", Up: true, IPs: []string{"fe80::2/64"}},
		{Name: "en0", Class: "hardware", Up: true, IPs: []string{"192.0.2.10/24"}, HardwarePort: "Wi-Fi", Service: "Wi-Fi"},
		{Name: "en1", Class: "hardware", Up: false, IPs: []string{"192.0.2.11/24"}, HardwarePort: "Ethernet", Service: "Ethernet"},
	}
	if !slices.EqualFunc(snapshot.Interfaces, want, sameSnapshotInterface) {
		t.Fatalf("interfaces = %+v, want %+v", snapshot.Interfaces, want)
	}
}

// Test_buildNetworkSnapshot_capsTheInterfaceList covers a container host. Such
// a host holds hundreds of interfaces, and a snapshot of all of them fills the
// journal.
func Test_buildNetworkSnapshot_capsTheInterfaceList(t *testing.T) {
	interfaces := make([]snapshotTestInterface, 0, 40)
	for i := range 36 {
		interfaces = append(interfaces, snapshotTestInterface{fmt.Sprintf("veth%02d", i), true, nil})
	}
	for i := range 4 {
		interfaces = append(interfaces, snapshotTestInterface{fmt.Sprintf("down%d", i), false, nil})
	}
	state := snapshotTestState("veth00", interfaces...)

	snapshot := buildNetworkSnapshot(snapshotInputs{State: state})

	if len(snapshot.Interfaces) != snapshotInterfaceLimit {
		t.Fatalf("interfaces = %d entries, want %d", len(snapshot.Interfaces), snapshotInterfaceLimit)
	}
	if snapshot.InterfacesOmitted != 8 {
		t.Errorf("interfaces_omitted = %d, want 8", snapshot.InterfacesOmitted)
	}
	if first, last := snapshot.Interfaces[0].Name, snapshot.Interfaces[snapshotInterfaceLimit-1].Name; first != "veth00" || last != "veth31" {
		t.Errorf("interfaces run from %q to %q, want veth00 to veth31", first, last)
	}
}

// Test_buildNetworkSnapshot_keepsUpOrAddressedInterfaces covers the rule that
// selects the interfaces of the list.
func Test_buildNetworkSnapshot_keepsUpOrAddressedInterfaces(t *testing.T) {
	state := snapshotTestState("en0",
		snapshotTestInterface{"en0", true, []string{"192.0.2.10/24"}},
		snapshotTestInterface{"en1", true, nil},
		snapshotTestInterface{"en2", false, []string{"192.0.2.20/24"}},
		snapshotTestInterface{"en3", false, nil})

	snapshot := buildNetworkSnapshot(snapshotInputs{State: state})

	var names []string
	for _, iface := range snapshot.Interfaces {
		names = append(names, iface.Name)
	}
	if !slices.Equal(names, []string{"en0", "en1", "en2"}) {
		t.Errorf("interfaces = %v, want en0, en1, and en2", names)
	}
	if snapshot.InterfacesOmitted != 1 {
		t.Errorf("interfaces_omitted = %d, want 1", snapshot.InterfacesOmitted)
	}
}

func Test_buildNetworkSnapshot_classesByNameWithoutMeta(t *testing.T) {
	state := snapshotTestState("utun3",
		snapshotTestInterface{"utun3", true, []string{"100.64.0.2/32"}},
		snapshotTestInterface{"en0", true, []string{"192.0.2.10/24"}})

	snapshot := buildNetworkSnapshot(snapshotInputs{State: state})

	classes := map[string]string{}
	for _, iface := range snapshot.Interfaces {
		classes[iface.Name] = iface.Class
	}
	if classes["utun3"] != "tunnel" || classes["en0"] != "hardware" {
		t.Fatalf("classes = %v, want utun3 tunnel and en0 hardware", classes)
	}
	if snapshot.LinkType != "tunnel" {
		t.Errorf("link_type = %q, want %q", snapshot.LinkType, "tunnel")
	}
}

func Test_buildNetworkSnapshot_fillsTheEmptyClassOfTheMeta(t *testing.T) {
	state := snapshotTestState("utun3",
		snapshotTestInterface{"utun3", true, []string{"100.64.0.2/32"}},
		snapshotTestInterface{"awdl0", true, []string{"fe80::2/64"}})

	snapshot := buildNetworkSnapshot(snapshotInputs{
		State: state,
		Meta:  snapshotTestMeta(map[string]interfaceMeta{"utun3": {HardwarePort: ""}}),
	})

	classes := map[string]string{}
	for _, iface := range snapshot.Interfaces {
		classes[iface.Name] = iface.Class
	}
	if classes["utun3"] != "tunnel" || classes["awdl0"] != "airdrop" {
		t.Fatalf("classes = %v, want utun3 tunnel and awdl0 airdrop", classes)
	}
	if snapshot.LinkType != "tunnel" {
		t.Errorf("link_type = %q, want %q", snapshot.LinkType, "tunnel")
	}
}

func Test_buildNetworkSnapshot_nilStateKeepsFlags(t *testing.T) {
	snapshot := buildNetworkSnapshot(snapshotInputs{
		RouteV4:         defaultRoute{Gateway: "192.168.1.1"},
		RouteV6:         defaultRoute{Gateway: "fe80::1"},
		Resolvers:       []string{"192.168.1.1:53"},
		SourceIPv4:      "192.168.1.20",
		SourceIPv6:      "2001:db8::20",
		InterceptTarget: "127.0.0.1",
		BypassActive:    true,
		RecoveryRunning: true,
		PFStabilizing:   true,
		NAT64Prefix:     "64:ff9b::/96",
		CLATPresent:     true,
	})

	if len(snapshot.Interfaces) != 0 {
		t.Errorf("interfaces = %+v, want none", snapshot.Interfaces)
	}
	if snapshot.DefaultRouteV4 != "" || snapshot.DefaultRouteV6 != "" || snapshot.HaveV4 || snapshot.HaveV6 {
		t.Errorf("state fields are set without a state: %+v", snapshot)
	}
	if snapshot.LinkType != "unknown" {
		t.Errorf("link_type = %q, want %q", snapshot.LinkType, "unknown")
	}
	if !snapshot.BypassActive || !snapshot.RecoveryRunning || !snapshot.PFStabilizing || !snapshot.CLATPresent {
		t.Errorf("flags dropped: %+v", snapshot)
	}
	if !snapshot.DNSLessTarget {
		t.Error("dns_less_target = false, want true with an intercept target")
	}
	if snapshot.GatewayV4 != "192.168.1.1" || snapshot.GatewayV6 != "fe80::1" {
		t.Errorf("gateways = %q/%q, want the input values", snapshot.GatewayV4, snapshot.GatewayV6)
	}
	if snapshot.SourceIPv4 != "192.168.1.20" || snapshot.SourceIPv6 != "2001:db8::20" {
		t.Errorf("sources = %q/%q, want the input values", snapshot.SourceIPv4, snapshot.SourceIPv6)
	}
	if snapshot.NAT64Prefix != "64:ff9b::/96" || !slices.Equal(snapshot.Resolvers, []string{"192.168.1.1:53"}) {
		t.Errorf("prefix and resolvers dropped: %+v", snapshot)
	}
}

func Test_buildNetworkSnapshot_noInterceptTargetIsNotDNSLess(t *testing.T) {
	snapshot := buildNetworkSnapshot(snapshotInputs{State: snapshotTestState("en0", snapshotTestInterface{"en0", true, nil})})
	if snapshot.DNSLessTarget {
		t.Error("dns_less_target = true, want false without an intercept target")
	}
}

// snapshotDictKeys are the field names that spec R2.2 names for the snapshot,
// plus the count of the interfaces that the list leaves out.
var snapshotDictKeys = []string{
	"default_route_v4", "default_route_v6", "gateway_v4", "gateway_v6",
	"have_v4", "have_v6", "interfaces", "interfaces_omitted", "resolvers",
	"source_ipv4", "source_ipv6", "intercept_target", "bypass_active",
	"recovery_running", "pf_stabilizing", "link_type", "tethered",
	"clat_present", "nat64_prefix", "dns_less_target",
}

var snapshotInterfaceDictKeys = []string{"class", "hardware_port", "ips", "name", "service", "up"}

// renderSnapshotDict writes the dict under one field and parses the line, so
// the test reads the keys that a reader of the journal sees.
func renderSnapshotDict(t *testing.T, snapshot networkSnapshot) (string, map[string]any) {
	t.Helper()
	buf := &syncBuffer{}
	newTestJSONLogger(buf).Info().Dict("network", snapshotDict(snapshot)).Msg("Network snapshot")

	line := strings.TrimSpace(buf.String())
	event := map[string]any{}
	if err := json.Unmarshal([]byte(line), &event); err != nil {
		t.Fatalf("log line is not JSON: %q: %v", line, err)
	}
	network, ok := event["network"].(map[string]any)
	if !ok {
		t.Fatalf("line has no network object: %q", line)
	}
	return line, network
}

func Test_snapshotDict_rendersEveryKeyOnce(t *testing.T) {
	line, network := renderSnapshotDict(t, buildNetworkSnapshot(snapshotInputs{}))

	if got := sortedKeys(network); !slices.Equal(got, slices.Sorted(slices.Values(snapshotDictKeys))) {
		t.Fatalf("keys = %v, want %v", got, snapshotDictKeys)
	}
	for _, key := range snapshotDictKeys {
		if count := strings.Count(line, `"`+key+`":`); count != 1 {
			t.Errorf("key %q appears %d times, want 1: %s", key, count, line)
		}
	}
	if network["interfaces"] == nil || len(network["interfaces"].([]any)) != 0 {
		t.Errorf("interfaces = %v, want an empty array", network["interfaces"])
	}
	if network["resolvers"] == nil || len(network["resolvers"].([]any)) != 0 {
		t.Errorf("resolvers = %v, want an empty array", network["resolvers"])
	}
}

func Test_snapshotDict_rendersSortedInterfaces(t *testing.T) {
	state := snapshotTestState("en0",
		snapshotTestInterface{"en1", true, nil},
		snapshotTestInterface{"awdl0", true, []string{"fe80::2/64"}},
		snapshotTestInterface{"en0", true, []string{"192.0.2.10/24"}})

	snapshot := buildNetworkSnapshot(snapshotInputs{
		State:     state,
		RouteV4:   defaultRoute{Gateway: "192.0.2.1", Interface: "en0"},
		Resolvers: []string{"192.0.2.1:53"},
		Meta:      snapshotTestMeta(map[string]interfaceMeta{"en0": {Class: "hardware", HardwarePort: "Wi-Fi", Service: "Wi-Fi"}}),
	})
	_, network := renderSnapshotDict(t, snapshot)

	interfaces, ok := network["interfaces"].([]any)
	if !ok || len(interfaces) != 3 {
		t.Fatalf("interfaces = %v, want three entries", network["interfaces"])
	}
	var names []string
	for _, entry := range interfaces {
		object, ok := entry.(map[string]any)
		if !ok {
			t.Fatalf("interface entry is not an object: %v", entry)
		}
		if got := sortedKeys(object); !slices.Equal(got, snapshotInterfaceDictKeys) {
			t.Fatalf("interface keys = %v, want %v", got, snapshotInterfaceDictKeys)
		}
		names = append(names, object["name"].(string))
	}
	if !slices.Equal(names, []string{"awdl0", "en0", "en1"}) {
		t.Errorf("interface order = %v, want awdl0, en0, en1", names)
	}
	if ips, ok := interfaces[2].(map[string]any)["ips"].([]any); !ok || len(ips) != 0 {
		t.Errorf("ips of en1 = %v, want an empty array", interfaces[2].(map[string]any)["ips"])
	}
	wantValues := map[string]any{"gateway_v4": "192.0.2.1", "link_type": "wifi", "default_route_v4": "en0", "tethered": false}
	for key, want := range wantValues {
		wantField(t, network, key, want)
	}
	if resolvers, ok := network["resolvers"].([]any); !ok || len(resolvers) != 1 || resolvers[0] != "192.0.2.1:53" {
		t.Errorf("resolvers = %v, want one entry", network["resolvers"])
	}
}

func Test_defaultRoutes_returnAddressesOrNothing(t *testing.T) {
	v4, v6 := defaultRoutes()
	// A host without a route of a family gives an empty value, so the test
	// logs the pair and holds every value it gets to the format.
	t.Logf("default routes: v4 %+v, v6 %+v", v4, v6)

	if v4.Gateway != "" {
		address, err := netip.ParseAddr(v4.Gateway)
		if err != nil || !address.Is4() {
			t.Errorf("gateway_v4 = %q, want an IPv4 address or nothing: %v", v4.Gateway, err)
		}
	}
	if v6.Gateway != "" {
		address, err := netip.ParseAddr(v6.Gateway)
		if err != nil || !address.Is6() {
			t.Errorf("gateway_v6 = %q, want an IPv6 address or nothing: %v", v6.Gateway, err)
		}
	}
	// A tunnel default has no next hop, so an interface without a gateway is a
	// valid pair. A gateway without an interface is not.
	if v4.Gateway != "" && v4.Interface == "" {
		t.Errorf("gateway_v4 = %q without an interface, want the interface of the route", v4.Gateway)
	}
	if v6.Gateway != "" && v6.Interface == "" {
		t.Errorf("gateway_v6 = %q without an interface, want the interface of the route", v6.Gateway)
	}
}

func sameSnapshotInterface(a, b snapshotInterface) bool {
	return a.Name == b.Name && a.Class == b.Class && a.Up == b.Up &&
		a.HardwarePort == b.HardwarePort && a.Service == b.Service &&
		slices.Equal(a.IPs, b.IPs)
}

func sortedKeys(object map[string]any) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
