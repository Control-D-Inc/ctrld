package cli

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/Control-D-Inc/ctrld"
	"tailscale.com/net/netmon"
)

// deltaTestInterface describes one interface of a test network state.
type deltaTestInterface struct {
	name string
	up   bool
	mac  string
	mtu  int
	ips  []string
}

var (
	deltaTestUpFlags   = net.FlagUp | net.FlagBroadcast | net.FlagMulticast
	deltaTestDownFlags = net.Flags(0)
)

func deltaTestState(t *testing.T, route string, ifaces ...deltaTestInterface) *netmon.State {
	t.Helper()
	state := &netmon.State{
		DefaultRouteInterface: route,
		Interface:             map[string]netmon.Interface{},
		InterfaceIPs:          map[string][]netip.Prefix{},
	}
	for _, iface := range ifaces {
		flags := deltaTestDownFlags
		if iface.up {
			flags = deltaTestUpFlags
		}
		var mac net.HardwareAddr
		if iface.mac != "" {
			parsed, err := net.ParseMAC(iface.mac)
			if err != nil {
				t.Fatalf("ParseMAC(%q) error: %v", iface.mac, err)
			}
			mac = parsed
		}
		state.Interface[iface.name] = netmon.Interface{Interface: &net.Interface{
			Name:         iface.name,
			Flags:        flags,
			MTU:          iface.mtu,
			HardwareAddr: mac,
		}}
		for _, ip := range iface.ips {
			state.InterfaceIPs[iface.name] = append(state.InterfaceIPs[iface.name], netip.MustParsePrefix(ip))
		}
	}
	return state
}

func sameInterfaceChange(got, want interfaceChange) bool {
	return got.Name == want.Name &&
		got.Action == want.Action &&
		got.Class == want.Class &&
		got.HardwarePort == want.HardwarePort &&
		got.Service == want.Service &&
		slices.Equal(got.IPsBefore, want.IPsBefore) &&
		slices.Equal(got.IPsAfter, want.IPsAfter) &&
		got.Flags == want.Flags &&
		got.MTU == want.MTU &&
		got.IsDefaultRoute == want.IsDefaultRoute
}

func assertInterfaceChanges(t *testing.T, got, want []interfaceChange) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("changes = %+v, want %+v", got, want)
	}
	for i := range want {
		if !sameInterfaceChange(got[i], want[i]) {
			t.Errorf("change %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func Test_diffNetworkDelta(t *testing.T) {
	en0 := deltaTestInterface{name: "en0", up: true, mac: "aa:bb:cc:dd:ee:01", mtu: 1500, ips: []string{"192.0.2.10/24"}}
	awdl0 := deltaTestInterface{name: "awdl0", up: true, mac: "aa:bb:cc:dd:ee:02", mtu: 1484, ips: []string{"fe80::1/64"}}
	awdl0NewMAC := deltaTestInterface{name: "awdl0", up: true, mac: "aa:bb:cc:dd:ee:03", mtu: 1484, ips: []string{"fe80::1/64"}}
	en5 := deltaTestInterface{name: "en5", up: true, mac: "aa:bb:cc:dd:ee:05", mtu: 1500, ips: []string{"192.0.2.50/24"}}

	for _, tt := range []struct {
		name      string
		routeOld  string
		routeNew  string
		nilBefore bool
		before    []deltaTestInterface
		after     []deltaTestInterface
		meta      interfaceMetaFunc
		want      []interfaceChange
	}{
		{
			name:     "airdrop_mac_change_with_link_local_only",
			routeOld: "en0", routeNew: "en0",
			before: []deltaTestInterface{en0, awdl0},
			after:  []deltaTestInterface{en0, awdl0NewMAC},
			want: []interfaceChange{{
				Name: "awdl0", Action: "mac_changed", Class: "airdrop",
				IPsBefore: []string{"fe80::1/64"}, IPsAfter: []string{"fe80::1/64"},
				Flags: deltaTestUpFlags.String(), MTU: 1484,
			}},
		},
		{
			name:     "airdrop_mac_and_link_local_change",
			routeOld: "en0", routeNew: "en0",
			before: []deltaTestInterface{en0, awdl0},
			after: []deltaTestInterface{en0, {
				name: "awdl0", up: true, mac: "aa:bb:cc:dd:ee:03", mtu: 1484, ips: []string{"fe80::2/64"},
			}},
			want: []interfaceChange{{
				Name: "awdl0", Action: "ip_removed", Class: "airdrop",
				IPsBefore: []string{"fe80::1/64"}, IPsAfter: []string{"fe80::2/64"},
				Flags: deltaTestUpFlags.String(), MTU: 1484,
			}},
		},
		{
			name:     "hardware_address_added_with_airdrop_change",
			routeOld: "en0", routeNew: "en0",
			before: []deltaTestInterface{en0, awdl0},
			after: []deltaTestInterface{{
				name: "en0", up: true, mac: "aa:bb:cc:dd:ee:01", mtu: 1500,
				ips: []string{"192.0.2.10/24", "192.0.2.11/24"},
			}, awdl0NewMAC},
			want: []interfaceChange{
				{
					Name: "awdl0", Action: "mac_changed", Class: "airdrop",
					IPsBefore: []string{"fe80::1/64"}, IPsAfter: []string{"fe80::1/64"},
					Flags: deltaTestUpFlags.String(), MTU: 1484,
				},
				{
					Name: "en0", Action: "ip_added", Class: "hardware",
					IPsBefore: []string{"192.0.2.10/24"}, IPsAfter: []string{"192.0.2.10/24", "192.0.2.11/24"},
					Flags: deltaTestUpFlags.String(), MTU: 1500, IsDefaultRoute: true,
				},
			},
		},
		{
			name:     "interface_removed",
			routeOld: "en0", routeNew: "en0",
			before: []deltaTestInterface{en0, en5},
			after:  []deltaTestInterface{en0},
			want: []interfaceChange{{
				Name: "en5", Action: "removed", Class: "hardware",
				IPsBefore: []string{"192.0.2.50/24"}, IPsAfter: nil,
				Flags: deltaTestUpFlags.String(), MTU: 1500,
			}},
		},
		{
			name:     "interface_added",
			routeOld: "en0", routeNew: "en0",
			before: []deltaTestInterface{en0},
			after:  []deltaTestInterface{en0, en5},
			want: []interfaceChange{{
				Name: "en5", Action: "added", Class: "hardware",
				IPsBefore: nil, IPsAfter: []string{"192.0.2.50/24"},
				Flags: deltaTestUpFlags.String(), MTU: 1500,
			}},
		},
		{
			name:     "address_removed",
			routeOld: "en0", routeNew: "en0",
			before: []deltaTestInterface{{
				name: "en0", up: true, mac: "aa:bb:cc:dd:ee:01", mtu: 1500,
				ips: []string{"192.0.2.10/24", "192.0.2.11/24"},
			}},
			after: []deltaTestInterface{en0},
			want: []interfaceChange{{
				Name: "en0", Action: "ip_removed", Class: "hardware",
				IPsBefore: []string{"192.0.2.10/24", "192.0.2.11/24"}, IPsAfter: []string{"192.0.2.10/24"},
				Flags: deltaTestUpFlags.String(), MTU: 1500, IsDefaultRoute: true,
			}},
		},
		{
			name:     "interface_down",
			routeOld: "en0", routeNew: "en0",
			before: []deltaTestInterface{en0},
			after: []deltaTestInterface{{
				name: "en0", up: false, mac: "aa:bb:cc:dd:ee:01", mtu: 1500, ips: []string{"192.0.2.10/24"},
			}},
			want: []interfaceChange{{
				Name: "en0", Action: "down", Class: "hardware",
				IPsBefore: []string{"192.0.2.10/24"}, IPsAfter: []string{"192.0.2.10/24"},
				Flags: deltaTestDownFlags.String(), MTU: 1500, IsDefaultRoute: true,
			}},
		},
		{
			name:     "interface_up",
			routeOld: "en0", routeNew: "en0",
			before: []deltaTestInterface{{
				name: "en0", up: false, mac: "aa:bb:cc:dd:ee:01", mtu: 1500, ips: []string{"192.0.2.10/24"},
			}},
			after: []deltaTestInterface{en0},
			want: []interfaceChange{{
				Name: "en0", Action: "up", Class: "hardware",
				IPsBefore: []string{"192.0.2.10/24"}, IPsAfter: []string{"192.0.2.10/24"},
				Flags: deltaTestUpFlags.String(), MTU: 1500, IsDefaultRoute: true,
			}},
		},
		{
			name:     "mtu_changed",
			routeOld: "en0", routeNew: "en0",
			before: []deltaTestInterface{en0},
			after: []deltaTestInterface{{
				name: "en0", up: true, mac: "aa:bb:cc:dd:ee:01", mtu: 1400, ips: []string{"192.0.2.10/24"},
			}},
			want: []interfaceChange{{
				Name: "en0", Action: "mtu_changed", Class: "hardware",
				IPsBefore: []string{"192.0.2.10/24"}, IPsAfter: []string{"192.0.2.10/24"},
				Flags: deltaTestUpFlags.String(), MTU: 1400, IsDefaultRoute: true,
			}},
		},
		{
			name:     "default_route_moves_to_the_new_interface",
			routeOld: "en0", routeNew: "en5",
			before: []deltaTestInterface{en0},
			after: []deltaTestInterface{{
				name: "en0", up: false, mac: "aa:bb:cc:dd:ee:01", mtu: 1500, ips: []string{"192.0.2.10/24"},
			}, en5},
			want: []interfaceChange{
				{
					Name: "en0", Action: "down", Class: "hardware",
					IPsBefore: []string{"192.0.2.10/24"}, IPsAfter: []string{"192.0.2.10/24"},
					Flags: deltaTestDownFlags.String(), MTU: 1500,
				},
				{
					Name: "en5", Action: "added", Class: "hardware",
					IPsBefore: nil, IPsAfter: []string{"192.0.2.50/24"},
					Flags: deltaTestUpFlags.String(), MTU: 1500, IsDefaultRoute: true,
				},
			},
		},
		{
			name:      "nil_old_state_adds_every_interface",
			routeNew:  "en0",
			nilBefore: true,
			after:     []deltaTestInterface{en0},
			want: []interfaceChange{{
				Name: "en0", Action: "added", Class: "hardware",
				IPsBefore: nil, IPsAfter: []string{"192.0.2.10/24"},
				Flags: deltaTestUpFlags.String(), MTU: 1500, IsDefaultRoute: true,
			}},
		},
		{
			name:     "no_change",
			routeOld: "en0", routeNew: "en0",
			before: []deltaTestInterface{en0, awdl0},
			after:  []deltaTestInterface{en0, awdl0},
			want:   nil,
		},
		{
			name:     "meta_fills_the_platform_fields",
			routeOld: "en0", routeNew: "en0",
			before: []deltaTestInterface{en0, {name: "utun3", up: true, mtu: 1400}},
			after: []deltaTestInterface{{
				name: "en0", up: true, mac: "aa:bb:cc:dd:ee:01", mtu: 1400, ips: []string{"192.0.2.10/24"},
			}, {name: "utun3", up: true, mtu: 1380}},
			meta: func(name string) interfaceMeta {
				if name == "utun3" {
					return interfaceMeta{Class: "virtual"}
				}
				return interfaceMeta{HardwarePort: "Wi-Fi", Service: "Wi-Fi"}
			},
			want: []interfaceChange{
				{
					Name: "en0", Action: "mtu_changed", Class: "hardware",
					HardwarePort: "Wi-Fi", Service: "Wi-Fi",
					IPsBefore: []string{"192.0.2.10/24"}, IPsAfter: []string{"192.0.2.10/24"},
					Flags: deltaTestUpFlags.String(), MTU: 1400, IsDefaultRoute: true,
				},
				{
					Name: "utun3", Action: "mtu_changed", Class: "virtual",
					Flags: deltaTestUpFlags.String(), MTU: 1380,
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var before *netmon.State
			if !tt.nilBefore {
				before = deltaTestState(t, tt.routeOld, tt.before...)
			}
			changes := diffNetworkDelta(before, deltaTestState(t, tt.routeNew, tt.after...))
			describeInterfaceChanges(changes, tt.meta)
			assertInterfaceChanges(t, changes, tt.want)
		})
	}
}

func Test_diffNetworkDeltaVirtualSet(t *testing.T) {
	virtual := virtualInterfaceSetFn
	t.Cleanup(func() { virtualInterfaceSetFn = virtual })
	virtualInterfaceSetFn = func() map[string]struct{} { return map[string]struct{}{"docker0": {}} }

	before := deltaTestState(t, "en0",
		deltaTestInterface{name: "en0", up: true, mtu: 1500, ips: []string{"192.0.2.10/24"}},
		deltaTestInterface{name: "docker0", up: true, mtu: 1500},
	)
	after := deltaTestState(t, "en0",
		deltaTestInterface{name: "en0", up: true, mtu: 1400, ips: []string{"192.0.2.10/24"}},
		deltaTestInterface{name: "docker0", up: true, mtu: 1400},
	)
	assertInterfaceChanges(t, diffNetworkDelta(before, after), []interfaceChange{
		{
			Name: "docker0", Action: "mtu_changed", Class: "virtual",
			Flags: deltaTestUpFlags.String(), MTU: 1400,
		},
		{
			Name: "en0", Action: "mtu_changed", Class: "hardware",
			IPsBefore: []string{"192.0.2.10/24"}, IPsAfter: []string{"192.0.2.10/24"},
			Flags: deltaTestUpFlags.String(), MTU: 1400, IsDefaultRoute: true,
		},
	})
}

func Test_interfaceClass(t *testing.T) {
	for _, tt := range []struct {
		name    string
		virtual bool
		want    string
	}{
		{name: "lo0", want: "loopback"},
		{name: "awdl0", want: "airdrop"},
		{name: "llw0", want: "airdrop"},
		{name: "utun3", want: "tunnel"},
		{name: "tun0", want: "tunnel"},
		{name: "tap0", want: "tunnel"},
		{name: "wg0", want: "tunnel"},
		{name: "ipsec0", want: "tunnel"},
		{name: "ppp0", want: "tunnel"},
		{name: "docker0", virtual: true, want: "virtual"},
		{name: "docker0", want: "hardware"},
		{name: "en0", want: "hardware"},
	} {
		t.Run(tt.name+"_"+tt.want, func(t *testing.T) {
			if got := interfaceClass(tt.name, tt.virtual); got != tt.want {
				t.Errorf("interfaceClass(%q, %v) = %q, want %q", tt.name, tt.virtual, got, tt.want)
			}
		})
	}
}

func Test_noiseDelta(t *testing.T) {
	en0 := deltaTestInterface{name: "en0", up: true, mac: "aa:bb:cc:dd:ee:01", mtu: 1500, ips: []string{"192.0.2.10/24"}}
	en5 := deltaTestInterface{name: "en5", up: true, mac: "aa:bb:cc:dd:ee:05", mtu: 1500, ips: []string{"192.0.2.50/24"}}
	awdl0 := deltaTestInterface{name: "awdl0", up: true, mac: "aa:bb:cc:dd:ee:02", mtu: 1484, ips: []string{"fe80::1/64"}}
	awdl0NewMAC := deltaTestInterface{name: "awdl0", up: true, mac: "aa:bb:cc:dd:ee:03", mtu: 1484, ips: []string{"fe80::1/64"}}
	en0Extra := deltaTestInterface{
		name: "en0", up: true, mac: "aa:bb:cc:dd:ee:01", mtu: 1500,
		ips: []string{"192.0.2.10/24", "192.0.2.11/24"},
	}

	docker0 := deltaTestInterface{name: "docker0", up: true, mtu: 1500}
	docker0NewMTU := deltaTestInterface{name: "docker0", up: true, mtu: 1400}

	for _, tt := range []struct {
		name               string
		routeOld           string
		routeNew           string
		before             []deltaTestInterface
		after              []deltaTestInterface
		virtual            []string
		timeJumped         bool
		beforeV4, beforeV6 bool
		afterV4, afterV6   bool
		source4            string
		want               bool
	}{
		{
			name:     "airdrop_only",
			routeOld: "en0", routeNew: "en0",
			before: []deltaTestInterface{en0, awdl0},
			after:  []deltaTestInterface{en0, awdl0NewMAC},
			want:   true,
		},
		{
			name:     "hardware_and_airdrop",
			routeOld: "en0", routeNew: "en0",
			before: []deltaTestInterface{en0, awdl0},
			after:  []deltaTestInterface{en0Extra, awdl0NewMAC},
			want:   false,
		},
		{
			name:     "no_change",
			routeOld: "en0", routeNew: "en0",
			before: []deltaTestInterface{en0, awdl0},
			after:  []deltaTestInterface{en0, awdl0},
			want:   false,
		},
		{
			name:     "default_route_moved",
			routeOld: "en0", routeNew: "en5",
			before: []deltaTestInterface{en0, en5, awdl0},
			after:  []deltaTestInterface{en0, en5, awdl0NewMAC},
			want:   false,
		},
		{
			name:     "virtual_only",
			routeOld: "en0", routeNew: "en0",
			before:  []deltaTestInterface{en0, docker0},
			after:   []deltaTestInterface{en0, docker0NewMTU},
			virtual: []string{"docker0"},
			want:    true,
		},
		{
			name:     "a_time_jump_is_never_noise",
			routeOld: "en0", routeNew: "en0",
			before:     []deltaTestInterface{en0, awdl0},
			after:      []deltaTestInterface{en0, awdl0NewMAC},
			timeJumped: true,
			want:       false,
		},
		{
			name:     "the_default_route_runs_over_a_virtual_interface",
			routeOld: "docker0", routeNew: "docker0",
			before:  []deltaTestInterface{en0, docker0},
			after:   []deltaTestInterface{en0, docker0NewMTU},
			virtual: []string{"docker0"},
			want:    false,
		},
		{
			name:     "a_virtual_interface_holds_a_routable_address",
			routeOld: "en0", routeNew: "en0",
			before:  []deltaTestInterface{en0, {name: "docker0", up: true, mtu: 1500, ips: []string{"172.17.0.1/16"}}},
			after:   []deltaTestInterface{en0, {name: "docker0", up: true, mtu: 1400, ips: []string{"172.17.0.1/16"}}},
			virtual: []string{"docker0"},
			want:    false,
		},
		{
			name:     "an_airdrop_interface_holds_the_resolver_source",
			routeOld: "en0", routeNew: "en0",
			before:  []deltaTestInterface{en0, {name: "awdl0", up: true, mtu: 1484, ips: []string{"169.254.10.5/16"}}},
			after:   []deltaTestInterface{en0, {name: "awdl0", up: true, mtu: 1400, ips: []string{"169.254.10.5/16"}}},
			source4: "169.254.10.5",
			want:    false,
		},
		{
			name:     "have_v4_flips",
			routeOld: "en0", routeNew: "en0",
			before:   []deltaTestInterface{en0, awdl0},
			after:    []deltaTestInterface{en0, awdl0NewMAC},
			beforeV4: true,
			want:     false,
		},
		{
			name:     "have_v6_flips",
			routeOld: "en0", routeNew: "en0",
			before:  []deltaTestInterface{en0, awdl0},
			after:   []deltaTestInterface{en0, awdl0NewMAC},
			afterV6: true,
			want:    false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			stubSnapshotVirtualSet(t, tt.virtual...)
			stubResolverSource(t, tt.source4)
			before := deltaTestState(t, tt.routeOld, tt.before...)
			after := deltaTestState(t, tt.routeNew, tt.after...)
			before.HaveV4, before.HaveV6 = tt.beforeV4, tt.beforeV6
			after.HaveV4, after.HaveV6 = tt.afterV4, tt.afterV6
			changes := diffNetworkDelta(before, after)
			if got := noiseDelta(before, after, tt.timeJumped, changes); got != tt.want {
				t.Errorf("noiseDelta = %v, want %v, changes %+v", got, tt.want, changes)
			}
		})
	}
}

// stubResolverSource sets the address that the resolver sends its queries
// from. The tests own that global, so each case starts from a known source.
func stubResolverSource(t *testing.T, source4 string) {
	t.Helper()
	original4, original6 := ctrld.GetDefaultLocalIPv4(), ctrld.GetDefaultLocalIPv6()
	t.Cleanup(func() {
		ctrld.SetDefaultLocalIPv4(context.Background(), original4)
		ctrld.SetDefaultLocalIPv6(context.Background(), original6)
	})
	ctrld.SetDefaultLocalIPv4(context.Background(), net.ParseIP(source4))
	ctrld.SetDefaultLocalIPv6(context.Background(), nil)
}
