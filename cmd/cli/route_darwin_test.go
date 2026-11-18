package cli

import (
	"net/netip"
	"syscall"
	"testing"

	"golang.org/x/net/route"
)

// stubRouteInterfaceNames names the interface of each index, because the
// interfaces of the host are not a fixture.
func stubRouteInterfaceNames(t *testing.T, names map[int]string) {
	t.Helper()
	orig := routeInterfaceNameFn
	t.Cleanup(func() { routeInterfaceNameFn = orig })
	routeInterfaceNameFn = func(index int) string { return names[index] }
}

// routeAddrs puts one destination, one netmask, and one gateway at the places
// of the route message that the kernel uses. A nil netmask leaves the slot
// empty, the shape of a host route.
func routeAddrs(destination, netmask, gateway route.Addr) []route.Addr {
	addrs := make([]route.Addr, syscall.RTAX_NETMASK+1)
	addrs[syscall.RTAX_DST] = destination
	addrs[syscall.RTAX_GATEWAY] = gateway
	addrs[syscall.RTAX_NETMASK] = netmask
	return addrs
}

func inet4(a, b, c, d byte) *route.Inet4Addr {
	return &route.Inet4Addr{IP: [4]byte{a, b, c, d}}
}

func inet6(address string, zoneID int) *route.Inet6Addr {
	addr := netip.MustParseAddr(address)
	return &route.Inet6Addr{IP: addr.As16(), ZoneID: zoneID}
}

func Test_defaultRouteGateway(t *testing.T) {
	stubRouteInterfaceNames(t, map[int]string{8: "utun4"})

	for _, tt := range []struct {
		name        string
		message     route.Message
		wantGateway string
		wantIndex   int
		wantOK      bool
	}{
		{
			name: "v4_gateway",
			message: &route.RouteMessage{
				Flags: syscall.RTF_GATEWAY,
				Index: 5,
				Addrs: routeAddrs(inet4(0, 0, 0, 0), inet4(0, 0, 0, 0), inet4(192, 168, 1, 1)),
			},
			wantGateway: "192.168.1.1",
			wantIndex:   5,
			wantOK:      true,
		},
		{
			name: "v6_link_local_gateway_with_a_zone",
			message: &route.RouteMessage{
				Flags: syscall.RTF_GATEWAY,
				Index: 8,
				Addrs: routeAddrs(inet6("::", 0), inet6("::", 0), inet6("fe80::1", 8)),
			},
			wantGateway: "fe80::1%utun4",
			wantIndex:   8,
			wantOK:      true,
		},
		{
			name: "destination_is_not_the_default_route",
			message: &route.RouteMessage{
				Flags: syscall.RTF_GATEWAY,
				Index: 5,
				Addrs: routeAddrs(inet4(192, 168, 1, 0), inet4(255, 255, 255, 0), inet4(192, 168, 1, 1)),
			},
		},
		{
			name: "gateway_names_a_link",
			message: &route.RouteMessage{
				Flags: syscall.RTF_GATEWAY,
				Index: 5,
				Addrs: routeAddrs(inet4(0, 0, 0, 0), inet4(0, 0, 0, 0), &route.LinkAddr{Index: 5, Name: "en0"}),
			},
		},
		{
			name: "gateway_family_differs_from_the_destination",
			message: &route.RouteMessage{
				Flags: syscall.RTF_GATEWAY,
				Index: 5,
				Addrs: routeAddrs(inet4(0, 0, 0, 0), inet4(0, 0, 0, 0), inet6("fe80::1", 8)),
			},
		},
		{
			name: "address_list_holds_no_gateway",
			message: &route.RouteMessage{
				Flags: syscall.RTF_GATEWAY,
				Index: 5,
				Addrs: []route.Addr{inet4(0, 0, 0, 0)},
			},
		},
		{
			name:    "message_is_not_a_route",
			message: &route.InterfaceMessage{Index: 5},
		},
		{
			name: "route_has_no_gateway_flag",
			message: &route.RouteMessage{
				Index: 5,
				Addrs: routeAddrs(inet4(0, 0, 0, 0), inet4(0, 0, 0, 0), inet4(192, 168, 1, 1)),
			},
		},
		{
			name: "route_is_bound_to_one_interface",
			message: &route.RouteMessage{
				Flags: syscall.RTF_GATEWAY | syscall.RTF_IFSCOPE,
				Index: 5,
				Addrs: routeAddrs(inet4(0, 0, 0, 0), inet4(0, 0, 0, 0), inet4(192, 168, 1, 1)),
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			gateway, index, ok := defaultRouteGateway(tt.message)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if gateway.String() != tt.wantGateway {
				t.Errorf("gateway = %q, want %q", gateway.String(), tt.wantGateway)
			}
			if index != tt.wantIndex {
				t.Errorf("index = %d, want %d", index, tt.wantIndex)
			}
		})
	}
}

// Test_defaultRoutesFromMessages covers the table of a host with a v4 default
// route and a v6 default route on another interface. The v6 route must not
// take the interface of the v4 route.
func Test_defaultRoutesFromMessages(t *testing.T) {
	stubRouteInterfaceNames(t, map[int]string{4: "en0", 8: "utun4"})

	v4, v6 := defaultRoutesFromMessages([]route.Message{
		&route.RouteMessage{
			Flags: syscall.RTF_GATEWAY | syscall.RTF_IFSCOPE,
			Index: 9,
			Addrs: routeAddrs(inet4(0, 0, 0, 0), inet4(0, 0, 0, 0), inet4(10, 0, 0, 1)),
		},
		&route.RouteMessage{
			Flags: syscall.RTF_GATEWAY,
			Index: 4,
			Addrs: routeAddrs(inet4(0, 0, 0, 0), inet4(0, 0, 0, 0), inet4(192, 168, 1, 1)),
		},
		&route.RouteMessage{
			Flags: syscall.RTF_GATEWAY,
			Index: 8,
			Addrs: routeAddrs(inet6("::", 0), inet6("::", 0), inet6("fe80::1", 8)),
		},
		&route.RouteMessage{
			Flags: syscall.RTF_GATEWAY,
			Index: 5,
			Addrs: routeAddrs(inet4(0, 0, 0, 0), inet4(0, 0, 0, 0), inet4(172, 16, 0, 1)),
		},
	})

	if want := (defaultRoute{Gateway: "192.168.1.1", Interface: "en0"}); v4 != want {
		t.Errorf("v4 route = %+v, want %+v", v4, want)
	}
	if want := (defaultRoute{Gateway: "fe80::1%utun4", Interface: "utun4"}); v6 != want {
		t.Errorf("v6 route = %+v, want %+v", v6, want)
	}
}

// Test_defaultRoutesFromMessagesWithoutADefaultRoute covers a table that holds
// no default route, for example a host with no link.
func Test_defaultRoutesFromMessagesWithoutADefaultRoute(t *testing.T) {
	stubRouteInterfaceNames(t, map[int]string{4: "en0"})

	v4, v6 := defaultRoutesFromMessages([]route.Message{
		&route.RouteMessage{
			Flags: syscall.RTF_GATEWAY,
			Index: 4,
			Addrs: routeAddrs(inet4(192, 168, 1, 0), inet4(255, 255, 255, 0), inet4(192, 168, 1, 1)),
		},
	})

	if v4 != (defaultRoute{}) || v6 != (defaultRoute{}) {
		t.Errorf("routes = %+v / %+v, want two empty routes", v4, v6)
	}
}

// Test_defaultRouteGatewayNeedsAZeroNetmask covers routes whose destination is
// the zero address but whose prefix is not /0. OpenVPN splits the default into
// two /1 routes, and a host route to 0.0.0.0 carries no mask at all.
func Test_defaultRouteGatewayNeedsAZeroNetmask(t *testing.T) {
	for _, tt := range []struct {
		name    string
		message route.Message
	}{
		{
			name: "half of the v4 space",
			message: &route.RouteMessage{
				Flags: syscall.RTF_GATEWAY,
				Index: 8,
				Addrs: routeAddrs(inet4(0, 0, 0, 0), inet4(128, 0, 0, 0), inet4(10, 8, 0, 1)),
			},
		},
		{
			name: "host route to the zero address",
			message: &route.RouteMessage{
				Flags: syscall.RTF_GATEWAY | syscall.RTF_HOST,
				Index: 8,
				Addrs: routeAddrs(inet4(0, 0, 0, 0), nil, inet4(10, 8, 0, 1)),
			},
		},
		{
			name: "one eighth of the v6 space",
			message: &route.RouteMessage{
				Flags: syscall.RTF_GATEWAY,
				Index: 8,
				Addrs: routeAddrs(inet6("::", 0), inet6("e000::", 0), inet6("fe80::1", 8)),
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if gateway, _, ok := defaultRouteGateway(tt.message); ok {
				t.Fatalf("a %s route counted as the default route with gateway %s", tt.name, gateway)
			}
		})
	}
	v4, _ := defaultRoutesFromMessages([]route.Message{&route.RouteMessage{
		Flags: syscall.RTF_GATEWAY,
		Index: 8,
		Addrs: routeAddrs(inet4(0, 0, 0, 0), inet4(128, 0, 0, 0), inet4(10, 8, 0, 1)),
	}})
	if v4.Gateway != "" || v4.Interface != "" {
		t.Fatalf("a table with one /1 route reported the default route %+v, want none", v4)
	}
}

// Test_defaultRoutesTakeALinkDefault covers a VPN that owns the default
// route. Its default has no next hop: the gateway is the link itself and the
// gateway flag is off. The snapshot must name that interface, with an empty
// gateway, instead of the interface of the network monitor.
func Test_defaultRoutesTakeALinkDefault(t *testing.T) {
	stubRouteInterfaceNames(t, map[int]string{28: "utun4", 16: "en0"})
	linkDefault := &route.RouteMessage{
		Flags: syscall.RTF_UP | syscall.RTF_STATIC,
		Index: 28,
		Addrs: routeAddrs(inet4(0, 0, 0, 0), inet4(0, 0, 0, 0), &route.LinkAddr{Index: 28, Name: "utun4"}),
	}
	scopedEn0 := &route.RouteMessage{
		Flags: syscall.RTF_UP | syscall.RTF_GATEWAY | syscall.RTF_IFSCOPE,
		Index: 16,
		Addrs: routeAddrs(inet4(0, 0, 0, 0), inet4(0, 0, 0, 0), inet4(192, 168, 50, 1)),
	}

	v4, _ := defaultRoutesFromMessages([]route.Message{linkDefault, scopedEn0})
	if v4.Interface != "utun4" || v4.Gateway != "" {
		t.Fatalf("default route = %+v, want utun4 with no gateway", v4)
	}
}

// Test_defaultRouteGatewaySkipsRejectAndBlackholeRoutes covers a kill switch
// that installs a default route to nowhere. Such a route carries the gateway
// flag, but it delivers nothing, so it is not the default route of the host.
func Test_defaultRouteGatewaySkipsRejectAndBlackholeRoutes(t *testing.T) {
	for _, tt := range []struct {
		name  string
		flags int
	}{
		{"reject", syscall.RTF_UP | syscall.RTF_GATEWAY | syscall.RTF_REJECT},
		{"blackhole", syscall.RTF_UP | syscall.RTF_GATEWAY | syscall.RTF_BLACKHOLE},
	} {
		t.Run(tt.name, func(t *testing.T) {
			message := &route.RouteMessage{
				Flags: tt.flags,
				Index: 8,
				Addrs: routeAddrs(inet4(0, 0, 0, 0), inet4(0, 0, 0, 0), inet4(10, 8, 0, 1)),
			}
			if gateway, _, ok := defaultRouteGateway(message); ok {
				t.Fatalf("a %s route counted as the default route with gateway %s", tt.name, gateway)
			}
		})
	}
}
