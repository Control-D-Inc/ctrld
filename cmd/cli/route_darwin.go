package cli

import (
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/net/route"
)

// routeInterfaceNameFn names the interface of one route table index. A test
// replaces it, because the interfaces of the host are not a fixture.
var routeInterfaceNameFn = interfaceNameByIndex

// defaultRoutes reads the default route of each family. It reads the kernel
// route table, because a snapshot follows every network change and a
// subprocess per change costs too much on a busy host. A table that the kernel
// does not give leaves both routes empty.
func defaultRoutes() (v4, v6 defaultRoute) {
	rib, err := route.FetchRIB(syscall.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return defaultRoute{}, defaultRoute{}
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return defaultRoute{}, defaultRoute{}
	}
	return defaultRoutesFromMessages(messages)
}

// defaultRoutesFromMessages picks the first default route of each family. The
// next hop and the interface come from one message, so a reader sees the pair
// that the kernel holds. The kernel keeps one unscoped default per family, so
// the first match is the only one.
func defaultRoutesFromMessages(messages []route.Message) (v4, v6 defaultRoute) {
	foundV4, foundV6 := false, false
	for _, message := range messages {
		match, ok := matchDefaultRoute(message)
		if !ok {
			continue
		}
		found := defaultRoute{Interface: routeInterfaceNameFn(match.index)}
		if match.gateway.IsValid() {
			found.Gateway = match.gateway.String()
		}
		if match.v4 && !foundV4 {
			v4, foundV4 = found, true
		}
		if !match.v4 && !foundV6 {
			v6, foundV6 = found, true
		}
		if foundV4 && foundV6 {
			return v4, v6
		}
	}
	return v4, v6
}

// defaultRouteMatch is one default route of the table. A tunnel default has
// no next hop, so gateway can be invalid while the interface is set.
type defaultRouteMatch struct {
	v4      bool
	gateway netip.Addr
	index   int
}

// defaultRouteGateway reports the next hop and the interface index of one
// default route, for the tests of the selector. See matchDefaultRoute.
func defaultRouteGateway(message route.Message) (netip.Addr, int, bool) {
	match, ok := matchDefaultRoute(message)
	return match.gateway, match.index, ok
}

// matchDefaultRoute reports whether one message is the default route of the
// host for its family. A route to another destination or to a part of the
// address space gives nothing: a VPN splits the default into two /1 routes,
// and the zero address alone does not make a route the default. A route bound
// to one interface serves that interface only, a host route is no default, and
// a reject or blackhole route delivers nothing. With the gateway flag, the
// next hop must be a host of the same family. Without it, the link itself
// delivers, which is how a tunnel owns the default; the match then has no
// gateway and names the interface.
func matchDefaultRoute(message route.Message) (defaultRouteMatch, bool) {
	routeMessage, ok := message.(*route.RouteMessage)
	if !ok || len(routeMessage.Addrs) <= syscall.RTAX_NETMASK {
		return defaultRouteMatch{}, false
	}
	if routeMessage.Flags&(syscall.RTF_IFSCOPE|syscall.RTF_HOST|syscall.RTF_REJECT|syscall.RTF_BLACKHOLE) != 0 {
		return defaultRouteMatch{}, false
	}
	destination, ok := routeMessageAddr(routeMessage.Addrs[syscall.RTAX_DST])
	if !ok || !destination.IsUnspecified() || !zeroNetmask(routeMessage.Addrs[syscall.RTAX_NETMASK], destination.Is4()) {
		return defaultRouteMatch{}, false
	}
	match := defaultRouteMatch{v4: destination.Is4(), index: routeMessage.Index}
	if routeMessage.Flags&syscall.RTF_GATEWAY == 0 {
		if _, link := routeMessage.Addrs[syscall.RTAX_GATEWAY].(*route.LinkAddr); !link {
			return defaultRouteMatch{}, false
		}
		return match, true
	}
	gateway, ok := routeMessageAddr(routeMessage.Addrs[syscall.RTAX_GATEWAY])
	if !ok || gateway.Is4() != destination.Is4() {
		return defaultRouteMatch{}, false
	}
	match.gateway = gateway
	return match, true
}

// zeroNetmask reports whether the netmask of a route covers the whole address
// space of its family, which only the default route does.
func zeroNetmask(addr route.Addr, v4 bool) bool {
	switch mask := addr.(type) {
	case *route.Inet4Addr:
		return v4 && mask.IP == [4]byte{}
	case *route.Inet6Addr:
		return !v4 && mask.IP == [16]byte{}
	}
	return false
}

func routeMessageAddr(addr route.Addr) (netip.Addr, bool) {
	switch address := addr.(type) {
	case *route.Inet4Addr:
		return netip.AddrFrom4(address.IP), true
	case *route.Inet6Addr:
		return withInterfaceZone(netip.AddrFrom16(address.IP), address.ZoneID), true
	}
	return netip.Addr{}, false
}

// withInterfaceZone names the interface of a link-local next hop. Every link
// repeats the same range, so the address alone names no host. A tunnel gives
// the bare address fe80:: and the interface is the only part that tells the
// links apart.
func withInterfaceZone(address netip.Addr, zoneID int) netip.Addr {
	if zoneID == 0 || !address.IsLinkLocalUnicast() {
		return address
	}
	name := routeInterfaceNameFn(zoneID)
	if name == "" {
		return address
	}
	return address.WithZone(name)
}

// interfaceNameByIndex names one interface of the route table. An index that
// no interface holds gives an empty name.
func interfaceNameByIndex(index int) string {
	if index == 0 {
		return ""
	}
	iface, err := net.InterfaceByIndex(index)
	if err != nil {
		return ""
	}
	return iface.Name
}
