package cli

import (
	"cmp"
	"net/netip"
	"slices"
	"strings"

	"github.com/Control-D-Inc/ctrld"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsaddr"
)

// hardwarePortIPhoneUSB is the macOS port name of a phone that shares its
// connection over the cable.
const hardwarePortIPhoneUSB = "iPhone USB"

// snapshotInterfaceLimit bounds the interface list of one snapshot. A
// container host holds hundreds of interfaces, and each entry costs bytes in
// every journal line and in every log file header.
const snapshotInterfaceLimit = 32

// v6GlobalPrefix holds the v6 addresses that reach the Internet.
var v6GlobalPrefix = netip.MustParsePrefix("2000::/3")

// hotspotGatewayPrefix is the range that an iPhone hotspot hands out. A
// gateway inside it names a tethered host on every platform.
var hotspotGatewayPrefix = netip.MustParsePrefix("172.20.10.0/28")

// ethernetPortWords name a wired port. macOS spells the same link in several
// ways, one per adapter family.
var ethernetPortWords = []string{"Ethernet", "LAN", "Thunderbolt"}

// defaultRoute names the next hop and the interface of one default route. Both
// values come from the same entry of the route table, so a reader can trust
// the pair.
type defaultRoute struct {
	Gateway   string
	Interface string
}

// snapshotInterface is one interface of a network snapshot.
type snapshotInterface struct {
	Name         string
	Class        string
	Up           bool
	IPs          []string
	HardwarePort string
	Service      string
}

// networkSnapshot describes the host network at one moment. The journal event
// and the header of a log file render the same value.
type networkSnapshot struct {
	DefaultRouteV4    string
	DefaultRouteV6    string
	GatewayV4         string
	GatewayV6         string
	HaveV4            bool
	HaveV6            bool
	Interfaces        []snapshotInterface
	InterfacesOmitted int
	Resolvers         []string
	SourceIPv4        string
	SourceIPv6        string
	InterceptTarget   string
	BypassActive      bool
	RecoveryRunning   bool
	PFStabilizing     bool
	LinkType          string
	Tethered          bool
	CLATPresent       bool
	NAT64Prefix       string
	DNSLessTarget     bool
}

// snapshotInputs holds every value a snapshot needs. The caller reads them, so
// the builder stays free of locks and of system calls.
type snapshotInputs struct {
	State           *netmon.State
	RouteV4         defaultRoute
	RouteV6         defaultRoute
	Resolvers       []string
	SourceIPv4      string
	SourceIPv6      string
	InterceptTarget string
	BypassActive    bool
	RecoveryRunning bool
	PFStabilizing   bool
	NAT64Prefix     string
	CLATPresent     bool
	Meta            interfaceMetaFunc
}

// buildNetworkSnapshot makes the snapshot of one moment. It is pure, so a
// caller can take the inputs under a lock and build outside it.
func buildNetworkSnapshot(in snapshotInputs) networkSnapshot {
	snapshot := networkSnapshot{
		GatewayV4:       in.RouteV4.Gateway,
		GatewayV6:       in.RouteV6.Gateway,
		DefaultRouteV4:  in.RouteV4.Interface,
		DefaultRouteV6:  in.RouteV6.Interface,
		Resolvers:       in.Resolvers,
		SourceIPv4:      in.SourceIPv4,
		SourceIPv6:      in.SourceIPv6,
		InterceptTarget: in.InterceptTarget,
		BypassActive:    in.BypassActive,
		RecoveryRunning: in.RecoveryRunning,
		PFStabilizing:   in.PFStabilizing,
		NAT64Prefix:     in.NAT64Prefix,
		CLATPresent:     in.CLATPresent,
		DNSLessTarget:   in.InterceptTarget != "",
	}

	routeMeta := interfaceMeta{}
	var routeAddresses []netip.Prefix
	if in.State != nil {
		meta := interfaceMetaWithClass(in.Meta)
		routeMeta = meta(in.State.DefaultRouteInterface)
		routeAddresses = in.State.InterfaceIPs[in.State.DefaultRouteInterface]
		snapshot.HaveV4, snapshot.HaveV6 = in.State.HaveV4, in.State.HaveV6
		snapshot.Interfaces, snapshot.InterfacesOmitted = snapshotInterfaces(in.State, meta)
		if snapshot.DefaultRouteV4 == "" {
			snapshot.DefaultRouteV4 = defaultRouteV4Interface(in.State)
		}
	}
	snapshot.LinkType = linkTypeFor(routeMeta.HardwarePort, routeMeta.Class)
	snapshot.Tethered = tetheredNetwork(in.RouteV4.Gateway, routeMeta.HardwarePort, routeAddresses)
	return snapshot
}

// interfaceMetaWithClass fills the class that the platform metadata leaves
// empty. A host that names no port still tells a tunnel from a hardware port
// by the interface name.
func interfaceMetaWithClass(meta interfaceMetaFunc) interfaceMetaFunc {
	return func(name string) interfaceMeta {
		info := interfaceMeta{}
		if meta != nil {
			info = meta(name)
		}
		if info.Class == "" {
			info.Class = interfaceClass(name, false)
		}
		return info
	}
}

// snapshotInterfaces lists the interfaces of the state, sorted by name, and
// counts the ones it leaves out. A reader compares two snapshots line by line,
// so the order must not move. An interface that is down and holds no address
// carries no traffic, and a container host holds hundreds of them.
func snapshotInterfaces(state *netmon.State, meta interfaceMetaFunc) (list []snapshotInterface, omitted int) {
	list = make([]snapshotInterface, 0, len(state.Interface))
	for name, iface := range state.Interface {
		up := iface.Interface != nil && iface.IsUp()
		ips := prefixStrings(state.InterfaceIPs[name])
		if !up && len(ips) == 0 {
			omitted++
			continue
		}
		info := meta(name)
		list = append(list, snapshotInterface{
			Name:         name,
			Class:        info.Class,
			Up:           up,
			IPs:          ips,
			HardwarePort: info.HardwarePort,
			Service:      info.Service,
		})
	}
	slices.SortFunc(list, func(a, b snapshotInterface) int {
		return cmp.Compare(a.Name, b.Name)
	})
	if len(list) > snapshotInterfaceLimit {
		omitted += len(list) - snapshotInterfaceLimit
		list = list[:snapshotInterfaceLimit]
	}
	return list, omitted
}

// defaultRouteV4Interface names the interface that the network monitor holds
// for the default route. It fills the v4 route of a platform that reads no
// route table. An interface without a usable v4 address carries no v4 traffic,
// whatever the monitor says.
func defaultRouteV4Interface(state *netmon.State) string {
	route := state.DefaultRouteInterface
	if route == "" {
		return ""
	}
	for _, prefix := range state.InterfaceIPs[route] {
		if usableV4(prefix.Addr().Unmap()) {
			return route
		}
	}
	return ""
}

// globalAddress reports whether an address reaches another host.
func globalAddress(address netip.Addr) bool {
	return address.IsGlobalUnicast() && !address.IsLoopback() && !address.IsLinkLocalUnicast()
}

// usableV4 and usableV6 grade one address the way the network monitor grades
// it. A fresh read of the interfaces must report the same families as a
// monitor callback, or two snapshots of one moment disagree. The monitor
// counts a unique local address of the v6 family, because some networks reach
// the Internet from it. The range of the Tailscale mesh is the exception,
// because that mesh carries no Internet traffic.
func usableV4(address netip.Addr) bool {
	return address.Is4() && globalAddress(address)
}

func usableV6(address netip.Addr) bool {
	if !address.Is6() {
		return false
	}
	if v6GlobalPrefix.Contains(address) {
		return true
	}
	return address.IsPrivate() && !tsaddr.TailscaleULARange().Contains(address)
}

// tetheredNetwork reports whether the host runs on a phone connection. A
// tethered host pays for its traffic and loses the link on every phone move.
// A platform that reads no route table gives no gateway, so the address that
// the phone handed to the host tells the same story.
func tetheredNetwork(gatewayV4, hardwarePort string, routeAddresses []netip.Prefix) bool {
	if hardwarePort == hardwarePortIPhoneUSB {
		return true
	}
	if gateway, err := netip.ParseAddr(gatewayV4); err == nil && hotspotGatewayPrefix.Contains(gateway.Unmap()) {
		return true
	}
	for _, prefix := range routeAddresses {
		if hotspotGatewayPrefix.Contains(prefix.Addr().Unmap()) {
			return true
		}
	}
	return false
}

// linkTypeFor names the link of the default route. The port name tells more
// than the interface name, which is only a number on macOS.
func linkTypeFor(hardwarePort, class string) string {
	switch {
	case hardwarePort == "Wi-Fi":
		return "wifi"
	case hardwarePort == hardwarePortIPhoneUSB:
		return "usb_tether"
	case ethernetPort(hardwarePort):
		return "ethernet"
	case class == "tunnel":
		return "tunnel"
	}
	return "unknown"
}

func ethernetPort(hardwarePort string) bool {
	for _, word := range ethernetPortWords {
		if strings.Contains(hardwarePort, word) {
			return true
		}
	}
	return false
}

// snapshotDict renders the snapshot with the field names of the spec. The
// journal event and the header line share it, so both stay in one shape.
func snapshotDict(snapshot networkSnapshot) *ctrld.LogEvent {
	interfaces := ctrld.Arr()
	for _, iface := range snapshot.Interfaces {
		interfaces = interfaces.Dict(ctrld.Dict().
			Str("name", iface.Name).
			Str("class", iface.Class).
			Bool("up", iface.Up).
			Strs("ips", iface.IPs).
			Str("hardware_port", iface.HardwarePort).
			Str("service", iface.Service))
	}
	return ctrld.Dict().
		Str("default_route_v4", snapshot.DefaultRouteV4).
		Str("default_route_v6", snapshot.DefaultRouteV6).
		Str("gateway_v4", snapshot.GatewayV4).
		Str("gateway_v6", snapshot.GatewayV6).
		Bool("have_v4", snapshot.HaveV4).
		Bool("have_v6", snapshot.HaveV6).
		Array("interfaces", interfaces).
		Int("interfaces_omitted", snapshot.InterfacesOmitted).
		Strs("resolvers", snapshot.Resolvers).
		Str("source_ipv4", snapshot.SourceIPv4).
		Str("source_ipv6", snapshot.SourceIPv6).
		Str("intercept_target", snapshot.InterceptTarget).
		Bool("bypass_active", snapshot.BypassActive).
		Bool("recovery_running", snapshot.RecoveryRunning).
		Bool("pf_stabilizing", snapshot.PFStabilizing).
		Str("link_type", snapshot.LinkType).
		Bool("tethered", snapshot.Tethered).
		Bool("clat_present", snapshot.CLATPresent).
		Str("nat64_prefix", snapshot.NAT64Prefix).
		Bool("dns_less_target", snapshot.DNSLessTarget)
}
