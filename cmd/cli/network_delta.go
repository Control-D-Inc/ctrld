package cli

import (
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/Control-D-Inc/ctrld"
	"tailscale.com/net/netmon"
)

// interfaceChange describes one interface that a network delta changed.
type interfaceChange struct {
	Name           string
	Action         string
	Class          string
	HardwarePort   string
	Service        string
	IPsBefore      []string
	IPsAfter       []string
	Flags          string
	MTU            int
	IsDefaultRoute bool
}

// interfaceMeta holds the platform description of one interface. An empty
// Class asks the caller to read the class from the interface name.
type interfaceMeta struct {
	Class        string
	HardwarePort string
	Service      string
	LinkType     string
}

// interfaceMetaFunc reads the platform description of one interface.
type interfaceMetaFunc func(name string) interfaceMeta

// virtualInterfaceSetFn names the virtual adapters of the host. Each platform
// file fills it, because a name alone does not tell a container bridge from a
// physical port.
var virtualInterfaceSetFn = func() map[string]struct{} { return nil }

// interfaceSnapshot holds the part of one interface state that the diff
// compares.
type interfaceSnapshot struct {
	present bool
	up      bool
	mac     string
	mtu     int
	flags   string
	ips     []string
}

// interfaceClass groups an interface by the traffic it carries. The class
// decides which changes are noise.
func interfaceClass(name string, virtual bool) string {
	switch {
	case strings.HasPrefix(name, "lo"):
		return "loopback"
	case hasInterfacePrefix(name, "awdl", "llw"):
		return "airdrop"
	case hasInterfacePrefix(name, "utun", "tun", "tap", "wg", "ipsec", "ppp"):
		return "tunnel"
	case virtual:
		return "virtual"
	default:
		return "hardware"
	}
}

// deltaBeforeState picks the state that the diff of one callback compares
// against, and makes a current callback the baseline of the next one. netmon
// caches major snapshots only, so every minor callback of an epoch carries the
// same Old, and a difference that lasts would look new in each of them. A
// callback that a newer snapshot replaced reads the baseline and leaves it.
// The caller holds networkSourceMu.
//
// netmon runs its callbacks in their own goroutines, so a minor callback of a
// new epoch can run before the major callback that opened the epoch. That
// major then reports its own changes against its Old and leaves the newer
// baseline in place. A major whose Old is the cache of the epoch before
// continues from the last reported state of that epoch, so a change that a
// minor callback reported does not appear again.
func (p *prog) deltaBeforeState(delta *netmon.ChangeDelta, epoch *netmon.State, current, major bool) *netmon.State {
	before := p.networkDeltaState
	switch {
	case before == nil:
		before = delta.Old
	case current && major && p.networkDeltaEpoch == epoch:
		return delta.Old
	case p.networkDeltaEpoch != epoch && delta.Old != p.networkDeltaEpoch:
		before = delta.Old
	}
	if current {
		p.networkDeltaState, p.networkDeltaEpoch = delta.New, epoch
	}
	return before
}

// diffNetworkDelta describes every interface that changed between two states.
// It walks every interface, not only the valid hardware ports, because the
// journal must show the port that went away too.
func diffNetworkDelta(beforeState, afterState *netmon.State) []interfaceChange {
	before, after := networkStateOrEmpty(beforeState), networkStateOrEmpty(afterState)
	virtual := virtualInterfaceSetFn()
	var changes []interfaceChange
	for _, name := range interfaceNameUnion(before, after) {
		snapBefore, snapAfter := readInterfaceSnapshot(before, name), readInterfaceSnapshot(after, name)
		action := interfaceAction(snapBefore, snapAfter)
		if action == "" {
			continue
		}
		known := snapAfter
		if !snapAfter.present {
			known = snapBefore
		}
		_, isVirtual := virtual[name]
		changes = append(changes, interfaceChange{
			Name:           name,
			Action:         action,
			Class:          interfaceClass(name, isVirtual),
			IPsBefore:      snapBefore.ips,
			IPsAfter:       snapAfter.ips,
			Flags:          known.flags,
			MTU:            known.mtu,
			IsDefaultRoute: name == after.DefaultRouteInterface,
		})
	}
	return changes
}

// noiseDelta reports a delta that no part of the daemon must act on. AirDrop
// and the virtual adapters of a container host change every few seconds, and
// each change would otherwise start the whole reconcile chain. A time jump
// means the host woke, so the daemon acts on the delta whatever it holds.
func noiseDelta(beforeState, afterState *netmon.State, timeJumped bool, changes []interfaceChange) bool {
	if len(changes) == 0 || timeJumped {
		return false
	}
	before, after := networkStateOrEmpty(beforeState), networkStateOrEmpty(afterState)
	if before.DefaultRouteInterface != after.DefaultRouteInterface {
		return false
	}
	if before.HaveV4 != after.HaveV4 || before.HaveV6 != after.HaveV6 {
		return false
	}
	source4, source6 := ctrld.GetDefaultLocalIPv4(), ctrld.GetDefaultLocalIPv6()
	for _, change := range changes {
		if !noiseClass(change.Class) || change.IsDefaultRoute {
			return false
		}
		if carriesHostTraffic(change.IPsBefore, source4, source6) {
			return false
		}
		if carriesHostTraffic(change.IPsAfter, source4, source6) {
			return false
		}
	}
	return true
}

// noiseClass names the classes that change on their own. The kernel moves the
// link-local address of an AirDrop or a container adapter every few seconds.
func noiseClass(class string) bool {
	return class == "airdrop" || class == "virtual"
}

// carriesHostTraffic reports an address list that reaches another host. A
// bridge, a bond, or a tunnel adapter can own the traffic of the host, so a
// routable address or the resolver source address makes the interface real
// whatever its name says.
func carriesHostTraffic(ips []string, source4, source6 net.IP) bool {
	for _, ip := range ips {
		prefix, err := netip.ParsePrefix(ip)
		if err != nil {
			continue
		}
		addr := prefix.Addr()
		if addr.IsGlobalUnicast() || sameAddress(addr, source4) || sameAddress(addr, source6) {
			return true
		}
	}
	return false
}

// sameAddress compares one interface address with a resolver source address.
func sameAddress(addr netip.Addr, ip net.IP) bool {
	source, ok := netip.AddrFromSlice(ip)
	return ok && source.Unmap() == addr
}

// describeInterfaceChanges fills the platform fields of the changes that reach
// the journal. macOS reads them with two subprocesses, so only a delta that
// the daemon acts on pays for them. The platform class wins where it knows
// one, because a name rule cannot see a virtual adapter on Windows.
func describeInterfaceChanges(changes []interfaceChange, meta interfaceMetaFunc) {
	if meta == nil {
		return
	}
	for i := range changes {
		info := meta(changes[i].Name)
		changes[i].HardwarePort, changes[i].Service = info.HardwarePort, info.Service
		if info.Class != "" {
			changes[i].Class = info.Class
		}
	}
}

// interfaceAction names the first difference that the journal reports. The
// order runs from the coarse change to the fine one, so one interface gives
// one action.
func interfaceAction(before, after interfaceSnapshot) string {
	switch {
	case before.present && !after.present:
		return "removed"
	case !before.present && after.present:
		return "added"
	case before.up && !after.up:
		return "down"
	case !before.up && after.up:
		return "up"
	case hasExtraEntry(before.ips, after.ips):
		return "ip_removed"
	case hasExtraEntry(after.ips, before.ips):
		return "ip_added"
	case before.mac != after.mac:
		return "mac_changed"
	case before.mtu != after.mtu:
		return "mtu_changed"
	default:
		return ""
	}
}

func readInterfaceSnapshot(state *netmon.State, name string) interfaceSnapshot {
	snapshot := interfaceSnapshot{ips: sortedPrefixStrings(state.InterfaceIPs[name])}
	iface, ok := state.Interface[name]
	if !ok {
		return snapshot
	}
	snapshot.present = true
	if iface.Interface == nil {
		return snapshot
	}
	snapshot.up = iface.IsUp()
	snapshot.mtu = iface.MTU
	snapshot.flags = iface.Flags.String()
	if len(iface.HardwareAddr) > 0 {
		snapshot.mac = iface.HardwareAddr.String()
	}
	return snapshot
}

func interfaceNameUnion(before, after *netmon.State) []string {
	names := make([]string, 0, len(before.Interface)+len(after.Interface))
	for name := range before.Interface {
		names = append(names, name)
	}
	for name := range after.Interface {
		if _, both := before.Interface[name]; !both {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

func sortedPrefixStrings(prefixes []netip.Prefix) []string {
	ips := prefixStrings(prefixes)
	slices.Sort(ips)
	return ips
}

// networkStateOrEmpty keeps the diff free of nil checks. The first delta after
// start carries no old state.
func networkStateOrEmpty(state *netmon.State) *netmon.State {
	if state != nil {
		return state
	}
	return &netmon.State{}
}

func hasInterfacePrefix(name string, prefixes ...string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// hasExtraEntry reports an entry of list that other does not hold.
func hasExtraEntry(list, other []string) bool {
	for _, entry := range list {
		if !slices.Contains(other, entry) {
			return true
		}
	}
	return false
}
