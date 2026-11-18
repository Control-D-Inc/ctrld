package cli

import (
	"net"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/Control-D-Inc/ctrld"
	"tailscale.com/net/netmon"
)

// networkSnapshotMessage is the message of the snapshot event. A log tool
// selects every snapshot of a run by this message.
const networkSnapshotMessage = "Network snapshot"

// snapshotTriggerStart names the snapshot of the start of a run.
const snapshotTriggerStart = "start"

// snapshotMinInterval bounds the snapshots of a flapping network.
const snapshotMinInterval = 60 * time.Second

// snapshotNowFn is the clock of the snapshot limit. A test replaces it.
var snapshotNowFn = time.Now

// defaultRoutesFn reads the default route of each family. A test replaces it,
// because the route table of the host is not a fixture.
var defaultRoutesFn = defaultRoutes

// platformInterfaceMetaFn reads the platform names of one interface. A test
// replaces it, because the ports of the host are not a fixture.
var platformInterfaceMetaFn = platformInterfaceMeta

// The delta diff has to know the virtual adapters of the host, and only the
// platform file reads them.
func init() {
	virtualInterfaceSetFn = platformVirtualInterfaces
}

// interfaceMetaFor describes one interface for the snapshot and for the delta
// diff.
func interfaceMetaFor(name string) interfaceMeta {
	platformClass, hardwarePort, service := platformInterfaceMetaFn(name)
	meta := interfaceMeta{
		Class:        interfaceClassFor(name, platformClass),
		HardwarePort: hardwarePort,
		Service:      service,
	}
	meta.LinkType = linkTypeFor(hardwarePort, meta.Class)
	return meta
}

// interfaceClassFor picks the class of one interface. A name rule wins for the
// loopback, the AirDrop, and the tunnel interfaces, because Windows describes
// a tunnel adapter as an Ethernet adapter.
func interfaceClassFor(name, platformClass string) string {
	if class := interfaceClass(name, false); class != "hardware" {
		return class
	}
	if platformClass != "" {
		return platformClass
	}
	if _, virtual := virtualInterfaceSetFn()[name]; virtual {
		return "virtual"
	}
	return "hardware"
}

// snapshotInputs reads the sources of one snapshot from the network that the
// last monitor callback reported. No callback ran before the first header of a
// run, so that header reads the network itself.
func (p *prog) snapshotInputs() snapshotInputs {
	state := p.lastNetworkState.Load()
	if state == nil {
		state = freshNetworkState()
	}
	return p.snapshotInputsFor(state)
}

// freshSnapshotInputs reads the sources of one snapshot from the network of
// this moment. Support reads the header of an upload to learn the network of
// the moment the user asked, which can differ from the last callback.
func (p *prog) freshSnapshotInputs() snapshotInputs {
	return p.snapshotInputsFor(freshNetworkState())
}

// networkSnapshot describes the host network of this moment.
func (p *prog) networkSnapshot() networkSnapshot {
	return buildNetworkSnapshot(p.snapshotInputs())
}

// logNetworkSnapshot puts the host network in the journal. Support reads the
// snapshot of each trigger to learn the network at the time of an outage.
func (p *prog) logNetworkSnapshot(trigger string) {
	snapshot := p.networkSnapshot()
	if !p.snapshotWrites.allow(trigger, snapshot, snapshotNowFn()) {
		return
	}
	journal(mainLog.Load().Info()).
		Str("trigger", trigger).
		Dict("network", snapshotDict(snapshot)).
		Msg(networkSnapshotMessage)
}

// snapshotLimiter holds the snapshot that reached the journal last, so a burst
// of triggers writes one line.
type snapshotLimiter struct {
	mu      sync.Mutex
	last    networkSnapshot
	written time.Time
	seen    bool
}

// allow reports whether one snapshot reaches the journal, and records the
// snapshots that do.
func (s *snapshotLimiter) allow(trigger string, snapshot networkSnapshot, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.permits(trigger, snapshot, now) {
		return false
	}
	s.last, s.written, s.seen = snapshot, now, true
	return true
}

// permits decides one snapshot. The first snapshot of a run tells a reader
// where the run started. A snapshot equal to the one before it carries
// nothing. A new default route and a new resolver set explain an outage, so
// they pass at once. Every other snapshot waits out the interval, because a
// flapping interface writes some kilobytes per flap.
func (s *snapshotLimiter) permits(trigger string, snapshot networkSnapshot, now time.Time) bool {
	if trigger == snapshotTriggerStart || !s.seen {
		return true
	}
	if sameNetworkSnapshot(s.last, snapshot) {
		return false
	}
	if routeOrResolversChanged(s.last, snapshot) {
		return true
	}
	return now.Sub(s.written) >= snapshotMinInterval
}

// sameNetworkSnapshot compares two snapshots field by field. The trigger is no
// part of a snapshot, so two triggers of one network give one line.
func sameNetworkSnapshot(before, after networkSnapshot) bool {
	return reflect.DeepEqual(before, after)
}

// routeOrResolversChanged names the changes that a reader of an outage needs
// at once.
func routeOrResolversChanged(before, after networkSnapshot) bool {
	return before.DefaultRouteV4 != after.DefaultRouteV4 ||
		before.DefaultRouteV6 != after.DefaultRouteV6 ||
		!slices.Equal(before.Resolvers, after.Resolvers)
}

// snapshotInputsFor reads every source of one snapshot. It takes no writer
// lock, so any path of the daemon can log a snapshot.
func (p *prog) snapshotInputsFor(state *netmon.State) snapshotInputs {
	routeV4, routeV6 := defaultRoutesFn()
	inputs := snapshotInputs{
		State:           state,
		RouteV4:         routeV4,
		RouteV6:         routeV6,
		Resolvers:       ctrld.OsResolverNameservers(),
		SourceIPv4:      addressString(ctrld.GetDefaultLocalIPv4()),
		SourceIPv6:      addressString(ctrld.GetDefaultLocalIPv6()),
		InterceptTarget: p.interceptTargetSnapshot(),
		BypassActive:    p.recoveryBypass.Load(),
		RecoveryRunning: p.recoveryRunning.Load(),
		PFStabilizing:   p.pfStabilizing.Load(),
		Meta:            interfaceMetaFor,
	}
	if prefix, ok := p.dns64PrefixSnapshot(); ok {
		inputs.NAT64Prefix = prefix.String()
	}
	if state != nil {
		inputs.CLATPresent = dns64StateHasCLAT(state)
	}
	return inputs
}

// freshNetworkState reads the interfaces of the host now. netmon fills the
// route and the families of a callback state, so a read of this package has to
// fill them itself.
func freshNetworkState() *netmon.State {
	state, err := readNetworkSourceStateFn()
	if err != nil || state == nil {
		return nil
	}
	fresh := *state
	if route, err := netmon.DefaultRouteInterface(); err == nil {
		fresh.DefaultRouteInterface = route
	}
	fresh.HaveV4, fresh.HaveV6 = reachableAddressFamilies(&fresh)
	return &fresh
}

// reachableAddressFamilies reports which families the host can reach. It
// grades each address with the rule of the network monitor, so the first
// header of a run reports the same families as the first callback.
func reachableAddressFamilies(state *netmon.State) (haveV4, haveV6 bool) {
	for name, iface := range state.Interface {
		if iface.Interface == nil || !iface.IsUp() {
			continue
		}
		for _, prefix := range state.InterfaceIPs[name] {
			address := prefix.Addr().Unmap()
			haveV4 = haveV4 || usableV4(address)
			haveV6 = haveV6 || usableV6(address)
		}
	}
	return haveV4, haveV6
}

// addressString names one source address. An address that ctrld does not hold
// leaves an empty field, because net.IP prints an empty value as the word for
// a nil address.
func addressString(ip net.IP) string {
	if len(ip) == 0 {
		return ""
	}
	return ip.String()
}
