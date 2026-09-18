//go:build !darwin && !windows && !linux

package cli

import (
	"net"

	"tailscale.com/net/netmon"
)

func patchNetIfaceName(iface *net.Interface) (bool, error) { return true, nil }

func validInterface(iface *net.Interface, validIfacesMap map[string]struct{}) bool { return true }

// validInterfacesMap returns a set containing only default route interfaces.
func validInterfacesMap() map[string]struct{} {
	defaultRoute, err := netmon.DefaultRoute()
	if err != nil {
		return nil
	}
	return map[string]struct{}{defaultRoute.InterfaceName: {}}
}

// platformInterfaceMeta returns no names. These platforms have no source for
// them, so the interface name decides the class.
func platformInterfaceMeta(name string) (class, hardwarePort, service string) {
	return "", "", ""
}

// platformVirtualInterfaces returns no set.
func platformVirtualInterfaces() map[string]struct{} {
	return nil
}

// refreshInterfaceMeta does no work. These platforms keep no interface names,
// so an adapter that appears leaves nothing stale.
func refreshInterfaceMeta() {}
