//go:build !darwin && !windows && !linux

package cli

import (
	"net"
)

// patchNetIfaceName patches network interface names on non-Linux/Darwin platforms
func patchNetIfaceName(iface *net.Interface) (bool, error) { return true, nil }

// validInterface checks if an interface is valid on non-Linux/Darwin platforms
func validInterface(iface *net.Interface, validIfacesMap map[string]struct{}) bool { return true }

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
