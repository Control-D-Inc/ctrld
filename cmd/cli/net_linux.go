package cli

import (
	"net"
)

// patchNetIfaceName patches network interface names on Linux
// This is a no-op on Linux as interface names don't need special handling
func patchNetIfaceName(iface *net.Interface) (bool, error) { return true, nil }

// validInterface reports whether the *net.Interface is a valid one.
// Only non-virtual interfaces are considered valid.
// This prevents DNS configuration on virtual interfaces like docker, veth, etc.
func validInterface(iface *net.Interface, validIfacesMap map[string]struct{}) bool {
	_, ok := validIfacesMap[iface.Name]
	return ok
}
