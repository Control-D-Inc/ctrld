package cli

import (
	"net"
)

func patchNetIfaceName(iface *net.Interface) (bool, error) {
	return true, nil
}

// validInterface reports whether the *net.Interface is a valid one.
// On Windows, only physical interfaces are considered valid.
func validInterface(iface *net.Interface, validIfacesMap map[string]struct{}) bool {
	_, ok := validIfacesMap[iface.Name]
	return ok
}
