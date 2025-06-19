package cli

import (
	"context"
	"net"

	"github.com/Control-D-Inc/ctrld"
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

// validInterfacesMap returns a set of all physical interfaces.
func validInterfacesMap(ctx context.Context) map[string]struct{} {
	m := make(map[string]struct{})
	for ifaceName := range ctrld.ValidInterfaces(ctx) {
		m[ifaceName] = struct{}{}
	}
	return m
}
