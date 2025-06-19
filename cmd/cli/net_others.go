//go:build !darwin && !windows && !linux

package cli

import (
	"context"
	"net"

	"tailscale.com/net/netmon"
)

func patchNetIfaceName(iface *net.Interface) (bool, error) { return true, nil }

func validInterface(iface *net.Interface, validIfacesMap map[string]struct{}) bool { return true }

// validInterfacesMap returns a set containing only default route interfaces.
func validInterfacesMap(ctx context.Context) map[string]struct{} {
	defaultRoute, err := netmon.DefaultRoute()
	if err != nil {
		return nil
	}
	return map[string]struct{}{defaultRoute.InterfaceName: {}}
}
