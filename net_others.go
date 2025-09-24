//go:build !darwin && !windows && !linux

package ctrld

import "tailscale.com/net/netmon"

// validInterfaces returns a set containing only default route interfaces.
// TODO: deuplicated with cmd/cli/net_others.go in v2.
func validInterfaces() map[string]struct{} {
	defaultRoute, err := netmon.DefaultRoute()
	if err != nil {
		return nil
	}
	return map[string]struct{}{defaultRoute.InterfaceName: {}}
}
