//go:build !darwin && !windows && !linux

package ctrld

import (
	"context"

	"tailscale.com/net/netmon"
)

// ValidInterfaces returns a set containing only default route interfaces.
func ValidInterfaces(_ context.Context) map[string]struct{} {
	defaultRoute, err := netmon.DefaultRoute()
	if err != nil {
		return nil
	}
	return map[string]struct{}{defaultRoute.InterfaceName: {}}
}
