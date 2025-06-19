package cli

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strings"

	"tailscale.com/net/netmon"

	"github.com/Control-D-Inc/ctrld"
)

func patchNetIfaceName(iface *net.Interface) (bool, error) { return true, nil }

// validInterface reports whether the *net.Interface is a valid one.
// Only non-virtual interfaces are considered valid.
func validInterface(iface *net.Interface, validIfacesMap map[string]struct{}) bool {
	_, ok := validIfacesMap[iface.Name]
	return ok
}

// validInterfacesMap returns a set containing non virtual interfaces.
func validInterfacesMap(ctx context.Context) map[string]struct{} {
	m := make(map[string]struct{})
	vis := virtualInterfaces(ctx)
	netmon.ForeachInterface(func(i netmon.Interface, prefixes []netip.Prefix) {
		if _, existed := vis[i.Name]; existed {
			return
		}
		m[i.Name] = struct{}{}
	})
	// Fallback to the default route interface if found nothing.
	if len(m) == 0 {
		defaultRoute, err := netmon.DefaultRoute()
		if err != nil {
			return m
		}
		m[defaultRoute.InterfaceName] = struct{}{}
	}
	return m
}

// virtualInterfaces returns a map of virtual interfaces on the current machine.
func virtualInterfaces(ctx context.Context) map[string]struct{} {
	logger := ctrld.LoggerFromCtx(ctx)
	s := make(map[string]struct{})
	entries, err := os.ReadDir("/sys/devices/virtual/net")
	if err != nil {
		logger.Error().Err(err).Msg("failed to read /sys/devices/virtual/net")
		return nil
	}
	for _, entry := range entries {
		if entry.IsDir() {
			s[strings.TrimSpace(entry.Name())] = struct{}{}
		}
	}
	return s
}
