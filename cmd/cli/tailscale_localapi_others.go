//go:build !darwin

package cli

import "context"

// discoverTailscaleRoutesFn is nil off macOS: other platforms publish
// Tailscale split domains through the OS (NRPT, systemd-resolved).
var discoverTailscaleRoutesFn func(context.Context) ([]tailscaleRoute, error)
