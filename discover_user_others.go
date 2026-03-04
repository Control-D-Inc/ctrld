//go:build !windows && !linux && !darwin

package ctrld

import "context"

// DiscoverMainUser returns "unknown" for unsupported platforms.
// This is a stub implementation for platforms where username detection
// is not yet implemented.
func DiscoverMainUser(ctx context.Context) string {
	ProxyLogger.Load().Debug().Msg("username discovery not implemented for this platform")
	return "unknown"
}
