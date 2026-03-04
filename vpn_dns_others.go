//go:build !windows && !darwin && !linux

package ctrld

import (
	"context"
)

// DiscoverVPNDNS is a stub implementation for unsupported platforms.
// Returns nil to indicate no VPN DNS configurations found.
func DiscoverVPNDNS(ctx context.Context) []VPNDNSConfig {
	logger := *ProxyLogger.Load()
	Log(ctx, logger.Debug(), "VPN DNS discovery not implemented for this platform")
	return nil
}
