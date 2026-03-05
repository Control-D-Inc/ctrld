//go:build !windows && !darwin

package cli

import (
	"fmt"
)

// startDNSIntercept is not supported on this platform.
// DNS intercept mode is only available on Windows (via WFP) and macOS (via pf).
func (p *prog) startDNSIntercept() error {
	return fmt.Errorf("dns intercept: not supported on this platform (only Windows and macOS)")
}

// stopDNSIntercept is a no-op on unsupported platforms.
func (p *prog) stopDNSIntercept() error {
	return nil
}

// exemptVPNDNSServers is a no-op on unsupported platforms.
func (p *prog) exemptVPNDNSServers(exemptions []vpnDNSExemption) error {
	return nil
}

// ensurePFAnchorActive is a no-op on unsupported platforms.
func (p *prog) ensurePFAnchorActive() bool {
	return false
}

// checkTunnelInterfaceChanges is a no-op on unsupported platforms.
func (p *prog) checkTunnelInterfaceChanges() bool {
	return false
}

// scheduleDelayedRechecks is a no-op on unsupported platforms.
func (p *prog) scheduleDelayedRechecks() {}

// pfInterceptMonitor is a no-op on unsupported platforms.
func (p *prog) pfInterceptMonitor() {}
