//go:build !windows && !darwin

package cli

import (
	"fmt"
	"time"
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

// skipInitialDNSReset is Windows-only; other platforms keep the normal reset.
func (p *prog) skipInitialDNSReset() bool { return false }

// exemptVPNDNSServers is a no-op on unsupported platforms.
func (p *prog) exemptVPNDNSServers(exemptions []vpnDNSExemption) error {
	return nil
}

// ensurePFAnchorActive is a no-op on unsupported platforms.
func (p *prog) ensurePFAnchorActive() pfAnchorCheckResult {
	return pfAnchorCheckSkipped
}

// checkTunnelInterfaceChanges is a no-op on unsupported platforms.
func (p *prog) checkTunnelInterfaceChanges() bool {
	return false
}

func (p *prog) dnsInterceptIgnoredChangeReconcileDue(time.Time) bool {
	return false
}

// scheduleDelayedRechecks is a no-op on unsupported platforms.
func (p *prog) scheduleDelayedRechecks() {}

// pfInterceptMonitor is a no-op on unsupported platforms.
func (p *prog) pfInterceptMonitor() {}

// reconcileForwardedSources is a no-op on unsupported platforms (macOS-only).
func (p *prog) reconcileForwardedSources() {}

// cleanupStaleDNSInterceptState is a no-op on unsupported platforms — there is no
// intercept state that can outlive the process here.
func cleanupStaleDNSInterceptState() {}

// osHealthcheckSuppressed always returns false on non-Windows platforms —
// WFP loopback protect (the trigger for suppression) is Windows-only.
func (p *prog) osHealthcheckSuppressed() bool { return false }
