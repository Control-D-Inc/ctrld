//go:build !darwin

package cli

// ensureInterceptDNSTarget is a no-op on non-Darwin platforms: the DNS-less
// network problem it solves is specific to macOS pf interception blocking
// IPv6 port 53 with no IPv4 fallback (issue #533). Windows intercept mode
// uses NRPT, which routes queries regardless of adapter DNS configuration.
func (p *prog) ensureInterceptDNSTarget(_ []string) {}

// removeInterceptDNSTarget is a no-op on non-Darwin platforms.
//
//lint:ignore U1000 called from Darwin-only intercept shutdown; kept for API symmetry.
func (p *prog) removeInterceptDNSTarget(_ string) {}
