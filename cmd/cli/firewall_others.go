//go:build !windows && !darwin

package cli

import "net/netip"

// initPlatformFirewall is a no-op on unsupported platforms (Linux, etc.).
// Firewall mode on Linux would require iptables/nftables or eBPF — future work.
func (p *prog) initPlatformFirewall() {
	p.Warn().Msg("Firewall: platform enforcement not available on this OS; firewall_mode fails open and only records allowlist stats")
}

// firewallFlushPlatform is a no-op on unsupported platforms.
func (p *prog) firewallFlushPlatform() {}

// shutdownPlatformFirewall is a no-op on unsupported platforms.
func (p *prog) shutdownPlatformFirewall() {}

// firewallApplyExceptionsPlatform succeeds trivially on unsupported platforms.
// Nothing enforces the allowlist here, so the organization's allowed destinations
// need no platform rules and there is nothing that can fail; the in-memory set is
// still maintained for stats and for the Contains() path used by embedders.
func (p *prog) firewallApplyExceptionsPlatform(added, removed []netip.Prefix) error {
	return nil
}

// firewallReplaceExceptionsPlatform succeeds trivially on unsupported platforms,
// for the same reason: there is no platform state to replace.
func (p *prog) firewallReplaceExceptionsPlatform(desired []netip.Prefix) error {
	return nil
}
