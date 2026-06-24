//go:build !windows && !darwin

package cli

// initPlatformFirewall is a no-op on unsupported platforms (Linux, etc.).
// Firewall mode on Linux would require iptables/nftables or eBPF — future work.
func (p *prog) initPlatformFirewall() {
	p.Warn().Msg("Firewall: platform enforcement not available on this OS; firewall_mode fails open and only records allowlist stats")
}

// firewallFlushPlatform is a no-op on unsupported platforms.
func (p *prog) firewallFlushPlatform() {}

// shutdownPlatformFirewall is a no-op on unsupported platforms.
func (p *prog) shutdownPlatformFirewall() {}
