package cli

// recoveryExemptFn writes intercept exemptions for recovery. Tests replace it,
// because the real writer reloads the pf anchor or the WFP filters.
var recoveryExemptFn = (*prog).exemptVPNDNSServers

// exemptRecoveryNameservers lets ctrld reach the recovery nameservers on port
// 53 and keeps the VPN DNS exemptions in place.
//
// The intercept callback replaces the whole exemption set. On macOS it
// rebuilds the pf anchor from the list, so a list of recovery nameservers
// alone drops the interface-scoped VPN DNS exemptions. pf then sends the VPN
// DNS handler's own traffic (for example Tailscale's 100.100.100.100) back to
// ctrld, and the VPN DNS refresh after recovery sees no change in the
// discovered set, so nothing restores the exemptions until a full pf reload.
func (p *prog) exemptRecoveryNameservers(recovery []vpnDNSExemption) error {
	exemptions := recovery
	if p.vpnDNS != nil {
		exemptions = mergeRecoveryExemptions(p.vpnDNS.CurrentExemptions(), recovery)
	}
	return recoveryExemptFn(p, exemptions)
}

// mergeRecoveryExemptions returns the VPN DNS exemptions followed by the
// recovery nameservers that are not VPN DNS servers already. Recovery entries
// carry no interface, so a recovery entry for a VPN DNS server would only
// repeat the group-scoped rule that the VPN entry writes.
func mergeRecoveryExemptions(vpn, recovery []vpnDNSExemption) []vpnDNSExemption {
	merged := make([]vpnDNSExemption, 0, len(vpn)+len(recovery))
	servers := make(map[string]bool, len(vpn)+len(recovery))
	for _, ex := range vpn {
		merged = append(merged, ex)
		servers[ex.Server] = true
	}
	for _, ex := range recovery {
		if servers[ex.Server] {
			continue
		}
		servers[ex.Server] = true
		merged = append(merged, ex)
	}
	return merged
}
