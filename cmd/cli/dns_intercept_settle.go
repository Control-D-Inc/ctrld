package cli

import "github.com/Control-D-Inc/ctrld"

var initializeOsResolver = ctrld.InitializeOsResolver

func (p *prog) refreshDNSAfterVPNSettle(reason string) (routes, domainlessServers, exemptions int) {
	mainLog.Load().Info().Msgf("DNS intercept: refreshing OS/VPN DNS route state after VPN settle (%s)", reason)
	ns := initializeOsResolver(true)
	mainLog.Load().Debug().Msgf("DNS intercept: post-settle OS resolver nameservers: %v", ns)

	if p.vpnDNS == nil {
		mainLog.Load().Debug().Msg("DNS intercept: post-settle VPN DNS route refresh skipped — manager unavailable")
		return 0, 0, 0
	}

	routes, domainlessServers, exemptions = p.vpnDNS.RefreshRoutesOnly()
	mainLog.Load().Info().Msgf("DNS intercept: post-settle VPN DNS route refresh completed — %d routes, %d domainless servers, %d exemptions",
		routes, domainlessServers, exemptions)
	return routes, domainlessServers, exemptions
}

func vpnDNSExemptionsEqual(a, b []vpnDNSExemption) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[vpnDNSExemption]int, len(a))
	for _, ex := range a {
		seen[ex]++
	}
	for _, ex := range b {
		if seen[ex] == 0 {
			return false
		}
		seen[ex]--
	}
	return true
}
