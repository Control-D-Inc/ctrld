package cli

import "net"

// interceptDNSRdrTarget is the loopback address used as the macOS service
// DNS value when ctrld's listener is NOT reachable at <listener IP>:53
// directly (non-53 port, e.g. 127.0.0.1:5354 when mDNSResponder holds *:53).
//
// macOS resolvers always send DNS to port 53, so a direct-hit value is
// impossible in that case; delivery must go through the pf rdr rule
// ("rdr on lo0 ... to ! <listenerIP> port 53 -> <listenerIP> port <port>").
// The value therefore must be a loopback address DIFFERENT from the listener
// IP so the rdr's "! <listenerIP>" matches. Any 127/8 address routes via lo0
// on macOS.
const interceptDNSRdrTarget = "127.0.0.53"

// interceptDNSTargetValue returns the nameserver value to set on a DNS-less
// macOS service so the OS emits DNS queries that reach ctrld, respecting the
// configured listener. The listener IP/port derivation mirrors
// buildPFAnchorRulesForTunnels so the value and the pf rules always agree.
//
//   - listener on port 53: return the effective listener IP — queries hit the
//     listener directly, no pf dependency for this leg.
//   - listener on another port: return interceptDNSRdrTarget so the lo0 rdr
//     rule fires and rewrites to the real listener address.
func (p *prog) interceptDNSTargetValue() string {
	listenerIP := "127.0.0.1"
	listenerPort := 53
	// FirstListener panics when no listener is configured; guard like the
	// startup paths do.
	if p.cfg != nil && len(p.cfg.Listener) > 0 {
		if lc := p.cfg.FirstListener(); lc != nil {
			if lc.IP != "" && lc.IP != "0.0.0.0" && lc.IP != "::" {
				listenerIP = lc.IP
			}
			if lc.Port != 0 {
				listenerPort = lc.Port
			}
		}
	}
	if listenerPort == 53 {
		return listenerIP
	}
	if listenerIP == interceptDNSRdrTarget {
		// Pathological config: the listener itself sits on the rdr target
		// address (with a non-53 port). Pick a different loopback so the
		// rdr's "! <listenerIP>" still matches.
		return "127.0.0.54"
	}
	return interceptDNSRdrTarget
}

// hasIPv4DNS reports whether any of the given nameserver strings (bare IPs or
// host:port) is an IPv4 address. Loopback counts: an existing local resolver
// is treated conservatively as an intentional emittable DNS target; ctrld does
// not probe or replace another resolver's ownership.
func hasIPv4DNS(nameservers []string) bool {
	for _, s := range nameservers {
		host := s
		if h, _, err := net.SplitHostPort(s); err == nil {
			host = h
		}
		ip := net.ParseIP(host)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			return true
		}
	}
	return false
}

// needsInterceptDNSTarget reports whether the OS is left without any usable
// IPv4 DNS target: neither the default-route service's static DNS nor the
// discovered (DHCP/scutil) nameservers contain an IPv4 address.
//
// IPv6-only DNS is not usable under DNS intercept mode on macOS: the pf
// ruleset blocks all outbound IPv6 port-53 traffic (IPv6 interception is not
// supported, see issues #507/#533), and with no IPv4 DNS configured
// mDNSResponder emits no DNS packets at all — leaving pf nothing to
// intercept despite a healthy upstream. Observed in production on IPv6-only
// iPhone tethering with 464XLAT (issue #533).
func needsInterceptDNSTarget(staticDNS, discovered []string) bool {
	return !hasIPv4DNS(staticDNS) && !hasIPv4DNS(discovered)
}

// isInterceptDNSTargetOnly reports whether the given static DNS list is
// exactly the entry ctrld set via ensureInterceptDNSTarget (recorded in
// target), meaning it is safe for ctrld to remove.
func isInterceptDNSTargetOnly(nameservers []string, target string) bool {
	return target != "" && len(nameservers) == 1 && nameservers[0] == target
}

// filterOwnTarget returns nameservers with ctrld's own recorded target
// removed. A previously-set target must never be mistaken for user/network
// IPv4 DNS when judging whether the network still needs one — otherwise the
// second recovery on the same DNS-less network would see "IPv4 DNS present"
// and remove the entry, and the third would re-add it, oscillating on every
// recovery.
func filterOwnTarget(nameservers []string, target string) []string {
	if target == "" {
		return nameservers
	}
	out := nameservers[:0:0]
	for _, s := range nameservers {
		host := s
		if h, _, err := net.SplitHostPort(s); err == nil {
			host = h
		}
		if host != target {
			out = append(out, s)
		}
	}
	return out
}
