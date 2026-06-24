package cli

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/kardianos/service"
	"github.com/miekg/dns"

	"github.com/Control-D-Inc/ctrld/internal/firewall"
)

// firewallModeEnabled reports whether firewall mode is active for this prog instance.
func (p *prog) firewallModeEnabled() bool {
	return p.allowList != nil
}

// initFirewallAllowList populates the permanent allowlist entries and starts the
// background reaper. Called once during prog.run() when firewall_mode is "on".
//
// Permanent entries include:
//   - Loopback (127.0.0.0/8, ::1)
//   - RFC1918 private ranges (configurable — enabled by default)
//   - Link-local (169.254.0.0/16, fe80::/10)
//   - CGNAT range (100.64.0.0/10) — used by Tailscale, carrier NAT
//   - ctrld listener IPs
//   - DoH/DoT/DoQ upstream resolver IPs
//   - ControlD API endpoint IPs
func (p *prog) initFirewallAllowList(ctx context.Context) {
	al := p.allowList

	// Loopback.
	al.AddPermanentPrefix(netip.MustParsePrefix("127.0.0.0/8"))
	al.AddPermanent(netip.MustParseAddr("::1"))

	// RFC1918 private ranges — needed for LAN access, printers, NAS, etc.
	al.AddPermanentPrefix(netip.MustParsePrefix("10.0.0.0/8"))
	al.AddPermanentPrefix(netip.MustParsePrefix("172.16.0.0/12"))
	al.AddPermanentPrefix(netip.MustParsePrefix("192.168.0.0/16"))

	// Link-local.
	al.AddPermanentPrefix(netip.MustParsePrefix("169.254.0.0/16"))
	al.AddPermanentPrefix(netip.MustParsePrefix("fe80::/10"))

	// CGNAT range — used by Tailscale (100.x.x.x), carrier-grade NAT, etc.
	al.AddPermanentPrefix(netip.MustParsePrefix("100.64.0.0/10"))

	// Multicast.
	al.AddPermanentPrefix(netip.MustParsePrefix("224.0.0.0/4"))
	al.AddPermanentPrefix(netip.MustParsePrefix("ff00::/8"))

	// ctrld listener IPs — traffic to ourselves must always be allowed.
	for _, lc := range p.cfg.Listener {
		if ip, err := netip.ParseAddr(lc.IP); err == nil {
			al.AddPermanent(ip)
		}
	}

	// Upstream resolver IPs — ctrld needs to reach its upstreams.
	p.addUpstreamIPsToPermanent(al)

	// Platform-specific enforcement (pf on macOS, WFP on Windows) is initialized
	// from postRun() after startDNSIntercept() has prepared dnsInterceptState.

	p.Info().Msgf("Firewall allowlist initialized with %d permanent entries",
		al.Stats().PermanentIPs)
}

// syncFirewallMode applies the current firewall_mode setting for this run.
// Reloads create a new run-scoped context, so background firewall workers must
// be restarted each run even when the allowlist object is reused.
func (p *prog) syncFirewallMode(ctx context.Context) {
	if p.cfg.Service.FirewallMode != "on" {
		if p.allowList != nil || p.platformFirewallState != nil {
			p.Info().Msg("Firewall mode disabled: removing platform enforcement and clearing allowlist")
		}
		if p.allowList != nil {
			p.allowList.SetOnChange(nil)
			p.allowList.SetOnBatchChange(nil)
			p.allowList = nil
		}
		if p.platformFirewallState != nil {
			p.shutdownPlatformFirewall()
			p.platformFirewallState = nil
		}
		return
	}

	if p.allowList == nil {
		p.allowList = firewall.New()
		p.initFirewallAllowList(ctx)
		if service.Interactive() {
			p.Warn().Msg("Firewall mode has no effect in interactive mode; run ctrld as a service for enforcement")
		} else {
			p.Info().Msg("Firewall mode enabled: only DNS-resolved IPs will be allowed")
		}
	} else {
		p.addUpstreamIPsToPermanent(p.allowList)
	}

	// The run context is canceled on each reload. Restart the reaper/stats
	// workers for this run so reused allowlists keep expiring entries.
	p.allowList.StartReaper(ctx)
	go p.logFirewallStats(ctx)

	// On reload, postRun() is not called, so initialize platform enforcement here
	// if intercept state already exists. Initial startup still defers to postRun()
	// because DNS intercept state is prepared there.
	if p.dnsInterceptState != nil && p.platformFirewallState == nil {
		p.initPlatformFirewall()
	}
}

// addUpstreamIPsToPermanent resolves upstream endpoint hostnames and adds their
// IPs to the permanent allowlist. Called at startup and on config reload.
func (p *prog) addUpstreamIPsToPermanent(al *firewall.AllowList) {
	for _, uc := range p.cfg.Upstream {
		if uc == nil || uc.Endpoint == "" {
			continue
		}
		// Extract host from the endpoint URL.
		host := extractHostFromEndpoint(uc.Endpoint)
		if host == "" {
			continue
		}

		// If it's already an IP, add directly.
		if ip, err := netip.ParseAddr(host); err == nil {
			al.AddPermanent(ip)
			p.Debug().Msgf("Firewall: added upstream IP %s to permanent allowlist", ip)
			continue
		}

		// Resolve hostname to IPs.
		ips, err := net.LookupHost(host)
		if err != nil {
			p.Warn().Err(err).Msgf("Firewall: could not resolve upstream host %s", host)
			continue
		}
		for _, ipStr := range ips {
			if ip, err := netip.ParseAddr(ipStr); err == nil {
				al.AddPermanent(ip)
				p.Debug().Msgf("Firewall: added upstream IP %s (%s) to permanent allowlist", ip, host)
			}
		}
	}
}

// extractHostFromEndpoint extracts the hostname or IP from a DoH/DoT/DoQ endpoint URL.
// Handles formats like:
//   - "https://dns.controld.com/abcdef"
//   - "tls://dns.controld.com"
//   - "quic://dns.controld.com:784"
//   - "1.2.3.4:53"
//   - "sdns://..." (DNS stamps — host is encoded inside, skip)
func extractHostFromEndpoint(endpoint string) string {
	// DNS stamps encode the server info in base64 — we can't extract the host
	// without decoding. The upstream IPs will be resolved by the sdns upstream
	// initialization path at runtime.
	if strings.HasPrefix(endpoint, "sdns://") {
		return ""
	}

	// Try parsing as URL first (covers https://, tls://, quic://).
	if host := extractHostFromURL(endpoint); host != "" {
		return host
	}

	// Try as host:port.
	host, _, err := net.SplitHostPort(endpoint)
	if err == nil {
		return host
	}

	// Try as bare IP.
	if _, err := netip.ParseAddr(endpoint); err == nil {
		return endpoint
	}

	return ""
}

// extractHostFromURL extracts the host from a URL string.
func extractHostFromURL(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Hostname()
}

// firewallRecordResolvedIPs extracts A and AAAA records from a DNS response
// and adds them to the firewall allowlist. Called from postProcessStandardQuery()
// after a successful DNS resolution.
//
// This is the primary feed for the allowlist — every IP that ctrld resolves
// gets added here, making it allowed for outbound connections.
func (p *prog) firewallRecordResolvedIPs(answer *dns.Msg, domain string) {
	if p.allowList == nil || answer == nil {
		return
	}

	// Only record IPs from successful responses.
	if answer.Rcode != dns.RcodeSuccess {
		return
	}

	for _, rr := range answer.Answer {
		switch r := rr.(type) {
		case *dns.A:
			if ip, ok := netip.AddrFromSlice(r.A); ok {
				ttl := time.Duration(r.Hdr.Ttl) * time.Second
				if ttl < 30*time.Second {
					// Enforce minimum TTL to prevent constant churn for very short TTLs.
					ttl = 30 * time.Second
				}
				p.allowList.Add(ip, domain, ttl)
			}
		case *dns.AAAA:
			if ip, ok := netip.AddrFromSlice(r.AAAA); ok {
				ttl := time.Duration(r.Hdr.Ttl) * time.Second
				if ttl < 30*time.Second {
					ttl = 30 * time.Second
				}
				p.allowList.Add(ip, domain, ttl)
			}
		case *dns.CNAME:
			// For CNAME chains: the final A/AAAA records will be caught above.
			// We don't need to do anything special for the CNAME itself, but we
			// log it for debugging CNAME chain issues.
			p.Debug().Msgf("Firewall: CNAME %s → %s (IPs from target will be allowlisted)", domain, r.Target)
		}
	}
}

// firewallOnConfigReload is called when apiConfigReload() detects a config change.
// It flushes the entire allowlist so that DNS queries against the new policy
// repopulate it with the correct set of allowed IPs.
//
// This is the simple approach (vs. selective re-resolution per domain).
// The tradeoff is a brief window where connections may fail until DNS cache
// repopulates. Apps that reconnect directly to a previously resolved IP without
// making a fresh DNS query can remain blocked longer; this is an explicit v1
// limitation to call out in release notes and app-compatibility testing.
func (p *prog) firewallOnConfigReload() {
	if p.allowList == nil {
		return
	}
	stats := p.allowList.Stats()
	p.Info().Msgf("Firewall: config reload detected, flushing allowlist (%d IPs, %d domains)",
		stats.AllowedIPs, stats.TrackedDomains)
	// Flush platform-specific state first (pf table / WFP filters),
	// then flush the allowlist. The AllowList's batch callbacks will
	// also fire, but the platform flush handles the bulk operation more
	// efficiently than removing IPs one-by-one.
	p.firewallFlushPlatform()
	p.allowList.Flush()
}

// firewallOnNetworkChange is called when monitorNetworkChanges() detects a major
// network transition (WiFi↔cellular, interface IP changes). Stale IPs from the
// old network may no longer be valid, so we flush and let DNS repopulate.
func (p *prog) firewallOnNetworkChange() {
	if p.allowList == nil {
		return
	}
	stats := p.allowList.Stats()
	p.Info().Msgf("Firewall: network change detected, flushing allowlist (%d IPs, %d domains)",
		stats.AllowedIPs, stats.TrackedDomains)
	p.firewallFlushPlatform()
	p.allowList.Flush()
}

// logFirewallStats logs allowlist metrics immediately, then every 5 minutes
// while firewall mode is active.
func (p *prog) logFirewallStats(ctx context.Context) {
	if p.allowList == nil {
		return
	}
	p.logFirewallStatsOnce()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.logFirewallStatsOnce()
		}
	}
}

func (p *prog) logFirewallStatsOnce() {
	if p.allowList == nil {
		return
	}
	stats := p.allowList.Stats()
	p.Info().
		Int("allowed_ips", stats.AllowedIPs).
		Int("permanent_ips", stats.PermanentIPs).
		Int("tracked_domains", stats.TrackedDomains).
		Int64("total_hits", stats.TotalHits).
		Int64("total_misses", stats.TotalMisses).
		Msg("Firewall allowlist stats")
}
