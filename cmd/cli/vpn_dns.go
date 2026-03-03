package cli

import (
	"context"
	"strings"
	"sync"

	"tailscale.com/net/netmon"

	"github.com/Control-D-Inc/ctrld"
)

// vpnDNSExemption represents a VPN DNS server that needs pf/WFP exemption,
// including the interface it was discovered on. The interface is used on macOS
// to create interface-scoped pf exemptions that allow the VPN's local DNS
// handler (e.g., Tailscale's MagicDNS Network Extension) to receive queries
// from all processes — not just ctrld.
type vpnDNSExemption struct {
	Server     string // DNS server IP (e.g., "100.100.100.100")
	Interface  string // Interface name from scutil (e.g., "utun11"), may be empty
	IsExitMode bool   // True if this VPN is in exit/full-tunnel mode (all traffic routed through VPN)
}

// vpnDNSExemptFunc is called when VPN DNS servers change, to update
// the intercept layer (WFP/pf) to permit VPN DNS traffic.
type vpnDNSExemptFunc func(exemptions []vpnDNSExemption) error

// vpnDNSManager tracks active VPN DNS configurations and provides
// domain-to-upstream routing for VPN split DNS.
type vpnDNSManager struct {
	mu      sync.RWMutex
	configs []ctrld.VPNDNSConfig
	// Map of domain suffix → DNS servers for fast lookup
	routes map[string][]string
	// DNS servers from VPN interfaces that have no domain/suffix config.
	// These are NOT added to the global OS resolver. They're only used
	// as additional nameservers for queries that match split-DNS rules
	// (from ctrld config, AD domain, or VPN suffix config).
	domainlessServers []string
	// Called when VPN DNS server list changes, to update intercept exemptions.
	onServersChanged vpnDNSExemptFunc
}

// newVPNDNSManager creates a new manager. Only call when dnsIntercept is active.
// exemptFunc is called whenever VPN DNS servers are discovered/changed, to update
// the OS-level intercept rules to permit ctrld's outbound queries to those IPs.
func newVPNDNSManager(exemptFunc vpnDNSExemptFunc) *vpnDNSManager {
	return &vpnDNSManager{
		routes:           make(map[string][]string),
		onServersChanged: exemptFunc,
	}
}

// Refresh re-discovers VPN DNS configs from the OS.
// Called on network change events.
func (m *vpnDNSManager) Refresh(guardAgainstNoNameservers bool) {
	logger := mainLog.Load()

	logger.Debug().Msg("Refreshing VPN DNS configurations")
	configs := ctrld.DiscoverVPNDNS(context.Background())

	// Detect exit mode: if the default route goes through a VPN DNS interface,
	// the VPN is routing ALL traffic (exit node / full tunnel). This is more
	// reliable than scutil flag parsing because the routing table is the ground
	// truth for traffic flow, regardless of how the VPN presents itself in scutil.
	if dri, err := netmon.DefaultRouteInterface(); err == nil && dri != "" {
		for i := range configs {
			if configs[i].InterfaceName == dri {
				if !configs[i].IsExitMode {
					logger.Info().Msgf("VPN DNS on %s: default route interface match — EXIT MODE (route-based detection)", dri)
				}
				configs[i].IsExitMode = true
			}
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.configs = configs
	m.routes = make(map[string][]string)

	// Build domain -> DNS servers mapping
	for _, config := range configs {
		logger.Debug().Msgf("Processing VPN interface %s with %d domains and %d servers",
			config.InterfaceName, len(config.Domains), len(config.Servers))

		for _, domain := range config.Domains {
			// Normalize domain: remove leading dot, Linux routing domain prefix (~),
			// and convert to lowercase.
			domain = strings.TrimPrefix(domain, "~")
			domain = strings.TrimPrefix(domain, ".")
			domain = strings.ToLower(domain)

			if domain != "" {
				m.routes[domain] = append([]string{}, config.Servers...)
				logger.Debug().Msgf("Added VPN DNS route: %s -> %v", domain, config.Servers)
			}
		}
	}

	// Collect unique VPN DNS exemptions (server + interface) for pf/WFP rules.
	type exemptionKey struct{ server, iface string }
	seen := make(map[exemptionKey]bool)
	var exemptions []vpnDNSExemption
	for _, config := range configs {
		for _, server := range config.Servers {
			key := exemptionKey{server, config.InterfaceName}
			if !seen[key] {
				seen[key] = true
				exemptions = append(exemptions, vpnDNSExemption{
					Server:     server,
					Interface:  config.InterfaceName,
					IsExitMode: config.IsExitMode,
				})
			}
		}
	}

	// Collect domain-less VPN DNS servers. These are NOT added to the global
	// OS resolver (that would pollute captive portal / DHCP flows). Instead,
	// they're stored separately and only used for queries that match existing
	// split-DNS rules (from ctrld config, AD domain, or VPN suffix config).
	var domainlessServers []string
	seen2 := make(map[string]bool)
	for _, config := range configs {
		if len(config.Domains) == 0 && len(config.Servers) > 0 {
			logger.Debug().Msgf("VPN interface %s has DNS servers but no domains, storing as split-rule fallback: %v",
				config.InterfaceName, config.Servers)
			for _, s := range config.Servers {
				if !seen2[s] {
					seen2[s] = true
					domainlessServers = append(domainlessServers, s)
				}
			}
		}
	}
	m.domainlessServers = domainlessServers

	logger.Debug().Msgf("VPN DNS refresh completed: %d configs, %d routes, %d domainless servers, %d unique exemptions",
		len(m.configs), len(m.routes), len(m.domainlessServers), len(exemptions))

	// Update intercept rules to permit VPN DNS traffic.
	// Always call onServersChanged — including when exemptions is empty — so that
	// stale exemptions from a previous VPN session get cleared on disconnect.
	if m.onServersChanged != nil {
		if err := m.onServersChanged(exemptions); err != nil {
			logger.Error().Err(err).Msg("Failed to update intercept exemptions for VPN DNS servers")
		}
	}
}

// UpstreamForDomain checks if the domain matches any VPN search domain.
// Returns VPN DNS servers if matched, nil otherwise.
func (m *vpnDNSManager) UpstreamForDomain(domain string) []string {
	if domain == "" {
		return nil
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	domain = strings.TrimSuffix(domain, ".")
	domain = strings.ToLower(domain)

	if servers, ok := m.routes[domain]; ok {
		return append([]string{}, servers...)
	}

	for vpnDomain, servers := range m.routes {
		if strings.HasSuffix(domain, "."+vpnDomain) {
			return append([]string{}, servers...)
		}
	}

	return nil
}

// DomainlessServers returns VPN DNS servers that have no associated domains.
// These should only be used for queries matching split-DNS rules, not for
// general OS resolver queries (to avoid polluting captive portal / DHCP flows).
func (m *vpnDNSManager) DomainlessServers() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]string{}, m.domainlessServers...)
}

// CurrentServers returns the current set of unique VPN DNS server IPs.
func (m *vpnDNSManager) CurrentServers() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	seen := make(map[string]bool)
	var servers []string
	for _, ss := range m.routes {
		for _, s := range ss {
			if !seen[s] {
				seen[s] = true
				servers = append(servers, s)
			}
		}
	}
	return servers
}

// CurrentExemptions returns VPN DNS server + interface pairs for pf exemption rules.
func (m *vpnDNSManager) CurrentExemptions() []vpnDNSExemption {
	m.mu.RLock()
	defer m.mu.RUnlock()

	type key struct{ server, iface string }
	seen := make(map[key]bool)
	var exemptions []vpnDNSExemption
	for _, config := range m.configs {
		for _, server := range config.Servers {
			k := key{server, config.InterfaceName}
			if !seen[k] {
				seen[k] = true
				exemptions = append(exemptions, vpnDNSExemption{
					Server:     server,
					Interface:  config.InterfaceName,
					IsExitMode: config.IsExitMode,
				})
			}
		}
	}
	return exemptions
}

// Routes returns a copy of the current VPN DNS routes for debugging.
func (m *vpnDNSManager) Routes() map[string][]string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	routes := make(map[string][]string)
	for domain, servers := range m.routes {
		routes[domain] = append([]string{}, servers...)
	}
	return routes
}

// upstreamConfigFor creates a legacy upstream configuration for the given VPN DNS server.
func (m *vpnDNSManager) upstreamConfigFor(server string) *ctrld.UpstreamConfig {
	endpoint := server
	if !strings.Contains(server, ":") {
		endpoint = server + ":53"
	}

	return &ctrld.UpstreamConfig{
		Name:     "VPN DNS",
		Type:     ctrld.ResolverTypeLegacy,
		Endpoint: endpoint,
		Timeout:  2000,
	}
}
