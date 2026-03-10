package cli

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"

	"tailscale.com/net/netmon"

	"github.com/Control-D-Inc/ctrld"
)

// vpnDNSExemption represents a VPN DNS server that needs pf/WFP exemption,
// including the interface it was discovered on. The interface is used on macOS
// to create interface-scoped pf exemptions that allow the VPN's local DNS
// handler (e.g., Tailscale's MagicDNS Network Extension) to receive queries
// from all processes — not just ctrld. Without the interface scope, VPN DNS
// handlers that operate at the packet level (Network Extensions) never see
// the queries because pf intercepts them first.
type vpnDNSExemption struct {
	Server     string // DNS server IP (e.g., "100.100.100.100")
	Interface  string // Interface name from scutil (e.g., "utun11"), may be empty
	IsExitMode bool   // True if this VPN is in exit/full-tunnel mode (all traffic routed through VPN)
}

// vpnDNSExemptFunc is called when VPN DNS servers change, to update
// the intercept layer (WFP/pf) to permit VPN DNS traffic.
// On macOS, exemptions are interface-scoped to allow VPN local DNS handlers
// (e.g., Tailscale MagicDNS) to receive queries from all processes.
type vpnDNSExemptFunc func(exemptions []vpnDNSExemption) error

// vpnDNSManager tracks active VPN DNS configurations and provides
// domain-to-upstream routing for VPN split DNS.
type vpnDNSManager struct {
	mu      sync.RWMutex
	configs []ctrld.VPNDNSConfig
	// Map of domain suffix → DNS servers for fast lookup
	routes map[string][]string
	logger *atomic.Pointer[ctrld.Logger]
	// Called when VPN DNS server list changes, to update intercept exemptions.
	onServersChanged vpnDNSExemptFunc
}

// newVPNDNSManager creates a new manager. Only call when dnsIntercept is active.
// exemptFunc is called whenever VPN DNS servers are discovered/changed, to update
// the OS-level intercept rules to permit ctrld's outbound queries to those IPs.
func newVPNDNSManager(logger *atomic.Pointer[ctrld.Logger], exemptFunc vpnDNSExemptFunc) *vpnDNSManager {
	return &vpnDNSManager{
		routes:           make(map[string][]string),
		logger:           logger,
		onServersChanged: exemptFunc,
	}
}

// Refresh re-discovers VPN DNS configs from the OS.
// Called on network change events.
func (m *vpnDNSManager) Refresh(ctx context.Context) {
	logger := ctrld.LoggerFromCtx(ctx)

	ctrld.Log(ctx, logger.Debug(), "Refreshing VPN DNS configurations")
	configs := ctrld.DiscoverVPNDNS(ctx)

	// Detect exit mode: if the default route goes through a VPN DNS interface,
	// the VPN is routing ALL traffic (exit node / full tunnel). This is more
	// reliable than scutil flag parsing because the routing table is the ground
	// truth for traffic flow.
	if dri, err := netmon.DefaultRouteInterface(); err == nil && dri != "" {
		for i := range configs {
			if configs[i].InterfaceName == dri {
				if !configs[i].IsExitMode {
					ctrld.Log(ctx, logger.Info(), "VPN DNS on %s: default route interface match — EXIT MODE (route-based detection)", dri)
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
		ctrld.Log(ctx, logger.Debug(), "Processing VPN interface %s with %d domains and %d servers",
			config.InterfaceName, len(config.Domains), len(config.Servers))

		for _, domain := range config.Domains {
			// Normalize domain: remove leading dot, Linux routing domain prefix (~),
			// and convert to lowercase.
			domain = strings.TrimPrefix(domain, "~") // Linux resolvectl routing domain prefix
			domain = strings.TrimPrefix(domain, ".")
			domain = strings.ToLower(domain)

			if domain != "" {
				m.routes[domain] = append([]string{}, config.Servers...)
				ctrld.Log(ctx, logger.Debug(), "Added VPN DNS route: %s -> %v", domain, config.Servers)
			}
		}
	}

	// Collect unique VPN DNS exemptions (server + interface) for pf/WFP rules.
	// We track server+interface pairs because the same server IP on different
	// interfaces needs separate exemptions (interface-scoped on macOS).
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

	ctrld.Log(ctx, logger.Debug(), "VPN DNS refresh completed: %d configs, %d routes, %d unique exemptions",
		len(m.configs), len(m.routes), len(exemptions))

	// Update intercept rules to permit VPN DNS traffic.
	// Always call onServersChanged — including when exemptions is empty — so that
	// stale exemptions from a previous VPN session get cleared on disconnect.
	if m.onServersChanged != nil {
		if err := m.onServersChanged(exemptions); err != nil {
			ctrld.Log(ctx, logger.Error().Err(err), "Failed to update intercept exemptions for VPN DNS servers")
		}
	}
}

// UpstreamForDomain checks if the domain matches any VPN search domain.
// Returns VPN DNS servers if matched, nil otherwise.
// Uses suffix matching: "foo.provisur.local" matches "provisur.local"
func (m *vpnDNSManager) UpstreamForDomain(domain string) []string {
	if domain == "" {
		return nil
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Normalize domain (remove trailing dot, convert to lowercase)
	domain = strings.TrimSuffix(domain, ".")
	domain = strings.ToLower(domain)

	// First try exact match
	if servers, ok := m.routes[domain]; ok {
		return append([]string{}, servers...) // Return copy to avoid race conditions
	}

	// Try suffix matching - check if domain ends with any of our VPN domains
	for vpnDomain, servers := range m.routes {
		if strings.HasSuffix(domain, "."+vpnDomain) {
			return append([]string{}, servers...) // Return copy
		}
	}

	return nil
}

// CurrentServers returns the current set of unique VPN DNS server IPs.
// Used by pf anchor rebuild to include VPN DNS exemptions without a full Refresh().
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
// Used by pf anchor rebuild paths that need interface-scoped exemptions.
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
		Timeout:  2000, // 2 second timeout for VPN DNS queries
	}
}
