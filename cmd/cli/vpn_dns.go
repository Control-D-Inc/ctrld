package cli

import (
	"context"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"tailscale.com/net/netmon"

	"github.com/Control-D-Inc/ctrld"
)

var vpnDNSSettlingEnabled = runtime.GOOS == "windows"

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
	// DNS servers from VPN interfaces that have no domain/suffix config.
	// These are NOT added to the global OS resolver. They're only used
	// as additional nameservers for queries that match split-DNS rules
	// (from ctrld config, AD domain, or VPN suffix config).
	domainlessServers []string
	// retainedAfterEmptyDiscovery means Windows reported an empty VPN DNS
	// snapshot once while previous VPN DNS state existed. We keep that last-known
	// state for one guarded refresh cycle because Windows can briefly report an
	// intermediate empty adapter/DNS state after sleep/wake or reconnect.
	retainedAfterEmptyDiscovery bool
	// discoverVPNDNS is injected for tests so Refresh does not depend on the
	// runner host's real VPN/virtual adapter state.
	discoverVPNDNS func(context.Context) []ctrld.VPNDNSConfig
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
		discoverVPNDNS:   ctrld.DiscoverVPNDNS,
		onServersChanged: exemptFunc,
	}
}

// Refresh re-discovers VPN DNS configs from the OS.
// Called on network change events.
func (m *vpnDNSManager) Refresh(ctx context.Context, guardAgainstNoNameservers ...bool) {
	logger := ctrld.LoggerFromCtx(ctx)
	guardedRefresh := len(guardAgainstNoNameservers) > 0 && guardAgainstNoNameservers[0]

	ctrld.Log(ctx, logger.Debug(), "Refreshing VPN DNS configurations")
	discoverVPNDNS := m.discoverVPNDNS
	if discoverVPNDNS == nil {
		discoverVPNDNS = ctrld.DiscoverVPNDNS
	}
	configs := discoverVPNDNS(ctx)

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

	previousExemptions := m.currentExemptionsLocked()

	if vpnDNSSettlingEnabled && len(configs) == 0 && guardedRefresh && m.hasVPNDNSStateLocked() {
		if !m.retainedAfterEmptyDiscovery {
			exemptions := m.currentExemptionsLocked()
			m.retainedAfterEmptyDiscovery = true
			ctrld.Log(ctx, logger.Debug(),
				"VPN DNS discovery empty; retaining last-known VPN DNS state for one guarded refresh (%d domainless servers, %d exemptions)",
				len(m.domainlessServers), len(exemptions))
			if m.onServersChanged != nil {
				if err := m.onServersChanged(exemptions); err != nil {
					ctrld.Log(ctx, logger.Error().Err(err), "Failed to re-apply retained VPN DNS exemptions")
				}
			}
			return
		}
		ctrld.Log(ctx, logger.Debug(),
			"VPN DNS discovery still empty on next guarded refresh; clearing retained VPN DNS state (%d domainless servers)",
			len(m.domainlessServers))
	}

	// Any discovery path that does not return with retained state clears the
	// settling marker: non-empty discovery replaces old servers immediately, and
	// an unguarded/second empty discovery clears stale state below.
	m.retainedAfterEmptyDiscovery = false
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

	// Collect domain-less VPN DNS servers. These are NOT added to the global
	// OS resolver (that would pollute captive portal / DHCP flows). Instead,
	// they're stored separately and only used for queries that match existing
	// split-DNS rules (from ctrld config, AD domain, or VPN suffix config).
	var domainlessServers []string
	seenDomainless := make(map[string]bool)
	for _, config := range configs {
		if len(config.Domains) == 0 && len(config.Servers) > 0 {
			ctrld.Log(ctx, logger.Debug(), "VPN interface %s has DNS servers but no domains, storing as split-rule fallback: %v",
				config.InterfaceName, config.Servers)
			for _, server := range config.Servers {
				if !seenDomainless[server] {
					seenDomainless[server] = true
					domainlessServers = append(domainlessServers, server)
				}
			}
		}
	}
	m.domainlessServers = domainlessServers

	ctrld.Log(ctx, logger.Debug(), "VPN DNS refresh completed: %d configs, %d routes, %d domainless servers, %d unique exemptions",
		len(m.configs), len(m.routes), len(m.domainlessServers), len(exemptions))

	// Update intercept rules to permit VPN DNS traffic only when the exemption set
	// actually changes. Network-change events can fire repeatedly while macOS/VPN
	// state is otherwise identical; rewriting pf for identical exemptions can feed
	// a self-triggering network-change loop. Empty exemptions are still applied
	// when they differ from the previous set, so stale VPN exemptions are cleared
	// on disconnect.
	m.updateInterceptExemptionsIfChanged(ctx, logger, previousExemptions, exemptions, "VPN DNS")
}

func (m *vpnDNSManager) updateInterceptExemptionsIfChanged(ctx context.Context, logger *ctrld.Logger, before, after []vpnDNSExemption, reason string) {
	if m.onServersChanged == nil {
		return
	}
	if vpnDNSExemptionsEqual(before, after) {
		ctrld.Log(ctx, logger.Debug(), "VPN DNS exemptions unchanged after %s refresh; skipping intercept rule update", reason)
		return
	}
	if err := m.onServersChanged(after); err != nil {
		ctrld.Log(ctx, logger.Error().Err(err), "Failed to update intercept exemptions for VPN DNS servers")
	}
}

// RefreshRoutesOnly re-discovers VPN DNS configs and updates only ctrld's
// in-memory split-DNS routes. It intentionally does not call onServersChanged,
// so it does not rewrite/reload pf/WFP rules. Use this for post-settle discovery
// checks where we only need to learn late-published VPN search domains.
func (m *vpnDNSManager) RefreshRoutesOnly() (routes, domainlessServers, exemptions int) {
	logger := mainLog.Load()

	logger.Debug().Msg("Refreshing VPN DNS route state only")
	discoverVPNDNS := m.discoverVPNDNS
	if discoverVPNDNS == nil {
		discoverVPNDNS = ctrld.DiscoverVPNDNS
	}
	configs := discoverVPNDNS(context.Background())

	if dri, err := netmon.DefaultRouteInterface(); err == nil && dri != "" {
		for i := range configs {
			if configs[i].InterfaceName == dri {
				configs[i].IsExitMode = true
			}
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.retainedAfterEmptyDiscovery = false
	m.configs = configs
	m.routes = make(map[string][]string)

	for _, config := range configs {
		for _, domain := range config.Domains {
			domain = strings.TrimPrefix(domain, "~")
			domain = strings.TrimPrefix(domain, ".")
			domain = strings.ToLower(domain)
			if domain != "" {
				m.routes[domain] = append([]string{}, config.Servers...)
			}
		}
	}

	var domainless []string
	seenDomainless := make(map[string]bool)
	for _, config := range configs {
		if len(config.Domains) == 0 && len(config.Servers) > 0 {
			for _, server := range config.Servers {
				if !seenDomainless[server] {
					seenDomainless[server] = true
					domainless = append(domainless, server)
				}
			}
		}
	}
	m.domainlessServers = domainless

	logger.Debug().Msgf("VPN DNS route-only refresh completed: %d configs, %d routes, %d domainless servers, %d exemptions",
		len(m.configs), len(m.routes), len(m.domainlessServers), len(m.currentExemptionsLocked()))
	return len(m.routes), len(m.domainlessServers), len(m.currentExemptionsLocked())
}

func (m *vpnDNSManager) hasVPNDNSStateLocked() bool {
	return len(m.configs) > 0 || len(m.routes) > 0 || len(m.domainlessServers) > 0
}

func (m *vpnDNSManager) currentExemptionsLocked() []vpnDNSExemption {
	type key struct{ server, iface string }
	seen := make(map[key]bool)
	var exemptions []vpnDNSExemption
	for _, config := range m.configs {
		for _, server := range config.Servers {
			k := key{server, config.InterfaceName}
			if seen[k] {
				continue
			}
			seen[k] = true
			exemptions = append(exemptions, vpnDNSExemption{
				Server:     server,
				Interface:  config.InterfaceName,
				IsExitMode: config.IsExitMode,
			})
		}
	}
	return exemptions
}

// ShouldFailClosedAfterVPNDNSTransportFailure reports whether split-rule
// queries should fail closed instead of falling back to OS/public DNS after
// every candidate VPN DNS server failed before returning a DNS packet. This is
// Windows-only and only active while serving retained VPN DNS state from a
// guarded empty discovery, which is the short window where Windows can report
// VPN DNS before routes to those servers are usable after wake/reconnect.
func (m *vpnDNSManager) ShouldFailClosedAfterVPNDNSTransportFailure(domain string, servers []string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !vpnDNSSettlingEnabled || len(servers) == 0 || !m.retainedAfterEmptyDiscovery || !m.hasVPNDNSStateLocked() {
		return false
	}

	logger := m.logger.Load()
	if logger != nil {
		logger.Debug().Msgf(
			"VPN DNS transport failed for %s while retained VPN DNS state is active; suppressing OS fallback for this query (servers=%v)",
			domain, servers)
	}
	return true
}

// VPNDNSReachable records that a VPN DNS server returned a DNS response. The
// response may be negative (NXDOMAIN/SERVFAIL); the important signal is that
// the VPN DNS transport is reachable again.
func (m *vpnDNSManager) VPNDNSReachable() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.retainedAfterEmptyDiscovery {
		logger := m.logger.Load()
		if logger != nil {
			logger.Debug().Msg("VPN DNS transport recovered; clearing retained-empty-discovery state")
		}
	}
	m.retainedAfterEmptyDiscovery = false
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

// DomainlessServers returns VPN DNS servers that have no associated domains.
// These should only be used for queries matching split-DNS rules, not for
// general OS resolver queries (to avoid polluting captive portal / DHCP flows).
func (m *vpnDNSManager) DomainlessServers() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]string{}, m.domainlessServers...)
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
	return m.currentExemptionsLocked()
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
	// Use net.JoinHostPort to correctly handle both IPv4 and IPv6 addresses.
	// Previously, the strings.Contains(":") check would skip appending ":53"
	// for IPv6 addresses (they contain colons), leaving a bare address like
	// "2a0d:6fc0:9b0:3600::1" which net.Dial rejects with "too many colons".
	// net.JoinHostPort produces "[2a0d:6fc0:9b0:3600::1]:53" as required.
	endpoint := net.JoinHostPort(server, "53")

	return &ctrld.UpstreamConfig{
		Name:     "VPN DNS",
		Type:     ctrld.ResolverTypeLegacy,
		Endpoint: endpoint,
		Timeout:  2000, // 2 second timeout for VPN DNS queries
	}
}
