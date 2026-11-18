package cli

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Control-D-Inc/ctrld"
	"tailscale.com/net/tsaddr"
)

// maxTailscaleRoutes bounds the routes taken from one Tailscale DNS config so
// a very large App Connector set cannot grow the route table without limit.
const maxTailscaleRoutes = 10000

// tailscaleRouteRetryDelays are the waits before each retry after a failed
// LocalAPI read while quad-100 is still discovered. Retries stop after the
// last one, so a steady network costs nothing.
var tailscaleRouteRetryDelays = []time.Duration{5 * time.Second, 15 * time.Second, 60 * time.Second}

// tailscaleDNSConfig is the subset of Tailscale's LocalAPI dns-config response
// (tailcfg.DNSConfig) that ctrld reads. Routes maps a DNS suffix to the
// resolvers Tailscale uses for it: Split DNS entries and App Connector domains.
type tailscaleDNSConfig struct {
	Routes map[string][]struct {
		Addr string `json:"Addr"`
	} `json:"Routes"`
}

// tailscaleRoute is one suffix that quad-100 resolves.
type tailscaleRoute struct {
	Domain string
	// NeedsPassthrough is set when quad-100 forwards the suffix as plain DNS
	// on port 53 to a Tailscale IPv4 address. pf passes that traffic only
	// through the VPN DNS interface passthrough, which exists in non-exit mode
	// only. Everywhere else it would be redirected back to ctrld.
	NeedsPassthrough bool
}

// tailscaleResolverPath tells how quad-100 reaches one route resolver, as seen
// by ctrld's pf rules.
type tailscaleResolverPath int

const (
	// tailscaleResolverLoopFree: not plain DNS on port 53 (DoH over the
	// tailnet, peerAPI), or no upstream at all. pf never redirects it.
	tailscaleResolverLoopFree tailscaleResolverPath = iota
	// tailscaleResolverViaPassthrough: plain DNS on port 53 to a Tailscale
	// IPv4 address, reached on the tunnel interface.
	tailscaleResolverViaPassthrough
	// tailscaleResolverLoops: plain DNS on port 53 to an address the
	// passthrough does not cover (public, LAN, IPv6), or an unknown form.
	tailscaleResolverLoops
)

// classifyTailscaleResolver classifies one dnstype.Resolver Addr: a plain IP,
// an IP:port, or an http(s) URL. Unknown forms are treated as looping, so the
// suffix keeps going to Control D as it did before Tailscale routes existed.
func classifyTailscaleResolver(addr string) tailscaleResolverPath {
	addr = strings.TrimSpace(addr)
	if strings.HasPrefix(addr, "http://") || strings.HasPrefix(addr, "https://") {
		u, err := url.Parse(addr)
		if err != nil || u.Hostname() == "" {
			return tailscaleResolverLoops
		}
		if u.Port() != "53" {
			return tailscaleResolverLoopFree
		}
		ip, err := netip.ParseAddr(u.Hostname())
		if err != nil {
			return tailscaleResolverLoops
		}
		return classifyTailscalePort53(ip)
	}
	if ip, err := netip.ParseAddr(addr); err == nil {
		return classifyTailscalePort53(ip)
	}
	if ipp, err := netip.ParseAddrPort(addr); err == nil {
		if ipp.Port() != 53 {
			return tailscaleResolverLoopFree
		}
		return classifyTailscalePort53(ipp.Addr())
	}
	return tailscaleResolverLoops
}

// classifyTailscalePort53 classifies a plain port-53 resolver. The pf
// passthrough is IPv4-only and covers only the tunnel interface, which carries
// the Tailscale CGNAT range in non-exit mode.
func classifyTailscalePort53(ip netip.Addr) tailscaleResolverPath {
	ip = ip.Unmap()
	if ip.Is4() && tsaddr.CGNATRange().Contains(ip) {
		return tailscaleResolverViaPassthrough
	}
	return tailscaleResolverLoops
}

// parseTailscaleRoutes returns the sorted, normalized routes of a dns-config
// response. It drops the root, IP literals and names that cannot be DNS
// suffixes, and suffixes with a resolver that quad-100 can reach only through
// pf's port-53 redirect. Those keep going to Control D rather than loop.
func parseTailscaleRoutes(body []byte) ([]tailscaleRoute, error) {
	var cfg tailscaleDNSConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		return nil, err
	}
	byDomain := make(map[string]tailscaleRoute, len(cfg.Routes))
	looping := 0
	for suffix, resolvers := range cfg.Routes {
		domain := normalizeVPNDomain(strings.TrimPrefix(strings.TrimSpace(suffix), "*."))
		if !validTailscaleRouteDomain(domain) {
			continue
		}
		route := tailscaleRoute{Domain: domain}
		loops := false
		for _, resolver := range resolvers {
			switch classifyTailscaleResolver(resolver.Addr) {
			case tailscaleResolverViaPassthrough:
				route.NeedsPassthrough = true
			case tailscaleResolverLoops:
				loops = true
			}
		}
		if loops {
			looping++
			continue
		}
		if prev, ok := byDomain[domain]; ok {
			route.NeedsPassthrough = route.NeedsPassthrough || prev.NeedsPassthrough
		}
		byDomain[domain] = route
	}
	routes := make([]tailscaleRoute, 0, len(byDomain))
	for _, route := range byDomain {
		routes = append(routes, route)
	}
	slices.SortFunc(routes, func(a, b tailscaleRoute) int { return strings.Compare(a.Domain, b.Domain) })
	if looping > 0 {
		mainLog.Load().Debug().Msgf("Tailscale DNS config: skipped %d routes whose port-53 resolvers pf would redirect back to ctrld", looping)
	}
	if len(routes) > maxTailscaleRoutes {
		mainLog.Load().Warn().Msgf("Tailscale DNS config has %d routes; keeping the first %d", len(routes), maxTailscaleRoutes)
		routes = routes[:maxTailscaleRoutes]
	}
	return routes, nil
}

func validTailscaleRouteDomain(domain string) bool {
	if domain == "" || net.ParseIP(domain) != nil {
		return false
	}
	return !strings.ContainsAny(domain, " /:*\t\r\n")
}

// isTailscaleServiceIP reports whether server is Tailscale's DNS service
// address (quad-100) in either address family.
func isTailscaleServiceIP(server string) bool {
	ip := net.ParseIP(server)
	if ip == nil {
		return false
	}
	return ip.Equal(net.IP(tsaddr.TailscaleServiceIP().AsSlice())) ||
		ip.Equal(net.IP(tsaddr.TailscaleServiceIPv6().AsSlice()))
}

func hasTailscaleResolver(configs []ctrld.VPNDNSConfig) bool {
	for _, config := range configs {
		if slices.ContainsFunc(config.Servers, isTailscaleServiceIP) {
			return true
		}
	}
	return false
}

// withTailscaleRouteDomains returns configs with the route domains appended to
// every config whose servers include Tailscale's service IP. Other configs are
// returned unchanged, so non-Tailscale resolvers never gain these routes.
// Routes that need the pf passthrough are added only to a config that gets
// one: a named interface in non-exit mode. It also returns the set of domains
// that were added.
func withTailscaleRouteDomains(configs []ctrld.VPNDNSConfig, routes []tailscaleRoute) ([]ctrld.VPNDNSConfig, map[string]bool) {
	if len(routes) == 0 {
		return configs, nil
	}
	added := make(map[string]bool)
	out := make([]ctrld.VPNDNSConfig, len(configs))
	for i, config := range configs {
		out[i] = config
		if !slices.ContainsFunc(config.Servers, isTailscaleServiceIP) {
			continue
		}
		hasPassthrough := config.InterfaceName != "" && !config.IsExitMode
		merged := append([]string{}, config.Domains...)
		for _, route := range routes {
			if route.NeedsPassthrough && !hasPassthrough {
				continue
			}
			if !slices.Contains(merged, route.Domain) {
				merged = append(merged, route.Domain)
				added[route.Domain] = true
			}
		}
		out[i].Domains = merged
	}
	return out, added
}

// tailscaleRouteState keeps the last good Tailscale route set and the bounded
// retry after a failed read.
type tailscaleRouteState struct {
	// last is the last successful read. It is guarded by the manager's
	// discoveryMu, which every refresh holds.
	last []tailscaleRoute

	mu       sync.Mutex
	timer    *time.Timer
	next     int  // index into tailscaleRouteRetryDelays of the next retry
	retrying bool // a retry timer fired and its refresh has not read yet
	closed   bool
}

// takeRetry reports whether the refresh now reading was started by a retry.
func (s *tailscaleRouteState) takeRetry() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	retrying := s.retrying
	s.retrying = false
	return retrying
}

// scheduleRetry arms the next retry after a failed read. A failure outside a
// retry restarts the sequence unless a retry is already pending.
func (s *tailscaleRouteState) scheduleRetry(fromRetry bool, refresh func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	if !fromRetry {
		if s.timer != nil {
			return
		}
		s.next = 0
	}
	if s.next >= len(tailscaleRouteRetryDelays) {
		return
	}
	delay := tailscaleRouteRetryDelays[s.next]
	s.next++
	s.timer = time.AfterFunc(delay, func() {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return
		}
		s.timer = nil
		s.retrying = true
		s.mu.Unlock()
		refresh()
	})
}

// stopRetry cancels a pending retry and resets the sequence.
func (s *tailscaleRouteState) stopRetry() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	s.next = 0
	s.retrying = false
}

// close stops retries for good.
func (s *tailscaleRouteState) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
}

// tailscaleRoutesFor reads the Tailscale DNS routes when a discovered resolver
// is Tailscale's. After a failed read it keeps the last good set and schedules
// a bounded retry; without a Tailscale resolver it forgets the set.
// The caller must hold m.discoveryMu.
func (m *vpnDNSManager) tailscaleRoutesFor(ctx context.Context, configs []ctrld.VPNDNSConfig) []tailscaleRoute {
	fromRetry := m.tailscale.takeRetry()
	if m.discoverTailscaleRoutes == nil || !hasTailscaleResolver(configs) {
		m.tailscale.last = nil
		m.tailscale.stopRetry()
		return nil
	}
	readCtx, cancel := context.WithTimeout(ctx, tailscaleLocalAPITimeout)
	defer cancel()
	routes, err := m.discoverTailscaleRoutes(readCtx)
	if err != nil {
		ctrld.Log(ctx, ctrld.LoggerFromCtx(ctx).Debug().Err(err), "Tailscale DNS routes unavailable; keeping %d last known routes and retrying", len(m.tailscale.last))
		retry := m.retryRefresh
		if retry == nil {
			retry = func() { m.Refresh(m.backgroundCtx(), true) }
		}
		m.tailscale.scheduleRetry(fromRetry, retry)
		return m.tailscale.last
	}
	m.tailscale.last = routes
	m.tailscale.stopRetry()
	return routes
}

// backgroundCtx returns a context carrying the manager's logger for refreshes
// that start outside a caller's context, such as a Tailscale route retry.
func (m *vpnDNSManager) backgroundCtx() context.Context {
	logger := mainLog.Load()
	if m.logger != nil && m.logger.Load() != nil {
		logger = m.logger.Load()
	}
	return ctrld.LoggerCtx(context.Background(), logger)
}

// Close stops background work of the manager. It is safe on a nil manager.
func (m *vpnDNSManager) Close() {
	if m == nil {
		return
	}
	m.tailscale.close()
}
