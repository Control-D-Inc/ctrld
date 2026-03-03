//go:build darwin

package ctrld

import (
	"bufio"
	"context"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// DiscoverVPNDNS discovers DNS servers and search domains from VPN interfaces on macOS.
// Parses `scutil --dns` output to find VPN resolver configurations.
func DiscoverVPNDNS(ctx context.Context) []VPNDNSConfig {
	logger := *ProxyLogger.Load()

	Log(ctx, logger.Debug(), "Discovering VPN DNS configurations on macOS")

	cmd := exec.CommandContext(ctx, "scutil", "--dns")
	output, err := cmd.Output()
	if err != nil {
		Log(ctx, logger.Error().Err(err), "Failed to execute scutil --dns")
		return nil
	}

	return parseScutilOutput(ctx, string(output))
}

// parseScutilOutput parses the output of `scutil --dns` to extract VPN DNS configurations.
func parseScutilOutput(ctx context.Context, output string) []VPNDNSConfig {
	logger := *ProxyLogger.Load()

	Log(ctx, logger.Debug(), "Parsing scutil --dns output")

	resolverBlockRe := regexp.MustCompile(`resolver #(\d+)`)
	searchDomainRe := regexp.MustCompile(`search domain\[\d+\] : (.+)`)
	// Matches singular "domain : value" entries (e.g., Tailscale per-domain resolvers).
	singleDomainRe := regexp.MustCompile(`^domain\s+:\s+(.+)`)
	nameserverRe := regexp.MustCompile(`nameserver\[\d+\] : (.+)`)
	ifIndexRe := regexp.MustCompile(`if_index : (\d+) \((.+)\)`)

	var vpnConfigs []VPNDNSConfig
	var currentResolver *resolverInfo
	var allResolvers []resolverInfo

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if match := resolverBlockRe.FindStringSubmatch(line); match != nil {
			if currentResolver != nil {
				allResolvers = append(allResolvers, *currentResolver)
			}
			resolverNum, _ := strconv.Atoi(match[1])
			currentResolver = &resolverInfo{
				Number: resolverNum,
			}
			continue
		}

		if currentResolver == nil {
			continue
		}

		if match := searchDomainRe.FindStringSubmatch(line); match != nil {
			domain := strings.TrimSpace(match[1])
			if domain != "" {
				currentResolver.Domains = append(currentResolver.Domains, domain)
			}
			continue
		}

		// Parse singular "domain : value" (used by Tailscale per-domain resolvers).
		if match := singleDomainRe.FindStringSubmatch(line); match != nil {
			domain := strings.TrimSpace(match[1])
			if domain != "" {
				currentResolver.Domains = append(currentResolver.Domains, domain)
			}
			continue
		}

		if match := nameserverRe.FindStringSubmatch(line); match != nil {
			server := strings.TrimSpace(match[1])
			if ip := net.ParseIP(server); ip != nil && !ip.IsLoopback() {
				currentResolver.Servers = append(currentResolver.Servers, server)
			}
			continue
		}

		if match := ifIndexRe.FindStringSubmatch(line); match != nil {
			currentResolver.InterfaceName = strings.TrimSpace(match[2])
			continue
		}

		if strings.HasPrefix(line, "flags") {
			if idx := strings.Index(line, ":"); idx >= 0 {
				currentResolver.Flags = strings.TrimSpace(line[idx+1:])
			}
			continue
		}
	}

	if currentResolver != nil {
		allResolvers = append(allResolvers, *currentResolver)
	}

	for _, resolver := range allResolvers {
		if isSplitDNSResolver(ctx, &resolver) {
			ifaceName := resolver.InterfaceName

			// When scutil doesn't provide if_index (common with Tailscale MagicDNS
			// per-domain resolvers), look up the outbound interface from the routing
			// table. This is needed for interface-scoped pf exemptions — without the
			// interface name, we can't generate rules that let the VPN's Network
			// Extension handle DNS queries from all processes.
			if ifaceName == "" && len(resolver.Servers) > 0 {
				if routeIface := resolveInterfaceForIP(ctx, resolver.Servers[0]); routeIface != "" {
					ifaceName = routeIface
					Log(ctx, logger.Debug(), "Resolver #%d: resolved interface %q from routing table for %s",
						resolver.Number, routeIface, resolver.Servers[0])
				}
			}

			config := VPNDNSConfig{
				InterfaceName: ifaceName,
				Servers:       resolver.Servers,
				Domains:       resolver.Domains,
			}

			vpnConfigs = append(vpnConfigs, config)

			Log(ctx, logger.Debug(), "Found VPN DNS config - Interface: %s, Servers: %v, Domains: %v",
				config.InterfaceName, config.Servers, config.Domains)
		}
	}

	// Detect exit mode: if a VPN DNS server IP also appears as the system's default
	// resolver (no search domains, no Supplemental flag), the VPN is routing ALL traffic
	// (not just specific domains). In exit mode, ctrld must continue intercepting DNS
	// on the VPN interface to enforce its profile on all queries.
	defaultResolverIPs := make(map[string]bool)
	for _, resolver := range allResolvers {
		if len(resolver.Servers) > 0 && len(resolver.Domains) == 0 &&
			!strings.Contains(resolver.Flags, "Supplemental") &&
			!strings.Contains(resolver.Flags, "Scoped") {
			for _, server := range resolver.Servers {
				defaultResolverIPs[server] = true
			}
		}
	}
	for i := range vpnConfigs {
		for _, server := range vpnConfigs[i].Servers {
			if defaultResolverIPs[server] {
				vpnConfigs[i].IsExitMode = true
				Log(ctx, logger.Info(), "VPN DNS config on %s detected as EXIT MODE — server %s is also the system default resolver",
					vpnConfigs[i].InterfaceName, server)
				break
			}
		}
	}

	Log(ctx, logger.Debug(), "VPN DNS discovery completed: found %d VPN interfaces", len(vpnConfigs))
	return vpnConfigs
}

// resolveInterfaceForIP uses the macOS routing table to determine which network
// interface would be used to reach the given IP address. This is a fallback for
// when scutil --dns doesn't include if_index in the resolver entry (common with
// Tailscale MagicDNS per-domain resolvers).
//
// Runs: route -n get <ip> and parses the "interface:" line from the output.
// Returns empty string on any error (callers should treat as "unknown interface").
func resolveInterfaceForIP(ctx context.Context, ip string) string {
	logger := *ProxyLogger.Load()

	cmd := exec.CommandContext(ctx, "route", "-n", "get", ip)
	output, err := cmd.Output()
	if err != nil {
		Log(ctx, logger.Debug(), "route -n get %s failed: %v", ip, err)
		return ""
	}

	// Parse "interface: utun11" from route output.
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "interface:") {
			iface := strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
			if iface != "" && iface != "lo0" {
				return iface
			}
		}
	}
	return ""
}

type resolverInfo struct {
	Number        int
	InterfaceName string
	Servers       []string
	Domains       []string
	Flags         string // Raw flags line (e.g., "Supplemental, Request A records")
}

// isSplitDNSResolver reports whether a scutil --dns resolver entry represents a
// split DNS configuration that ctrld should forward to. Any resolver with both
// non-loopback DNS servers and search domains qualifies — this covers VPN adapters
// (F5, Tailscale, Cisco AnyConnect, etc.) and any other virtual interface that
// registers search domains (e.g., corporate proxies, containers).
//
// We intentionally avoid heuristics about interface names or domain suffixes:
// if an interface declares "these domains resolve via these servers," we honor it.
// The only exclusions are mDNS entries (bare ".local" without an interface binding).
//
// Note: loopback servers are already filtered out during parsing in parseScutilOutput.
func isSplitDNSResolver(ctx context.Context, resolver *resolverInfo) bool {
	logger := *ProxyLogger.Load()

	// Must have both DNS servers and search domains to be a useful split DNS route.
	if len(resolver.Servers) == 0 || len(resolver.Domains) == 0 {
		Log(ctx, logger.Debug(), "Resolver #%d: skipping — no servers (%d) or no domains (%d)",
			resolver.Number, len(resolver.Servers), len(resolver.Domains))
		return false
	}

	// Skip multicast DNS entries. scutil --dns shows a resolver for ".local" that
	// handles mDNS — it has no interface binding and the sole domain is "local".
	// Real VPN entries with ".local" suffix (e.g., "corp.example.com") will have an
	// interface name or additional domains.
	if len(resolver.Domains) == 1 {
		domain := strings.ToLower(strings.TrimSpace(resolver.Domains[0]))
		if domain == "local" || domain == ".local" {
			Log(ctx, logger.Debug(), "Resolver #%d: skipping — mDNS resolver", resolver.Number)
			return false
		}
	}

	Log(ctx, logger.Debug(), "Resolver #%d: split DNS resolver — interface: %q, servers: %v, domains: %v",
		resolver.Number, resolver.InterfaceName, resolver.Servers, resolver.Domains)
	return true
}
