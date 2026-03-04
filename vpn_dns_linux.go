//go:build linux

package ctrld

import (
	"bufio"
	"context"
	"net"
	"os/exec"
	"regexp"
	"strings"
)

// DiscoverVPNDNS discovers DNS servers and search domains from VPN interfaces on Linux.
// Uses resolvectl status to find per-link DNS configurations.
func DiscoverVPNDNS(ctx context.Context) []VPNDNSConfig {
	logger := *ProxyLogger.Load()

	Log(ctx, logger.Debug(), "Discovering VPN DNS configurations on Linux")

	if configs := parseResolvectlStatus(ctx); len(configs) > 0 {
		return configs
	}

	Log(ctx, logger.Debug(), "resolvectl not available or no results, trying fallback method")
	return parseVPNInterfacesDNS(ctx)
}

func parseResolvectlStatus(ctx context.Context) []VPNDNSConfig {
	logger := *ProxyLogger.Load()

	cmd := exec.CommandContext(ctx, "resolvectl", "status")
	output, err := cmd.Output()
	if err != nil {
		Log(ctx, logger.Debug(), "Failed to execute resolvectl status: %v", err)
		return nil
	}

	Log(ctx, logger.Debug(), "Parsing resolvectl status output")

	linkRe := regexp.MustCompile(`^Link (\d+) \((.+)\):`)
	dnsServersRe := regexp.MustCompile(`^\s+DNS Servers?: (.+)`)
	dnsDomainsRe := regexp.MustCompile(`^\s+DNS Domain: (.+)`)

	var vpnConfigs []VPNDNSConfig
	var currentLink *linkInfo

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()

		if match := linkRe.FindStringSubmatch(line); match != nil {
			if currentLink != nil && isVPNLink(ctx, currentLink) {
				config := VPNDNSConfig{
					InterfaceName: currentLink.InterfaceName,
					Servers:       currentLink.Servers,
					Domains:       currentLink.Domains,
				}
				vpnConfigs = append(vpnConfigs, config)

				Log(ctx, logger.Debug(), "Found VPN DNS config - Interface: %s, Servers: %v, Domains: %v",
					config.InterfaceName, config.Servers, config.Domains)
			}

			currentLink = &linkInfo{
				InterfaceName: strings.TrimSpace(match[2]),
			}
			continue
		}

		if currentLink == nil {
			continue
		}

		if match := dnsServersRe.FindStringSubmatch(line); match != nil {
			serverList := strings.TrimSpace(match[1])
			for _, server := range strings.Fields(serverList) {
				if ip := net.ParseIP(server); ip != nil && !ip.IsLoopback() {
					currentLink.Servers = append(currentLink.Servers, server)
				}
			}
			continue
		}

		if match := dnsDomainsRe.FindStringSubmatch(line); match != nil {
			domainList := strings.TrimSpace(match[1])
			for _, domain := range strings.Fields(domainList) {
				domain = strings.TrimSpace(domain)
				if domain != "" {
					currentLink.Domains = append(currentLink.Domains, domain)
				}
			}
			continue
		}
	}

	if currentLink != nil && isVPNLink(ctx, currentLink) {
		config := VPNDNSConfig{
			InterfaceName: currentLink.InterfaceName,
			Servers:       currentLink.Servers,
			Domains:       currentLink.Domains,
		}
		vpnConfigs = append(vpnConfigs, config)

		Log(ctx, logger.Debug(), "Found VPN DNS config - Interface: %s, Servers: %v, Domains: %v",
			config.InterfaceName, config.Servers, config.Domains)
	}

	Log(ctx, logger.Debug(), "resolvectl parsing completed: found %d VPN interfaces", len(vpnConfigs))
	return vpnConfigs
}

func parseVPNInterfacesDNS(ctx context.Context) []VPNDNSConfig {
	logger := *ProxyLogger.Load()

	Log(ctx, logger.Debug(), "Using fallback method to detect VPN DNS")

	interfaces, err := net.Interfaces()
	if err != nil {
		Log(ctx, logger.Error().Err(err), "Failed to get network interfaces")
		return nil
	}

	var vpnConfigs []VPNDNSConfig

	for _, iface := range interfaces {
		if !isVPNInterfaceName(iface.Name) {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		Log(ctx, logger.Debug(), "Found potential VPN interface: %s", iface.Name)
		Log(ctx, logger.Debug(), "Fallback DNS detection not implemented for interface: %s", iface.Name)
	}

	Log(ctx, logger.Debug(), "Fallback method completed: found %d VPN interfaces", len(vpnConfigs))
	return vpnConfigs
}

type linkInfo struct {
	InterfaceName string
	Servers       []string
	Domains       []string
}

func isVPNLink(ctx context.Context, link *linkInfo) bool {
	logger := *ProxyLogger.Load()

	if len(link.Servers) == 0 || len(link.Domains) == 0 {
		Log(ctx, logger.Debug(), "Link %s: insufficient config (servers: %d, domains: %d)",
			link.InterfaceName, len(link.Servers), len(link.Domains))
		return false
	}

	if isVPNInterfaceName(link.InterfaceName) {
		Log(ctx, logger.Debug(), "Link %s: identified as VPN based on interface name", link.InterfaceName)
		return true
	}

	hasRoutingDomain := false
	for _, domain := range link.Domains {
		if strings.HasPrefix(domain, "~") {
			hasRoutingDomain = true
			break
		}
	}

	if hasRoutingDomain {
		Log(ctx, logger.Debug(), "Link %s: identified as VPN based on routing domain", link.InterfaceName)
		return true
	}

	hasPrivateDNS := false
	for _, server := range link.Servers {
		if ip := net.ParseIP(server); ip != nil && ip.IsPrivate() {
			hasPrivateDNS = true
			break
		}
	}

	hasVPNDomains := false
	for _, domain := range link.Domains {
		domain = strings.ToLower(strings.TrimPrefix(domain, "~"))
		if strings.HasSuffix(domain, ".local") ||
			strings.HasSuffix(domain, ".corp") ||
			strings.HasSuffix(domain, ".internal") ||
			strings.Contains(domain, "vpn") {
			hasVPNDomains = true
			break
		}
	}

	if hasPrivateDNS && hasVPNDomains {
		Log(ctx, logger.Debug(), "Link %s: identified as VPN based on private DNS + VPN domains", link.InterfaceName)
		return true
	}

	Log(ctx, logger.Debug(), "Link %s: not identified as VPN link", link.InterfaceName)
	return false
}

func isVPNInterfaceName(name string) bool {
	name = strings.ToLower(name)
	return strings.HasPrefix(name, "tun") ||
		strings.HasPrefix(name, "tap") ||
		strings.HasPrefix(name, "ppp") ||
		strings.HasPrefix(name, "vpn") ||
		strings.Contains(name, "vpn")
}
