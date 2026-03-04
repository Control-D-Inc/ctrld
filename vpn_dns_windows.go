//go:build windows

package ctrld

import (
	"context"
	"strings"
	"syscall"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// DiscoverVPNDNS discovers DNS servers and search domains from non-physical (VPN) interfaces.
// Only called when dnsIntercept is active.
func DiscoverVPNDNS(ctx context.Context) []VPNDNSConfig {
	logger := *ProxyLogger.Load()

	Log(ctx, logger.Debug(), "Discovering VPN DNS configurations on Windows")

	flags := winipcfg.GAAFlagIncludeGateways | winipcfg.GAAFlagIncludePrefix
	aas, err := winipcfg.GetAdaptersAddresses(syscall.AF_UNSPEC, flags)
	if err != nil {
		Log(ctx, logger.Error().Err(err), "Failed to get adapters addresses")
		return nil
	}

	Log(ctx, logger.Debug(), "Found %d network adapters", len(aas))

	// Get valid (physical/hardware) interfaces to filter them out
	validInterfacesMap := validInterfaces()

	var vpnConfigs []VPNDNSConfig

	for _, aa := range aas {
		if aa.OperStatus != winipcfg.IfOperStatusUp {
			Log(ctx, logger.Debug(), "Skipping adapter %s - not up, status: %d",
				aa.FriendlyName(), aa.OperStatus)
			continue
		}

		if aa.IfType == winipcfg.IfTypeSoftwareLoopback {
			Log(ctx, logger.Debug(), "Skipping %s (software loopback)", aa.FriendlyName())
			continue
		}

		// INVERT the validInterfaces filter: we want non-physical/non-hardware adapters
		_, isValidPhysical := validInterfacesMap[aa.FriendlyName()]
		if isValidPhysical {
			Log(ctx, logger.Debug(), "Skipping %s (physical/hardware adapter)", aa.FriendlyName())
			continue
		}

		// Skip adapters that have no routable unicast addresses. An adapter
		// with only link-local (fe80::) or APIPA (169.254.x.x) addresses is
		// not actually connected — its DNS servers are stale. This prevents
		// picking up e.g. Tailscale's adapter when the app is installed but
		// disconnected (OperStatus reports Up but only APIPA addresses exist).
		hasRoutableAddr := false
		for a := aa.FirstUnicastAddress; a != nil; a = a.Next {
			ip := a.Address.IP()
			if ip == nil {
				continue
			}
			if !ip.IsLinkLocalUnicast() {
				hasRoutableAddr = true
				break
			}
		}
		if !hasRoutableAddr {
			Log(ctx, logger.Debug(), "Skipping %s - no routable addresses (likely disconnected)", aa.FriendlyName())
			continue
		}

		var servers []string
		for dns := aa.FirstDNSServerAddress; dns != nil; dns = dns.Next {
			ip := dns.Address.IP()
			if ip == nil {
				continue
			}

			ipStr := ip.String()
			if ip.IsLoopback() {
				continue
			}

			servers = append(servers, ipStr)
		}

		// Check adapter-specific (connection-specific) DNS suffix first,
		// since we want to map per-adapter DNS servers to per-adapter suffixes.
		// This is what most traditional VPNs set (F5, Cisco AnyConnect, GlobalProtect).
		var domains []string
		if connSuffix := strings.TrimSpace(aa.DNSSuffix()); connSuffix != "" {
			domains = append(domains, connSuffix)
			Log(ctx, logger.Debug(), "Using connection-specific DNS suffix for %s: %s",
				aa.FriendlyName(), connSuffix)
		}

		// Then check supplemental DNS suffix list (used by Tailscale and
		// VPN clients that register search domains via the DNS Client API).
		for suffix := aa.FirstDNSSuffix; suffix != nil; suffix = suffix.Next {
			domain := strings.TrimSpace(suffix.String())
			if domain != "" {
				domains = append(domains, domain)
			}
		}

		// Accept VPN adapters with DNS servers even without domains.
		// Domain-less configs still provide useful DNS server IPs that
		// can serve existing split-rules and OS resolver queries.
		if len(servers) > 0 {
			config := VPNDNSConfig{
				InterfaceName: aa.FriendlyName(),
				Servers:       servers,
				Domains:       domains,
			}

			vpnConfigs = append(vpnConfigs, config)

			Log(ctx, logger.Debug(), "Found VPN DNS config - Interface: %s, Servers: %v, Domains: %v",
				config.InterfaceName, config.Servers, config.Domains)
		} else {
			Log(ctx, logger.Debug(), "Skipping %s - no DNS servers found",
				aa.FriendlyName())
		}
	}

	Log(ctx, logger.Debug(), "VPN DNS discovery completed: found %d VPN interfaces", len(vpnConfigs))
	return vpnConfigs
}
