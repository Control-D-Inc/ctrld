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
	logger := LoggerFromCtx(ctx)

	Log(ctx, logger.Debug(), "Discovering VPN DNS configurations on Windows")

	flags := winipcfg.GAAFlagIncludeGateways | winipcfg.GAAFlagIncludePrefix
	aas, err := winipcfg.GetAdaptersAddresses(syscall.AF_UNSPEC, flags)
	if err != nil {
		Log(ctx, logger.Error().Err(err), "Failed to get adapters addresses")
		return nil
	}

	Log(ctx, logger.Debug(), "Found %d network adapters", len(aas))

	// Get valid (physical/hardware) interfaces to filter them out
	validInterfacesMap := ValidInterfaces(ctx)

	var vpnConfigs []VPNDNSConfig

	for _, aa := range aas {
		// Skip adapters that are not up
		if aa.OperStatus != winipcfg.IfOperStatusUp {
			Log(ctx, logger.Debug(), "Skipping adapter %s - not up, status: %d", 
				aa.FriendlyName(), aa.OperStatus)
			continue
		}

		// Skip software loopback
		if aa.IfType == winipcfg.IfTypeSoftwareLoopback {
			Log(ctx, logger.Debug(), "Skipping %s (software loopback)", aa.FriendlyName())
			continue
		}

		// INVERT the ValidInterfaces filter: we want non-physical/non-hardware adapters
		// that are UP and have DNS servers AND DNS suffixes
		_, isValidPhysical := validInterfacesMap[aa.FriendlyName()]
		if isValidPhysical {
			Log(ctx, logger.Debug(), "Skipping %s (physical/hardware adapter)", aa.FriendlyName())
			continue
		}

		// Collect DNS servers
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

		// Collect DNS suffixes (search/match domains)
		var domains []string
		for suffix := aa.FirstDNSSuffix; suffix != nil; suffix = suffix.Next {
			domain := strings.TrimSpace(suffix.String())
			if domain != "" {
				domains = append(domains, domain)
			}
		}

		// Only include interfaces that have BOTH DNS servers AND search domains
		if len(servers) > 0 && len(domains) > 0 {
			config := VPNDNSConfig{
				InterfaceName: aa.FriendlyName(),
				Servers:       servers,
				Domains:       domains,
			}

			vpnConfigs = append(vpnConfigs, config)

			Log(ctx, logger.Debug(), "Found VPN DNS config - Interface: %s, Servers: %v, Domains: %v",
				config.InterfaceName, config.Servers, config.Domains)
		} else {
			Log(ctx, logger.Debug(), "Skipping %s - insufficient DNS config (servers: %d, domains: %d)",
				aa.FriendlyName(), len(servers), len(domains))
		}
	}

	Log(ctx, logger.Debug(), "VPN DNS discovery completed: found %d VPN interfaces", len(vpnConfigs))
	return vpnConfigs
}