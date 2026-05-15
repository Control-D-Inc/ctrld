package cli

import (
	"net"
	"net/netip"
	"os/exec"

	"tailscale.com/control/controlknobs"
	"tailscale.com/health"
	"tailscale.com/util/dnsname"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/dns"
)

// allocateIP allocates an IP address on the specified interface
// sudo ifconfig lo0 127.0.0.53 alias
func allocateIP(ip string) error {
	mainLog.Load().Debug().Str("ip", ip).Msg("Allocating IP address")
	cmd := exec.Command("ifconfig", "lo0", ip, "alias")
	if err := cmd.Run(); err != nil {
		mainLog.Load().Error().Err(err).Msg("allocateIP failed")
		return err
	}
	mainLog.Load().Debug().Str("ip", ip).Msg("IP address allocated successfully")
	return nil
}

// deAllocateIP deallocates an IP address from the specified interface
func deAllocateIP(ip string) error {
	mainLog.Load().Debug().Str("ip", ip).Msg("Deallocating IP address")
	cmd := exec.Command("ifconfig", "lo0", ip, "-alias")
	if err := cmd.Run(); err != nil {
		mainLog.Load().Error().Err(err).Msg("deAllocateIP failed")
		return err
	}
	mainLog.Load().Debug().Str("ip", ip).Msg("IP address deallocated successfully")
	return nil
}

// setDnsIgnoreUnusableInterface likes setDNS, but return a nil error if the interface is not usable.
func setDnsIgnoreUnusableInterface(iface *net.Interface, nameservers []string) error {
	return setDNS(iface, nameservers)
}

// set the dns server for the provided network interface
func setDNS(iface *net.Interface, nameservers []string) error {
	mainLog.Load().Debug().Str("interface", iface.Name).Strs("nameservers", nameservers).Msg("Setting DNS configuration")

	r, err := dns.NewOSConfigurator(logf, &health.Tracker{}, &controlknobs.Knobs{}, iface.Name)
	if err != nil {
		mainLog.Load().Error().Err(err).Msg("Failed to create DNS OS configurator")
		return err
	}

	ns := make([]netip.Addr, 0, len(nameservers))
	for _, nameserver := range nameservers {
		ns = append(ns, netip.MustParseAddr(nameserver))
	}

	osConfig := dns.OSConfig{
		Nameservers:   ns,
		SearchDomains: []dnsname.FQDN{},
	}
	if sds, err := searchDomains(); err == nil {
		osConfig.SearchDomains = sds
	} else {
		mainLog.Load().Debug().Err(err).Msg("Failed to get search domains list")
	}

	if err := r.SetDNS(osConfig); err != nil {
		mainLog.Load().Error().Err(err).Msg("Failed to set DNS")
		return err
	}

	mainLog.Load().Debug().Str("interface", iface.Name).Msg("DNS configuration set successfully")
	return nil
}

// resetDnsIgnoreUnusableInterface likes resetDNS, but return a nil error if the interface is not usable.
func resetDnsIgnoreUnusableInterface(iface *net.Interface) error {
	return resetDNS(iface)
}

// resetDNS resets DNS servers for the specified interface
func resetDNS(iface *net.Interface) error {
	mainLog.Load().Debug().Str("interface", iface.Name).Msg("Resetting DNS configuration")

	r, err := dns.NewOSConfigurator(logf, &health.Tracker{}, &controlknobs.Knobs{}, iface.Name)
	if err != nil {
		mainLog.Load().Error().Err(err).Msg("Failed to create DNS OS configurator")
		return err
	}

	if err := r.Close(); err != nil {
		mainLog.Load().Error().Err(err).Msg("Failed to rollback DNS setting")
		return err
	}

	mainLog.Load().Debug().Str("interface", iface.Name).Msg("DNS configuration reset successfully")
	return nil
}

// restoreDNS restores the DNS settings of the given interface.
// this should only be executed upon turning off the ctrld service.
func restoreDNS(iface *net.Interface) (err error) {
	return err
}

// currentDNS returns the current DNS servers for the specified interface
func currentDNS(_ *net.Interface) []string {
	return ctrld.CurrentNameserversFromResolvconf()
}

// currentStaticDNS returns the current static DNS settings of given interface.
func currentStaticDNS(iface *net.Interface) ([]string, error) {
	return currentDNS(iface), nil
}
