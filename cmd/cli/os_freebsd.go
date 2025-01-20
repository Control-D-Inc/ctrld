package cli

import (
	"net"
	"net/netip"
	"os/exec"

	"tailscale.com/control/controlknobs"
	"tailscale.com/health"

	"github.com/Control-D-Inc/ctrld/internal/dns"
	"github.com/Control-D-Inc/ctrld/internal/resolvconffile"
)

// allocate loopback ip
// sudo ifconfig lo0 127.0.0.53 alias
func allocateIP(ip string) error {
	cmd := exec.Command("ifconfig", "lo0", ip, "alias")
	if err := cmd.Run(); err != nil {
		mainLog.Load().Error().Err(err).Msg("allocateIP failed")
		return err
	}
	return nil
}

func deAllocateIP(ip string) error {
	cmd := exec.Command("ifconfig", "lo0", ip, "-alias")
	if err := cmd.Run(); err != nil {
		mainLog.Load().Error().Err(err).Msg("deAllocateIP failed")
		return err
	}
	return nil
}

// setDnsIgnoreUnusableInterface likes setDNS, but return a nil error if the interface is not usable.
func setDnsIgnoreUnusableInterface(iface *net.Interface, nameservers []string) error {
	return setDNS(iface, nameservers)
}

// set the dns server for the provided network interface
func setDNS(iface *net.Interface, nameservers []string) error {
	r, err := dns.NewOSConfigurator(logf, &health.Tracker{}, &controlknobs.Knobs{}, iface.Name)
	if err != nil {
		mainLog.Load().Error().Err(err).Msg("failed to create DNS OS configurator")
		return err
	}

	ns := make([]netip.Addr, 0, len(nameservers))
	for _, nameserver := range nameservers {
		ns = append(ns, netip.MustParseAddr(nameserver))
	}

	if err := r.SetDNS(dns.OSConfig{Nameservers: ns}); err != nil {
		mainLog.Load().Error().Err(err).Msg("failed to set DNS")
		return err
	}
	return nil
}

// resetDnsIgnoreUnusableInterface likes resetDNS, but return a nil error if the interface is not usable.
func resetDnsIgnoreUnusableInterface(iface *net.Interface) error {
	return resetDNS(iface)
}

func resetDNS(iface *net.Interface) error {
	r, err := dns.NewOSConfigurator(logf, &health.Tracker{}, &controlknobs.Knobs{}, iface.Name)
	if err != nil {
		mainLog.Load().Error().Err(err).Msg("failed to create DNS OS configurator")
		return err
	}

	if err := r.Close(); err != nil {
		mainLog.Load().Error().Err(err).Msg("failed to rollback DNS setting")
		return err
	}
	return nil
}

// restoreDNS restores the DNS settings of the given interface.
// this should only be executed upon turning off the ctrld service.
func restoreDNS(iface *net.Interface) (err error) {
	return err
}

func currentDNS(_ *net.Interface) []string {
	return resolvconffile.NameServers("")
}

// currentStaticDNS returns the current static DNS settings of given interface.
func currentStaticDNS(iface *net.Interface) ([]string, error) {
	return currentDNS(iface), nil
}
