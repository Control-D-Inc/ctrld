package main

import (
	"net"
	"net/netip"
	"os/exec"

	"github.com/Control-D-Inc/ctrld/internal/dns"
	"github.com/Control-D-Inc/ctrld/internal/resolvconffile"
)

// allocate loopback ip
// sudo ifconfig lo0 127.0.0.53 alias
func allocateIP(ip string) error {
	cmd := exec.Command("ifconfig", "lo0", ip, "alias")
	if err := cmd.Run(); err != nil {
		mainLog.Error().Err(err).Msg("allocateIP failed")
		return err
	}
	return nil
}

func deAllocateIP(ip string) error {
	cmd := exec.Command("ifconfig", "lo0", ip, "-alias")
	if err := cmd.Run(); err != nil {
		mainLog.Error().Err(err).Msg("deAllocateIP failed")
		return err
	}
	return nil
}

// set the dns server for the provided network interface
func setDNS(iface *net.Interface, nameservers []string) error {
	r, err := dns.NewOSConfigurator(logf, iface.Name)
	if err != nil {
		mainLog.Error().Err(err).Msg("failed to create DNS OS configurator")
		return err
	}

	ns := make([]netip.Addr, 0, len(nameservers))
	for _, nameserver := range nameservers {
		ns = append(ns, netip.MustParseAddr(nameserver))
	}

	if err := r.SetDNS(dns.OSConfig{Nameservers: ns}); err != nil {
		mainLog.Error().Err(err).Msg("failed to set DNS")
		return err
	}
	return nil
}

func resetDNS(iface *net.Interface) error {
	r, err := dns.NewOSConfigurator(logf, iface.Name)
	if err != nil {
		mainLog.Error().Err(err).Msg("failed to create DNS OS configurator")
		return err
	}

	if err := r.Close(); err != nil {
		mainLog.Error().Err(err).Msg("failed to rollback DNS setting")
		return err
	}
	return nil
}

func currentDNS(_ *net.Interface) []string {
	return resolvconffile.NameServers("")
}
