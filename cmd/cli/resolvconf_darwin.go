package cli

import (
	"net"
	"net/netip"
	"os"
	"slices"

	"github.com/Control-D-Inc/ctrld/internal/dns/resolvconffile"
)

const resolvConfPath = "/etc/resolv.conf"

// setResolvConf sets the content of resolv.conf file using the given nameservers list.
func setResolvConf(iface *net.Interface, ns []netip.Addr) error {
	servers := make([]string, len(ns))
	for i := range ns {
		servers[i] = ns[i].String()
	}
	if err := setDNS(iface, servers); err != nil {
		return err
	}
	slices.Sort(servers)
	curNs := currentDNS(iface)
	slices.Sort(curNs)
	if !slices.Equal(curNs, servers) {
		c, err := resolvconffile.ParseFile(resolvConfPath)
		if err != nil {
			return err
		}
		c.Nameservers = ns
		f, err := os.Create(resolvConfPath)
		if err != nil {
			return err
		}
		defer f.Close()

		if err := c.Write(f); err != nil {
			return err
		}
		return f.Close()
	}
	return nil
}

// shouldWatchResolvconf reports whether ctrld should watch changes to resolv.conf file with given OS configurator.
func shouldWatchResolvconf() bool {
	return true
}
