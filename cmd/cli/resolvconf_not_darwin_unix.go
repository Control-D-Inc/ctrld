//go:build unix && !darwin

package cli

import (
	"net"
	"net/netip"

	"tailscale.com/util/dnsname"

	"github.com/Control-D-Inc/ctrld/internal/dns"
)

// setResolvConf sets the content of resolv.conf file using the given nameservers list.
func setResolvConf(iface *net.Interface, ns []netip.Addr) error {
	r, err := dns.NewOSConfigurator(func(format string, args ...any) {}, "lo") // interface name does not matter.
	if err != nil {
		return err
	}

	oc := dns.OSConfig{
		Nameservers:   ns,
		SearchDomains: []dnsname.FQDN{},
	}
	return r.SetDNS(oc)
}

// shouldWatchResolvconf reports whether ctrld should watch changes to resolv.conf file with given OS configurator.
func shouldWatchResolvconf() bool {
	r, err := dns.NewOSConfigurator(func(format string, args ...any) {}, "lo") // interface name does not matter.
	if err != nil {
		return false
	}
	switch r.Mode() {
	case "direct", "resolvconf":
		return true
	default:
		return false
	}
}
