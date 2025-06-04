//go:build unix && !darwin

package cli

import (
	"net"
	"net/netip"

	"tailscale.com/control/controlknobs"
	"tailscale.com/health"
	"tailscale.com/util/dnsname"

	"github.com/Control-D-Inc/ctrld/internal/dns"
)

// setResolvConf sets the content of the resolv.conf file using the given nameservers list.
func setResolvConf(iface *net.Interface, ns []netip.Addr) error {
	r, err := newLoopbackOSConfigurator()
	if err != nil {
		return err
	}

	oc := dns.OSConfig{
		Nameservers:   ns,
		SearchDomains: []dnsname.FQDN{},
	}
	if sds, err := searchDomains(); err == nil {
		oc.SearchDomains = sds
	} else {
		mainLog.Load().Debug().Err(err).Msg("failed to get search domains list when reverting resolv.conf file")
	}
	return r.SetDNS(oc)
}

// shouldWatchResolvconf reports whether ctrld should watch changes to resolv.conf file with given OS configurator.
func shouldWatchResolvconf() bool {
	r, err := newLoopbackOSConfigurator()
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

// newLoopbackOSConfigurator creates an OSConfigurator for DNS management using the "lo" interface.
func newLoopbackOSConfigurator() (dns.OSConfigurator, error) {
	return dns.NewOSConfigurator(noopLogf, &health.Tracker{}, &controlknobs.Knobs{}, "lo")
}
