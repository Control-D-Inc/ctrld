package cli

import (
	"net"
	"net/netip"
)

// setResolvConf sets the content of resolv.conf file using the given nameservers list.
func setResolvConf(iface *net.Interface, ns []netip.Addr) error {
	servers := make([]string, len(ns))
	for i := range ns {
		servers[i] = ns[i].String()
	}
	return setDNS(iface, servers)
}

// shouldWatchResolvconf reports whether ctrld should watch changes to resolv.conf file with given OS configurator.
func shouldWatchResolvconf() bool {
	return true
}
