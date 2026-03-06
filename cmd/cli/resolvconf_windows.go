package cli

import (
	"net"
	"net/netip"
)

// setResolvConf sets the content of resolv.conf file using the given nameservers list.
func (p *prog) setResolvConf(_ *net.Interface, _ []netip.Addr) error {
	return nil
}

// shouldWatchResolvconf reports whether ctrld should watch changes to resolv.conf file with given OS configurator.
func shouldWatchResolvconf() bool {
	return false
}
