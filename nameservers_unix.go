//go:build !js && !windows

package ctrld

import (
	"net"

	"tailscale.com/net/dns/resolvconffile"
)

const resolvconfPath = "/etc/resolv.conf"

func nameservers() []string {
	c, err := resolvconffile.ParseFile(resolvconfPath)
	if err != nil {
		return nil
	}
	ns := make([]string, 0, len(c.Nameservers))
	for _, nameserver := range c.Nameservers {
		ns = append(ns, net.JoinHostPort(nameserver.String(), "53"))
	}
	return ns
}
