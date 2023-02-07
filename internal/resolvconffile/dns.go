//go:build !js && !windows

package resolvconffile

import (
	"net"

	"tailscale.com/net/dns/resolvconffile"
)

const resolvconfPath = "/etc/resolv.conf"

func NameServersWithPort() []string {
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

func NameServers(_ string) []string {
	c, err := resolvconffile.ParseFile(resolvconfPath)
	if err != nil {
		return nil
	}
	ns := make([]string, 0, len(c.Nameservers))
	for _, nameserver := range c.Nameservers {
		ns = append(ns, nameserver.String())
	}
	return ns
}
