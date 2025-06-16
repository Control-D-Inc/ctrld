//go:build !js && !windows

package resolvconffile

import (
	"net"

	"tailscale.com/net/dns/resolvconffile"
	"tailscale.com/util/dnsname"
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

func NameServers() []string {
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

// SearchDomains returns the current search domains config in /etc/resolv.conf file.
func SearchDomains() ([]dnsname.FQDN, error) {
	c, err := resolvconffile.ParseFile(resolvconfPath)
	if err != nil {
		return nil, err
	}
	return c.SearchDomains, nil
}
