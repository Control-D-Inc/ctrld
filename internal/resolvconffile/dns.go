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
	nss, _ := NameserversFromFile(resolvconfPath)
	return nss
}

func NameserversFromFile(path string) ([]string, error) {
	c, err := resolvconffile.ParseFile(path)
	if err != nil {
		return nil, err
	}
	ns := make([]string, 0, len(c.Nameservers))
	for _, nameserver := range c.Nameservers {
		ns = append(ns, nameserver.String())
	}
	return ns, nil
}

// SearchDomains returns the current search domains config in /etc/resolv.conf file.
func SearchDomains() ([]dnsname.FQDN, error) {
	c, err := resolvconffile.ParseFile(resolvconfPath)
	if err != nil {
		return nil, err
	}
	return c.SearchDomains, nil
}
