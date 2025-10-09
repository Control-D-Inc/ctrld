package resolvconffile

import (
	"net"

	"tailscale.com/net/dns/resolvconffile"
	"tailscale.com/util/dnsname"
)

const resolvconfPath = "/etc/resolv.conf"

// NameServersWithPort retrieves a list of nameservers with the default DNS port 53 appended to each address.
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

// NameServers retrieves a list of nameservers from the /etc/resolv.conf file
// Returns an empty slice if reading fails.
func NameServers() []string {
	nss, _ := NameserversFromFile(resolvconfPath)
	return nss
}

// NameserversFromFile reads nameserver addresses from the specified resolv.conf file
// and returns them as a slice of strings.
//
// Returns an error if the file cannot be parsed.
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
