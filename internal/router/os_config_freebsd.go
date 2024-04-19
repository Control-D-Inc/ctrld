package router

import (
	"encoding/xml"
	"os"
)

// Config represents /conf/config.xml file found on pfsense/opnsense.
type Config struct {
	PfsenseUnbound  *string `xml:"unbound>enable,omitempty"`
	OPNsenseUnbound *string `xml:"OPNsense>unboundplus>general>enabled,omitempty"`
	Dnsmasq         *string `xml:"dnsmasq>enable,omitempty"`
}

// DnsmasqEnabled reports whether dnsmasq is enabled.
func (c *Config) DnsmasqEnabled() bool {
	if isPfsense() { // pfsense only set the attribute if dnsmasq is enabled.
		return c.Dnsmasq != nil
	}
	return c.Dnsmasq != nil && *c.Dnsmasq == "1"
}

// UnboundEnabled reports whether unbound is enabled.
func (c *Config) UnboundEnabled() bool {
	if isPfsense() { // pfsense only set the attribute if unbound is enabled.
		return c.PfsenseUnbound != nil
	}
	return c.OPNsenseUnbound != nil && *c.OPNsenseUnbound == "1"
}

// currentConfig does unmarshalling /conf/config.xml file,
// return the corresponding *Config represent it.
func currentConfig() (*Config, error) {
	buf, _ := os.ReadFile("/conf/config.xml")
	c := Config{}
	if err := xml.Unmarshal(buf, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
