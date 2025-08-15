package clientinfo

import "github.com/Control-D-Inc/ctrld"

// clientInfoFiles specifies client info files and how to read them on supported platforms.
var clientInfoFiles = map[string]ctrld.LeaseFileFormat{
	"/tmp/dnsmasq.leases":                      ctrld.Dnsmasq,  // ddwrt
	"/tmp/dhcp.leases":                         ctrld.Dnsmasq,  // openwrt
	"/var/lib/misc/dnsmasq.leases":             ctrld.Dnsmasq,  // merlin
	"/mnt/data/udapi-config/dnsmasq.lease":     ctrld.Dnsmasq,  // UDM Pro
	"/data/udapi-config/dnsmasq.lease":         ctrld.Dnsmasq,  // UDR
	"/etc/dhcpd/dhcpd-leases.log":              ctrld.Dnsmasq,  // Synology
	"/tmp/var/lib/misc/dnsmasq.leases":         ctrld.Dnsmasq,  // Tomato
	"/run/dnsmasq-dhcp.leases":                 ctrld.Dnsmasq,  // EdgeOS
	"/run/dhcpd.leases":                        ctrld.IscDhcpd, // EdgeOS
	"/var/dhcpd/var/db/dhcpd.leases":           ctrld.IscDhcpd, // Pfsense
	"/home/pi/.router/run/dhcp/dnsmasq.leases": ctrld.Dnsmasq,  // Firewalla
	"/var/lib/kea/dhcp4.leases":                ctrld.KeaDHCP4, // Pfsense
	"/var/db/dnsmasq.leases":                   ctrld.Dnsmasq,  // OPNsense
}
