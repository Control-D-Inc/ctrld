package clientinfo

import (
	"sync"
)

// virtualNetworkIface is the manager for clients from virtual network interface.
type virtualNetworkIface struct {
	ip2name sync.Map // ip  => name
	mac     sync.Map // ip  => mac
}

// LookupHostnameByIP returns hostname of the given VPN client ip.
func (v *virtualNetworkIface) LookupHostnameByIP(ip string) string {
	val, ok := v.ip2name.Load(ip)
	if !ok {
		return ""
	}
	return val.(string)
}

// LookupHostnameByMac always returns empty string.
func (v *virtualNetworkIface) LookupHostnameByMac(mac string) string {
	return ""
}

// String returns the string representation of virtualNetworkIface struct.
func (v *virtualNetworkIface) String() string {
	return ""
}

// List lists all known VPN clients IP.
func (v *virtualNetworkIface) List() []string {
	if v == nil {
		return nil
	}
	var ips []string
	v.mac.Range(func(key, value any) bool {
		ips = append(ips, key.(string))
		return true
	})
	return ips
}
