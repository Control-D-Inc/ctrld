package clientinfo

import (
	"sync"
)

// vpn is the manager for VPN clients info.
type vpn struct {
	ip2name sync.Map // ip  => name
	mac     sync.Map // ip  => mac
}

// LookupHostnameByIP returns hostname of the given VPN client ip.
func (v *vpn) LookupHostnameByIP(ip string) string {
	val, ok := v.ip2name.Load(ip)
	if !ok {
		return ""
	}
	return val.(string)
}

// LookupHostnameByMac always returns empty string.
func (v *vpn) LookupHostnameByMac(mac string) string {
	return ""
}

// String returns the string representation of vpn struct.
func (v *vpn) String() string {
	return "vpn"
}

// List lists all known VPN clients IP.
func (v *vpn) List() []string {
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
