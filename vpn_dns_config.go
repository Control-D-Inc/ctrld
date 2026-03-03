package ctrld

// VPNDNSConfig represents DNS configuration discovered from a VPN interface.
// Used by the dns-intercept mode to detect VPN split DNS settings and
// route matching queries to VPN DNS servers automatically.
type VPNDNSConfig struct {
	InterfaceName string   // VPN adapter name (e.g., "F5 Networks VPN")
	Servers       []string // DNS server IPs (e.g., ["10.20.30.1"])
	Domains       []string // Search/match domains (e.g., ["corp.example.com"])
	IsExitMode    bool     // True if this VPN is also the system default resolver (exit node mode)
}
