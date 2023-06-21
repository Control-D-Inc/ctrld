package ctrld

// ClientInfoCtxKey is the context key to store client info.
type ClientInfoCtxKey struct{}

// ClientInfo represents ctrld's clients information.
type ClientInfo struct {
	Mac      string
	IP       string
	Hostname string
}

// LeaseFileFormat specifies the format of DHCP lease file.
type LeaseFileFormat string

const (
	Dnsmasq  LeaseFileFormat = "dnsmasq"
	IscDhcpd                 = "isc-dhcpd"
)
