package clientinfo

import (
	"testing"

	"github.com/Control-D-Inc/ctrld"
)

func Test_normalizeIP(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"v4", "127.0.0.1", "127.0.0.1"},
		{"v4 with index", "127.0.0.1%lo", "127.0.0.1"},
		{"v6", "fe80::1", "fe80::1"},
		{"v6 with index", "fe80::1%22002", "fe80::1"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := normalizeIP(tc.in); got != tc.want {
				t.Errorf("normalizeIP() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTable_LookupRFC1918IPv4(t *testing.T) {
	table := &Table{
		dhcp:   &dhcp{},
		arp:    &arpDiscover{},
		logger: ctrld.NopLogger,
	}

	table.ipResolvers = append(table.ipResolvers, table.dhcp)
	table.ipResolvers = append(table.ipResolvers, table.arp)

	macAddress := "cc:19:f9:8a:49:e6"
	rfc1918IPv4 := "10.0.10.245"
	table.dhcp.ip.Store(macAddress, "127.0.0.1")
	table.arp.ip.Store(macAddress, rfc1918IPv4)

	if got := table.LookupRFC1918IPv4(macAddress); got != rfc1918IPv4 {
		t.Fatalf("unexpected result, want: %s, got: %s", rfc1918IPv4, got)
	}
}

func TestTable_ListClients(t *testing.T) {
	mac := "74:56:3c:44:eb:5e"
	ipv6_1 := "2405:4803:a04b:4190:fbe9:cd14:d522:bbae"
	ipv6_2 := "2405:4803:a04b:4190:fbe9:cd14:d522:bbab"
	table := &Table{}

	// NDP init.
	table.ndp = &ndpDiscover{}
	table.ndp.mac.Store(ipv6_1, mac)
	table.ndp.mac.Store(ipv6_2, mac)
	table.ndp.ip.Store(mac, ipv6_1)
	table.ndp.ip.Store(mac, ipv6_2)
	table.ipResolvers = append(table.ipResolvers, table.ndp)
	table.macResolvers = append(table.macResolvers, table.ndp)

	hostname := "foo"
	// mdns init.
	table.mdns = &mdns{}
	table.mdns.name.Store(ipv6_2, hostname)
	table.hostnameResolvers = append(table.hostnameResolvers, table.mdns)

	for _, c := range table.ListClients() {
		if c.Hostname != hostname {
			t.Fatalf("missing hostname for client: %v", c)
		}
	}
}
