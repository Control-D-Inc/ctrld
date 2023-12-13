package clientinfo

import (
	"testing"
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
		dhcp: &dhcp{},
		arp:  &arpDiscover{},
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
