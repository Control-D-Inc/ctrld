package dnsmasq

import (
	"io"
	"strings"
	"testing"
)

func Test_interfaceNameFromReader(t *testing.T) {
	tests := []struct {
		name      string
		in        string
		wantIface string
	}{
		{
			"good",
			`interface=lo`,
			"lo",
		},
		{
			"multiple",
			`interface=lo
interface=eth0
`,
			"lo",
		},
		{
			"no iface",
			`cache-size=100`,
			"",
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ifaceName, err := interfaceNameFromReader(strings.NewReader(tc.in))
			if tc.wantIface != "" && err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if tc.wantIface != ifaceName {
				t.Errorf("mismatched, want: %q, got: %q", tc.wantIface, ifaceName)
			}
		})
	}
}

func Test_leaseFileFromReader(t *testing.T) {
	tests := []struct {
		name     string
		in       io.Reader
		expected string
	}{
		{
			"default",
			strings.NewReader(`
dhcp-script=/sbin/dhcpc_lease
dhcp-leasefile=/var/lib/misc/dnsmasq-1.leases
script-arp
`),
			"/var/lib/misc/dnsmasq-1.leases",
		},
		{
			"non-default",
			strings.NewReader(`
dhcp-script=/sbin/dhcpc_lease
dhcp-leasefile=/tmp/var/lib/misc/dnsmasq-1.leases
script-arp
`),
			"/tmp/var/lib/misc/dnsmasq-1.leases",
		},
		{
			"missing",
			strings.NewReader(`
dhcp-script=/sbin/dhcpc_lease
script-arp
`),
			"",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := leaseFileFromReader(tc.in); got != tc.expected {
				t.Errorf("leaseFileFromReader() = %v, want %v", got, tc.expected)
			}
		})
	}

}
