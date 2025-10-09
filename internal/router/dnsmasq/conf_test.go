package dnsmasq

import (
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
