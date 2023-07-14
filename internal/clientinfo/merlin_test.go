package clientinfo

import (
	"testing"
)

func TestParseMerlinCustomClientList(t *testing.T) {
	tests := []struct {
		name              string
		clientList        string
		macList           []string
		hostnameList      []string
		macNotPresentList []string
	}{
		{
			"normal",
			"<client1>00:00:00:00:00:01>0>4>>",
			[]string{"00:00:00:00:00:01"},
			[]string{"client1"},
			nil,
		},
		{
			"multiple clients",
			"<client1>00:00:00:00:00:01>0>4>><client2>00:00:00:00:00:02>0>24>>",
			[]string{"00:00:00:00:00:01", "00:00:00:00:00:02"},
			[]string{"client1", "client2"},
			nil,
		},
		{
			"empty hostname",
			"<client1>00:00:00:00:00:01>0>4>><>00:00:00:00:00:02>0>24>>",
			[]string{"00:00:00:00:00:01"},
			[]string{"client1"},
			[]string{"00:00:00:00:00:02"},
		},
		{
			"empty dhcp",
			"<client1>00:00:00:00:00:01>0>4>><client 1>>>",
			[]string{"00:00:00:00:00:01"},
			[]string{"client1"},
			[]string{""},
		},
		{
			"invalid",
			"qwerty",
			nil,
			nil,
			nil,
		},
		{
			"empty",
			"",

			nil,
			nil,
			nil,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := &merlinDiscover{}
			m.parseMerlinCustomClientList(tc.clientList)
			for i, mac := range tc.macList {
				val, ok := m.hostname.Load(mac)
				if !ok {
					t.Errorf("missing hostname: %s", mac)
				}
				hostname := val.(string)
				if hostname != tc.hostnameList[i] {
					t.Errorf("hostname mismatch, want: %q, got: %q", tc.hostnameList[i], hostname)
				}
			}
			for _, mac := range tc.macNotPresentList {
				if _, ok := m.hostname.Load(mac); ok {
					t.Errorf("mac2name address %q should not be present", mac)
				}
			}
		})
	}
}
