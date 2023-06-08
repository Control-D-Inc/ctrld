package router

import (
	"io"
	"strings"
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

func Test_readClientInfoReader(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		readFunc func(r io.Reader) error
		mac      string
	}{
		{
			"good dnsmasq",
			`1683329857 e6:20:59:b8:c1:6d 192.168.1.186 * 01:e6:20:59:b8:c1:6d
`,
			dnsmasqReadClientInfoReader,
			"e6:20:59:b8:c1:6d",
		},
		{
			"bad dnsmasq seen on UDMdream machine",
			`1683329857 e6:20:59:b8:c1:6e 192.168.1.111 * 01:e6:20:59:b8:c1:6e
duid 00:01:00:01:2b:e4:2e:2c:52:52:14:26:dc:1c
1683322985 117442354 2600:4040:b0e6:b700::111 ASDASD 00:01:00:01:2a:d0:b9:81:00:07:32:4c:1c:07
`,
			dnsmasqReadClientInfoReader,
			"e6:20:59:b8:c1:6e",
		},
		{
			"isc-dhcpd good",
			`lease 192.168.1.1 {
    hardware ethernet 00:00:00:00:00:01;
    client-hostname "host-1";
}
`,
			iscDHCPReadClientInfoReader,
			"00:00:00:00:00:01",
		},
		{
			"isc-dhcpd bad mac",
			`lease 192.168.1.1 {
    hardware ethernet invalid-mac;
    client-hostname "host-1";
}

lease 192.168.1.2 {
    hardware ethernet 00:00:00:00:00:02;
    client-hostname "host-2";
}
`,
			iscDHCPReadClientInfoReader,
			"00:00:00:00:00:02",
		},
		{
			"",
			`1685794060 00:00:00:00:00:04 192.168.0.209 cuonglm-ThinkPad-X1-Carbon-Gen-9 00:00:00:00:00:04 9`,
			dnsmasqReadClientInfoReader,
			"00:00:00:00:00:04",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := routerPlatform.Load()
			r.mac.Delete(tc.mac)
			if err := tc.readFunc(strings.NewReader(tc.in)); err != nil {
				t.Errorf("readClientInfoReader() error = %v", err)
			}
			info, existed := r.mac.Load(tc.mac)
			if !existed {
				t.Error("client info missing")
			}
			if ci, ok := info.(*ctrld.ClientInfo); ok && existed && ci.Mac != tc.mac {
				t.Errorf("mac mismatched, got: %q, want: %q", ci.Mac, tc.mac)
			} else {
				t.Log(ci)
			}
		})
	}
}
