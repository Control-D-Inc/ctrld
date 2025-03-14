package openwrt

import (
	"io"
	"path/filepath"
	"strings"
	"testing"
)

// Sample output from https://github.com/openwrt/openwrt/pull/16806#issuecomment-2448255734
const ubusDnsmasqBefore2410 = `{
	"dnsmasq": {
		"instances": {
			"guest_dns": {
				"mount": {
					"/tmp/dnsmasq.d": "0",
					"/var/run/dnsmasq/": "1"
				}
			}
		}
	}
}`

const ubusDnsmasq2410 = `{
	"dnsmasq": {
		"instances": {
			"guest_dns": {
				"mount": {
					"/tmp/dnsmasq.guest_dns.d": "0",
					"/var/run/dnsmasq/": "1"
				}
			}
		}
	}
}`

func Test_dnsmasqConfPath(t *testing.T) {
	var dnsmasq2410expected = filepath.Join("/tmp/dnsmasq.guest_dns.d", openwrtDNSMasqConfigName)
	tests := []struct {
		name     string
		in       io.Reader
		expected string
	}{
		{"empty", strings.NewReader(""), openwrtDnsmasqDefaultConfigPath},
		{"invalid", strings.NewReader("}}"), openwrtDnsmasqDefaultConfigPath},
		{"before 24.10", strings.NewReader(ubusDnsmasqBefore2410), openwrtDnsmasqDefaultConfigPath},
		{"24.10", strings.NewReader(ubusDnsmasq2410), dnsmasq2410expected},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := dnsmasqConfPath(tc.in); got != tc.expected {
				t.Errorf("dnsmasqConfPath() = %v, want %v", got, tc.expected)
			}
		})
	}
}
