// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"

	"tailscale.com/tstest"
	"tailscale.com/util/dnsname"
)

func TestOSConfigPrintable(t *testing.T) {
	ocfg := OSConfig{
		Hosts: []*HostEntry{
			{
				Addr:  netip.AddrFrom4([4]byte{100, 1, 2, 3}),
				Hosts: []string{"server", "client"},
			},
			{
				Addr:  netip.AddrFrom4([4]byte{100, 1, 2, 4}),
				Hosts: []string{"otherhost"},
			},
		},
		Nameservers: []netip.Addr{
			netip.AddrFrom4([4]byte{8, 8, 8, 8}),
		},
		SearchDomains: []dnsname.FQDN{
			dnsname.FQDN("foo.beta.controld.com."),
			dnsname.FQDN("bar.beta.controld.com."),
		},
		MatchDomains: []dnsname.FQDN{
			dnsname.FQDN("controld.com."),
		},
	}
	s := fmt.Sprintf("%+v", ocfg)

	const expected = `{Nameservers:[8.8.8.8] SearchDomains:[foo.beta.controld.com. bar.beta.controld.com.] MatchDomains:[controld.com.] Hosts:[&{Addr:100.1.2.3 Hosts:[server client]} &{Addr:100.1.2.4 Hosts:[otherhost]}]}`
	if s != expected {
		t.Errorf("format mismatch:\n   got: %s\n  want: %s", s, expected)
	}
}

func TestIsZero(t *testing.T) {
	tstest.CheckIsZero[OSConfig](t, map[reflect.Type]any{
		reflect.TypeFor[dnsname.FQDN](): dnsname.FQDN("foo.bar."),
		reflect.TypeFor[*HostEntry](): &HostEntry{
			Addr:  netip.AddrFrom4([4]byte{100, 1, 2, 3}),
			Hosts: []string{"foo", "bar"},
		},
	})
}
