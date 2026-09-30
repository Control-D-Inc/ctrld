package cli

import (
	"testing"

	"github.com/miekg/dns"
)

// The auto-added AD split rules route to upstream.os, and a rule match skips
// the LAN classification, so without this check every AD lookup was also sent
// to Control D's public resolver in plaintext.
func Test_isAdOSResolverLookup(t *testing.T) {
	p := &prog{adDomain: "corp.lab"}
	for _, tc := range []struct {
		name      string
		qname     string
		qtype     uint16
		upstreams []string
		want      bool
	}{
		{"AD host via OS", "DC01.corp.lab.", dns.TypeA, []string{upstreamOS}, true},
		{"DC locator SRV via OS", "_ldap._tcp.dc._msdcs.corp.lab.", dns.TypeSRV, []string{upstreamOS}, true},
		{"AD domain itself", "corp.lab.", dns.TypeA, []string{upstreamOS}, true},
		{"AD name, explicit upstream", "dc01.corp.lab.", dns.TypeA, []string{upstreamPrefix + "0"}, false},
		{"bypass rule, public name", "example.com.", dns.TypeA, []string{upstreamOS}, false},
		{"lookalike suffix", "notcorp.lab.", dns.TypeA, []string{upstreamOS}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := new(dns.Msg)
			m.SetQuestion(tc.qname, tc.qtype)
			if got := p.isAdOSResolverLookup(tc.upstreams, m); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
	if (&prog{}).isAdOSResolverLookup([]string{upstreamOS}, new(dns.Msg).SetQuestion("dc01.corp.lab.", dns.TypeA)) {
		t.Error("no AD domain must match nothing")
	}
}
