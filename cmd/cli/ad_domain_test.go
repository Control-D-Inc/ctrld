package cli

import (
	"context"
	"testing"

	"github.com/miekg/dns"

	"github.com/Control-D-Inc/ctrld"
)

func withActiveDirectoryDomain(t *testing.T, domain string) {
	t.Helper()
	prev := activeDirectoryDomain.Load()
	setActiveDirectoryDomain(domain)
	t.Cleanup(func() { activeDirectoryDomain.Store(prev) })
}

func Test_inActiveDirectoryDomain(t *testing.T) {
	withActiveDirectoryDomain(t, "Corp.Lab.")
	for name, want := range map[string]bool{
		"corp.lab.":                        true,
		"DC01.corp.lab.":                   true,
		"_ldap._tcp.dc._msdcs.corp.lab.":   true,
		"wpad.corp.lab":                    true,
		"notcorp.lab.":                     false,
		"corp.lab.example.com.":            false,
		"13gmuaedixa.verify.controld.com.": false,
	} {
		if got := inActiveDirectoryDomain(name); got != want {
			t.Errorf("inActiveDirectoryDomain(%q) = %v, want %v", name, got, want)
		}
	}
	activeDirectoryDomain.Store(nil)
	if inActiveDirectoryDomain("dc01.corp.lab.") {
		t.Error("no AD domain recorded must match nothing")
	}
}

// A split-rule match returns before the LAN-query marking; AD names routed to
// the OS resolver must still be marked, so osResolver drops 76.76.2.0.
func Test_handleSpecialQueryTypes_ADRuleIsLanQuery(t *testing.T) {
	withActiveDirectoryDomain(t, "corp.lab")
	p := newTestProg(t)
	for _, tc := range []struct {
		name      string
		qname     string
		qtype     uint16
		upstreams []string
		wantLan   bool
	}{
		{"AD host via OS", "DC01.corp.lab.", dns.TypeA, []string{upstreamOS}, true},
		{"DC locator SRV via OS", "_ldap._tcp.dc._msdcs.corp.lab.", dns.TypeSRV, []string{upstreamOS}, true},
		{"AD name, explicit upstream", "dc01.corp.lab.", dns.TypeA, []string{upstreamPrefix + "0"}, false},
		{"bypass rule, public name", "example.com.", dns.TypeA, []string{upstreamOS}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := new(dns.Msg)
			m.SetQuestion(tc.qname, tc.qtype)
			req := &proxyRequest{msg: m, ufr: &upstreamForResult{matched: true, matchedPolicy: "My Policy", matchedNetwork: "no network", matchedRule: "*.corp.lab"}}
			ctx := context.Background()
			upstreams := tc.upstreams
			var configs []*ctrld.UpstreamConfig
			if res := p.handleSpecialQueryTypes(&ctx, req, &upstreams, &configs); res != nil {
				t.Fatalf("unexpected local answer: %v", res)
			}
			lan, _ := ctx.Value(ctrld.LanQueryCtxKey{}).(bool)
			if lan != tc.wantLan {
				t.Errorf("LAN query = %v, want %v", lan, tc.wantLan)
			}
		})
	}
}
