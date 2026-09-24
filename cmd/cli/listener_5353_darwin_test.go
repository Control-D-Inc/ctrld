//go:build darwin

package cli

import (
	"fmt"
	ctrld "github.com/Control-D-Inc/ctrld"
	"strings"
	"testing"
)

func TestPFScopedNameserverAddress(t *testing.T) {
	for _, tc := range []struct{ server, host, family string }{
		{"[fe80::1%en0]:53", "fe80::1", "inet6"},
		{"2001:db8::53", "2001:db8::53", "inet6"},
		{"192.0.2.53:53", "192.0.2.53", "inet"},
	} {
		host, family, ok := pfNameserverAddress(tc.server)
		if !ok || host != tc.host || family != tc.family {
			t.Fatalf("PF nameserver %q: %q %q %v", tc.server, host, family, ok)
		}
	}
	if _, _, ok := pfNameserverAddress("not an address"); ok {
		t.Fatal("invalid PF address accepted")
	}
}

func TestPFRecoveryScopedNameserverRules(t *testing.T) {
	captureDebugMainLog(t)
	p := &prog{cfg: &ctrld.Config{Listener: map[string]*ctrld.ListenerConfig{"0": {IP: "127.0.0.2", Port: 5353}}}}
	// Recovery converts OS-discovered addresses into this exemption list.
	rules := p.buildPFAnchorRulesForTunnels([]vpnDNSExemption{
		{Server: "fe80::1%en0"}, {Server: "fe80::1%en1"}, {Server: "192.0.2.53"},
	}, nil)
	want := "pass out quick on ! lo0 inet6 proto { udp, tcp } from any to fe80::1 port 53 group " + pfGroupName
	if strings.Count(rules, want) != 1 {
		t.Fatalf("scoped recovery exemption missing or duplicated: %s", rules)
	}
	if strings.Contains(rules, "%en0") || strings.Contains(rules, "%en1") || strings.Contains(rules, "inet proto { udp, tcp } from any to fe80:") {
		t.Fatal("socket zone or IPv4 family leaked into recovery PF rules")
	}
	if !strings.Contains(rules, "inet proto { udp, tcp } from any to 192.0.2.53 port 53 group "+pfGroupName) {
		t.Fatal("IPv4 recovery exemption changed")
	}
}

func TestCustomListener5353PFRules(t *testing.T) {
	captureDebugMainLog(t)
	for _, ip := range []string{"127.0.0.1", "127.0.0.2", "127.0.0.53", "192.0.2.10"} {
		t.Run(ip, func(t *testing.T) {
			p := &prog{cfg: &ctrld.Config{Listener: map[string]*ctrld.ListenerConfig{"0": {IP: ip, Port: 5353}}}}
			rules := p.buildPFAnchorRulesForTunnels(nil, []string{"utun9"})
			for _, proto := range []string{"udp", "tcp"} {
				want := fmt.Sprintf("rdr on lo0 inet proto %s from any to ! %s port 53 -> %s port 5353", proto, ip, ip)
				if !strings.Contains(rules, want) {
					t.Errorf("missing redirect %s", want)
				}
			}
			if strings.Contains(rules, "port 5354") {
				t.Fatal("explicit port replaced with automatic fallback")
			}
			if p.interceptDNSTargetValue() == ip {
				t.Fatal("target equals rdr exclusion: no port translation")
			}
		})
	}
}
