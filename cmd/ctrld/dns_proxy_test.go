package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/dnscache"
	"github.com/Control-D-Inc/ctrld/testhelper"
)

func Test_wildcardMatches(t *testing.T) {
	tests := []struct {
		name     string
		wildcard string
		domain   string
		match    bool
	}{
		{"prefix parent should not match", "*.windscribe.com", "windscribe.com", false},
		{"prefix", "*.windscribe.com", "anything.windscribe.com", true},
		{"prefix not match other domain", "*.windscribe.com", "example.com", false},
		{"prefix not match domain in name", "*.windscribe.com", "wwindscribe.com", false},
		{"suffix", "suffix.*", "suffix.windscribe.com", true},
		{"suffix not match other", "suffix.*", "suffix1.windscribe.com", false},
		{"both", "suffix.*.windscribe.com", "suffix.anything.windscribe.com", true},
		{"both not match", "suffix.*.windscribe.com", "suffix1.suffix.windscribe.com", false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := wildcardMatches(tc.wildcard, tc.domain); got != tc.match {
				t.Errorf("unexpected result, wildcard: %s, domain: %s, want: %v, got: %v", tc.wildcard, tc.domain, tc.match, got)
			}
		})
	}
}

func Test_canonicalName(t *testing.T) {
	tests := []struct {
		name      string
		domain    string
		canonical string
	}{
		{"fqdn to canonical", "windscribe.com.", "windscribe.com"},
		{"already canonical", "windscribe.com", "windscribe.com"},
		{"case insensitive", "Windscribe.Com.", "windscribe.com"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := canonicalName(tc.domain); got != tc.canonical {
				t.Errorf("unexpected result, want: %s, got: %s", tc.canonical, got)
			}
		})
	}
}

func Test_prog_upstreamFor(t *testing.T) {
	cfg := testhelper.SampleConfig(t)
	prog := &prog{cfg: cfg}
	for _, nc := range prog.cfg.Network {
		for _, cidr := range nc.Cidrs {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				t.Fatal(err)
			}
			nc.IPNets = append(nc.IPNets, ipNet)
		}
	}

	tests := []struct {
		name               string
		ip                 string
		defaultUpstreamNum string
		lc                 *ctrld.ListenerConfig
		domain             string
		upstreams          []string
		matched            bool
		testLogMsg         string
	}{
		{"Policy map matches", "192.168.0.1:0", "0", prog.cfg.Listener["0"], "abc.xyz", []string{"upstream.1", "upstream.0"}, true, ""},
		{"Policy split matches", "192.168.0.1:0", "0", prog.cfg.Listener["0"], "abc.ru", []string{"upstream.1"}, true, ""},
		{"Policy map for other network matches", "192.168.1.2:0", "0", prog.cfg.Listener["0"], "abc.xyz", []string{"upstream.0"}, true, ""},
		{"No policy map for listener", "192.168.1.2:0", "1", prog.cfg.Listener["1"], "abc.ru", []string{"upstream.1"}, false, ""},
		{"unenforced loging", "192.168.1.2:0", "0", prog.cfg.Listener["0"], "abc.ru", []string{"upstream.1"}, true, "My Policy, network.1 (unenforced), *.ru -> [upstream.1]"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, network := range []string{"udp", "tcp"} {
				var (
					addr net.Addr
					err  error
				)
				switch network {
				case "udp":
					addr, err = net.ResolveUDPAddr(network, tc.ip)
				case "tcp":
					addr, err = net.ResolveTCPAddr(network, tc.ip)
				}
				require.NoError(t, err)
				require.NotNil(t, addr)
				ctx := context.WithValue(context.Background(), ctrld.ReqIdCtxKey{}, requestID())
				upstreams, matched := prog.upstreamFor(ctx, tc.defaultUpstreamNum, tc.lc, addr, tc.domain)
				assert.Equal(t, tc.matched, matched)
				assert.Equal(t, tc.upstreams, upstreams)
				if tc.testLogMsg != "" {
					assert.Contains(t, logOutput.String(), tc.testLogMsg)
				}
			}
		})
	}
}

func TestCache(t *testing.T) {
	cfg := testhelper.SampleConfig(t)
	prog := &prog{cfg: cfg}
	for _, nc := range prog.cfg.Network {
		for _, cidr := range nc.Cidrs {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				t.Fatal(err)
			}
			nc.IPNets = append(nc.IPNets, ipNet)
		}
	}
	cacher, err := dnscache.NewLRUCache(4096)
	require.NoError(t, err)
	prog.cache = cacher

	msg := new(dns.Msg)
	msg.SetQuestion("example.com", dns.TypeA)
	msg.MsgHdr.RecursionDesired = true
	answer1 := new(dns.Msg)
	answer1.SetRcode(msg, dns.RcodeSuccess)

	prog.cache.Add(dnscache.NewKey(msg, "upstream.1"), dnscache.NewValue(answer1, time.Now().Add(time.Minute)))
	answer2 := new(dns.Msg)
	answer2.SetRcode(msg, dns.RcodeRefused)
	prog.cache.Add(dnscache.NewKey(msg, "upstream.0"), dnscache.NewValue(answer2, time.Now().Add(time.Minute)))

	got1 := prog.proxy(context.Background(), []string{"upstream.1"}, nil, msg)
	got2 := prog.proxy(context.Background(), []string{"upstream.0"}, nil, msg)
	assert.NotSame(t, got1, got2)
	assert.Equal(t, answer1.Rcode, got1.Rcode)
	assert.Equal(t, answer2.Rcode, got2.Rcode)
}

func Test_macFromMsg(t *testing.T) {
	tests := []struct {
		name    string
		mac     string
		wantMac bool
	}{
		{"has mac", "4c:20:b8:ab:87:1b", true},
		{"no mac", "4c:20:b8:ab:87:1b", false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			hw, err := net.ParseMAC(tc.mac)
			if err != nil {
				t.Fatal(err)
			}
			m := new(dns.Msg)
			m.SetQuestion(selfCheckFQDN+".", dns.TypeA)
			o := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
			if tc.wantMac {
				ec1 := &dns.EDNS0_LOCAL{Code: EDNS0_OPTION_MAC, Data: hw}
				o.Option = append(o.Option, ec1)
			}
			m.Extra = append(m.Extra, o)
			got := macFromMsg(m)
			if tc.wantMac && got != tc.mac {
				t.Errorf("mismatch, want: %q, got: %q", tc.mac, got)
			}
			if !tc.wantMac && got != "" {
				t.Errorf("unexpected mac: %q", got)
			}
		})
	}
}
