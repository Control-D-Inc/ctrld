package main

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Control-D-Inc/ctrld"
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
	}{
		{"Policy map matches", "192.168.0.1:0", "0", prog.cfg.Listener["0"], "abc.xyz", []string{"upstream.1", "upstream.0"}, true},
		{"Policy split matches", "192.168.0.1:0", "0", prog.cfg.Listener["0"], "abc.ru", []string{"upstream.1"}, true},
		{"Policy map for other network matches", "192.168.1.2:0", "0", prog.cfg.Listener["0"], "abc.xyz", []string{"upstream.0"}, true},
		{"No policy map for listener", "192.168.1.2:0", "1", prog.cfg.Listener["1"], "abc.ru", []string{"upstream.1"}, false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
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
			}
		})
	}
}
