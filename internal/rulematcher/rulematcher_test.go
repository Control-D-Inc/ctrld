package rulematcher

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/testhelper"
)

// Test NetworkRuleMatcher
func TestNetworkRuleMatcher(t *testing.T) {
	cfg := testhelper.SampleConfig(t)
	// Convert Cidrs to IPNets like in the original test
	for _, nc := range cfg.Network {
		for _, cidr := range nc.Cidrs {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				t.Fatal(err)
			}
			nc.IPNets = append(nc.IPNets, ipNet)
		}
	}
	matcher := &NetworkRuleMatcher{}

	tests := []struct {
		name     string
		request  *MatchRequest
		expected *MatchResult
	}{
		{
			name: "No policy",
			request: &MatchRequest{
				SourceIP: net.ParseIP("192.168.0.1"),
				Policy:   nil,
				Config:   cfg,
			},
			expected: &MatchResult{Matched: false, RuleType: RuleTypeNetwork},
		},
		{
			name: "No network rules",
			request: &MatchRequest{
				SourceIP: net.ParseIP("192.168.0.1"),
				Policy:   &ctrld.ListenerPolicyConfig{},
				Config:   cfg,
			},
			expected: &MatchResult{Matched: false, RuleType: RuleTypeNetwork},
		},
		{
			name: "Match network rule",
			request: &MatchRequest{
				SourceIP: net.ParseIP("192.168.0.1"),
				Policy:   cfg.Listener["0"].Policy,
				Config:   cfg,
			},
			expected: &MatchResult{
				Matched:     true,
				Targets:     []string{"upstream.1", "upstream.0"},
				MatchedRule: "network.0",
				RuleType:    RuleTypeNetwork,
			},
		},
		{
			name: "No match for IP",
			request: &MatchRequest{
				SourceIP: net.ParseIP("10.0.0.1"),
				Policy:   cfg.Listener["0"].Policy,
				Config:   cfg,
			},
			expected: &MatchResult{Matched: false, RuleType: RuleTypeNetwork},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := matcher.Match(context.Background(), tc.request)
			assert.Equal(t, tc.expected.Matched, result.Matched)
			assert.Equal(t, tc.expected.RuleType, result.RuleType)
			if tc.expected.Matched {
				assert.Equal(t, tc.expected.Targets, result.Targets)
				assert.Equal(t, tc.expected.MatchedRule, result.MatchedRule)
			}
		})
	}
}

// Test MacRuleMatcher
func TestMacRuleMatcher(t *testing.T) {
	cfg := testhelper.SampleConfig(t)
	matcher := &MacRuleMatcher{}

	tests := []struct {
		name     string
		request  *MatchRequest
		expected *MatchResult
	}{
		{
			name: "No policy",
			request: &MatchRequest{
				SourceMac: "14:45:A0:67:83:0A",
				Policy:    nil,
				Config:    cfg,
			},
			expected: &MatchResult{Matched: false, RuleType: RuleTypeMac},
		},
		{
			name: "No MAC rules",
			request: &MatchRequest{
				SourceMac: "14:45:A0:67:83:0A",
				Policy:    &ctrld.ListenerPolicyConfig{},
				Config:    cfg,
			},
			expected: &MatchResult{Matched: false, RuleType: RuleTypeMac},
		},
		{
			name: "Match MAC rule - exact",
			request: &MatchRequest{
				SourceMac: "14:45:A0:67:83:0A",
				Policy:    cfg.Listener["0"].Policy,
				Config:    cfg,
			},
			expected: &MatchResult{
				Matched:     true,
				Targets:     []string{"upstream.2"},
				MatchedRule: "14:45:a0:67:83:0a", // Config loading normalizes MAC addresses to lowercase
				RuleType:    RuleTypeMac,
			},
		},
		{
			name: "Match MAC rule - case insensitive",
			request: &MatchRequest{
				SourceMac: "14:54:4a:8e:08:2d",
				Policy:    cfg.Listener["0"].Policy,
				Config:    cfg,
			},
			expected: &MatchResult{
				Matched:     true,
				Targets:     []string{"upstream.2"},
				MatchedRule: "14:54:4a:8e:08:2d",
				RuleType:    RuleTypeMac,
			},
		},
		{
			name: "No match for MAC",
			request: &MatchRequest{
				SourceMac: "00:11:22:33:44:55",
				Policy:    cfg.Listener["0"].Policy,
				Config:    cfg,
			},
			expected: &MatchResult{Matched: false, RuleType: RuleTypeMac},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := matcher.Match(context.Background(), tc.request)
			assert.Equal(t, tc.expected.Matched, result.Matched)
			assert.Equal(t, tc.expected.RuleType, result.RuleType)
			if tc.expected.Matched {
				assert.Equal(t, tc.expected.Targets, result.Targets)
				assert.Equal(t, tc.expected.MatchedRule, result.MatchedRule)
			}
		})
	}
}

// Test DomainRuleMatcher
func TestDomainRuleMatcher(t *testing.T) {
	cfg := testhelper.SampleConfig(t)
	matcher := &DomainRuleMatcher{}

	tests := []struct {
		name     string
		request  *MatchRequest
		expected *MatchResult
	}{
		{
			name: "No policy",
			request: &MatchRequest{
				Domain: "example.com",
				Policy: nil,
				Config: cfg,
			},
			expected: &MatchResult{Matched: false, RuleType: RuleTypeDomain},
		},
		{
			name: "No domain rules",
			request: &MatchRequest{
				Domain: "example.com",
				Policy: &ctrld.ListenerPolicyConfig{},
				Config: cfg,
			},
			expected: &MatchResult{Matched: false, RuleType: RuleTypeDomain},
		},
		{
			name: "Match domain rule - exact",
			request: &MatchRequest{
				Domain: "example.ru",
				Policy: cfg.Listener["0"].Policy,
				Config: cfg,
			},
			expected: &MatchResult{
				Matched:     true,
				Targets:     []string{"upstream.1"},
				MatchedRule: "*.ru",
				RuleType:    RuleTypeDomain,
			},
		},
		{
			name: "Match domain rule - wildcard",
			request: &MatchRequest{
				Domain: "test.ru",
				Policy: cfg.Listener["0"].Policy,
				Config: cfg,
			},
			expected: &MatchResult{
				Matched:     true,
				Targets:     []string{"upstream.1"},
				MatchedRule: "*.ru",
				RuleType:    RuleTypeDomain,
			},
		},
		{
			name: "No match for domain",
			request: &MatchRequest{
				Domain: "example.com",
				Policy: cfg.Listener["0"].Policy,
				Config: cfg,
			},
			expected: &MatchResult{Matched: false, RuleType: RuleTypeDomain},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := matcher.Match(context.Background(), tc.request)
			assert.Equal(t, tc.expected.Matched, result.Matched)
			assert.Equal(t, tc.expected.RuleType, result.RuleType)
			if tc.expected.Matched {
				assert.Equal(t, tc.expected.Targets, result.Targets)
				assert.Equal(t, tc.expected.MatchedRule, result.MatchedRule)
			}
		})
	}
}
