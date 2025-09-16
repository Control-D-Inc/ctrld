package rulematcher

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/Control-D-Inc/ctrld/testhelper"
)

func TestMatchingEngine(t *testing.T) {
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

	tests := []struct {
		name     string
		config   *MatchingConfig
		request  *MatchRequest
		expected *MatchingResult
	}{
		{
			name:   "Default config - network match first",
			config: DefaultMatchingConfig(),
			request: &MatchRequest{
				SourceIP:  net.ParseIP("192.168.0.1"),
				SourceMac: "14:45:A0:67:83:0A",
				Domain:    "example.ru",
				Policy:    cfg.Listener["0"].Policy,
				Config:    cfg,
			},
			expected: &MatchingResult{
				Upstreams:       []string{"upstream.1"},
				MatchedPolicy:   "My Policy",
				MatchedNetwork:  "network.0 (unenforced)",
				MatchedRule:     "*.ru",
				Matched:         true,
				SrcAddr:         "192.168.0.1",
				MatchedRuleType: "domain",
				MatchingOrder:   []RuleType{RuleTypeNetwork, RuleTypeMac, RuleTypeDomain},
			},
		},
		{
			name: "Custom order - domain first",
			config: &MatchingConfig{
				Order: []RuleType{RuleTypeDomain, RuleTypeNetwork, RuleTypeMac},
			},
			request: &MatchRequest{
				SourceIP:  net.ParseIP("192.168.0.1"),
				SourceMac: "14:45:A0:67:83:0A",
				Domain:    "example.ru",
				Policy:    cfg.Listener["0"].Policy,
				Config:    cfg,
			},
			expected: &MatchingResult{
				Upstreams:       []string{"upstream.1"},
				MatchedPolicy:   "My Policy",
				MatchedNetwork:  "network.0 (unenforced)",
				MatchedRule:     "*.ru",
				Matched:         true,
				SrcAddr:         "192.168.0.1",
				MatchedRuleType: "domain",
				MatchingOrder:   []RuleType{RuleTypeDomain, RuleTypeNetwork, RuleTypeMac},
			},
		},
		{
			name: "Custom order - MAC first",
			config: &MatchingConfig{
				Order: []RuleType{RuleTypeMac, RuleTypeNetwork, RuleTypeDomain},
			},
			request: &MatchRequest{
				SourceIP:  net.ParseIP("192.168.0.1"),
				SourceMac: "14:45:A0:67:83:0A",
				Domain:    "example.ru",
				Policy:    cfg.Listener["0"].Policy,
				Config:    cfg,
			},
			expected: &MatchingResult{
				Upstreams:       []string{"upstream.1"},
				MatchedPolicy:   "My Policy",
				MatchedNetwork:  "network.0 (unenforced)",
				MatchedRule:     "*.ru",
				Matched:         true,
				SrcAddr:         "192.168.0.1",
				MatchedRuleType: "domain",
				MatchingOrder:   []RuleType{RuleTypeMac, RuleTypeNetwork, RuleTypeDomain},
			},
		},
		{
			name:   "No policy",
			config: DefaultMatchingConfig(),
			request: &MatchRequest{
				SourceIP:  net.ParseIP("192.168.0.1"),
				SourceMac: "14:45:A0:67:83:0A",
				Domain:    "example.ru",
				Policy:    nil,
				Config:    cfg,
			},
			expected: &MatchingResult{
				Upstreams:       []string{},
				MatchedPolicy:   "no policy",
				MatchedNetwork:  "no network",
				MatchedRule:     "no rule",
				Matched:         false,
				SrcAddr:         "192.168.0.1",
				MatchedRuleType: "",
				MatchingOrder:   []RuleType{RuleTypeNetwork, RuleTypeMac, RuleTypeDomain},
			},
		},
		{
			name:   "No matches",
			config: DefaultMatchingConfig(),
			request: &MatchRequest{
				SourceIP:  net.ParseIP("10.0.0.1"),
				SourceMac: "00:11:22:33:44:55",
				Domain:    "example.com",
				Policy:    cfg.Listener["0"].Policy,
				Config:    cfg,
			},
			expected: &MatchingResult{
				Upstreams:       []string{},
				MatchedPolicy:   "My Policy",
				MatchedNetwork:  "no network",
				MatchedRule:     "no rule",
				Matched:         false,
				SrcAddr:         "10.0.0.1",
				MatchedRuleType: "",
				MatchingOrder:   []RuleType{RuleTypeNetwork, RuleTypeMac, RuleTypeDomain},
			},
		},
		{
			name:   "MAC rule overrides network rule",
			config: DefaultMatchingConfig(),
			request: &MatchRequest{
				SourceIP:  net.ParseIP("192.168.0.1"),
				SourceMac: "14:45:A0:67:83:0A",
				Domain:    "example.com", // This domain doesn't match any domain rules
				Policy:    cfg.Listener["0"].Policy,
				Config:    cfg,
			},
			expected: &MatchingResult{
				Upstreams:       []string{"upstream.2"},
				MatchedPolicy:   "My Policy",
				MatchedNetwork:  "14:45:a0:67:83:0a",
				MatchedRule:     "no rule",
				Matched:         true,
				SrcAddr:         "192.168.0.1",
				MatchedRuleType: "mac",
				MatchingOrder:   []RuleType{RuleTypeNetwork, RuleTypeMac, RuleTypeDomain},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			engine := NewMatchingEngine(tc.config)
			result := engine.FindUpstreams(context.Background(), tc.request)

			assert.Equal(t, tc.expected.Upstreams, result.Upstreams)
			assert.Equal(t, tc.expected.MatchedPolicy, result.MatchedPolicy)
			assert.Equal(t, tc.expected.MatchedNetwork, result.MatchedNetwork)
			assert.Equal(t, tc.expected.MatchedRule, result.MatchedRule)
			assert.Equal(t, tc.expected.Matched, result.Matched)
			assert.Equal(t, tc.expected.SrcAddr, result.SrcAddr)
			assert.Equal(t, tc.expected.MatchedRuleType, result.MatchedRuleType)
			assert.Equal(t, tc.expected.MatchingOrder, result.MatchingOrder)
		})
	}
}

func TestDefaultMatchingConfig(t *testing.T) {
	config := DefaultMatchingConfig()

	assert.Equal(t, []RuleType{RuleTypeNetwork, RuleTypeMac, RuleTypeDomain}, config.Order)
}

func TestMatchingEngineWithInvalidRuleType(t *testing.T) {
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

	config := &MatchingConfig{
		Order: []RuleType{RuleType("invalid"), RuleTypeNetwork},
	}

	engine := NewMatchingEngine(config)
	request := &MatchRequest{
		SourceIP: net.ParseIP("192.168.0.1"),
		Policy:   cfg.Listener["0"].Policy,
		Config:   cfg,
	}

	result := engine.FindUpstreams(context.Background(), request)

	// Should still work, just skip the invalid rule type
	assert.True(t, result.Matched)
	assert.Equal(t, "network", result.MatchedRuleType)
}
