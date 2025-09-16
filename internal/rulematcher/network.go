package rulematcher

import (
	"context"
	"strings"
)

// NetworkRuleMatcher handles matching of network-based rules
type NetworkRuleMatcher struct{}

// Type returns the rule type for network matcher
func (n *NetworkRuleMatcher) Type() RuleType {
	return RuleTypeNetwork
}

// Match evaluates network rules against the source IP address
func (n *NetworkRuleMatcher) Match(ctx context.Context, req *MatchRequest) *MatchResult {
	if req.Policy == nil || len(req.Policy.Networks) == 0 {
		return &MatchResult{Matched: false, RuleType: RuleTypeNetwork}
	}

	for _, rule := range req.Policy.Networks {
		for source, targets := range rule {
			networkNum := strings.TrimPrefix(source, "network.")
			nc := req.Config.Network[networkNum]
			if nc == nil {
				continue
			}
			for _, ipNet := range nc.IPNets {
				if ipNet.Contains(req.SourceIP) {
					return &MatchResult{
						Matched:     true,
						Targets:     targets,
						MatchedRule: source,
						RuleType:    RuleTypeNetwork,
					}
				}
			}
		}
	}

	return &MatchResult{Matched: false, RuleType: RuleTypeNetwork}
}
