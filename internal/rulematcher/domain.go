package rulematcher

import (
	"context"
)

// DomainRuleMatcher handles matching of domain-based rules
type DomainRuleMatcher struct{}

// Match evaluates domain rules against the requested domain
func (d *DomainRuleMatcher) Match(ctx context.Context, req *MatchRequest) *MatchResult {
	if req.Policy == nil || len(req.Policy.Rules) == 0 {
		return &MatchResult{Matched: false, RuleType: RuleTypeDomain}
	}

	for _, rule := range req.Policy.Rules {
		// There's only one entry per rule, config validation ensures this.
		for source, targets := range rule {
			if source == req.Domain || wildcardMatches(source, req.Domain) {
				return &MatchResult{
					Matched:     true,
					Targets:     targets,
					MatchedRule: source,
					RuleType:    RuleTypeDomain,
				}
			}
		}
	}

	return &MatchResult{Matched: false, RuleType: RuleTypeDomain}
}
