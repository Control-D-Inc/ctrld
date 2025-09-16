package rulematcher

import (
	"context"
	"strings"
)

// MacRuleMatcher handles matching of MAC address-based rules
type MacRuleMatcher struct{}

// Type returns the rule type for MAC matcher
func (m *MacRuleMatcher) Type() RuleType {
	return RuleTypeMac
}

// Match evaluates MAC address rules against the source MAC address
func (m *MacRuleMatcher) Match(ctx context.Context, req *MatchRequest) *MatchResult {
	if req.Policy == nil || len(req.Policy.Macs) == 0 {
		return &MatchResult{Matched: false, RuleType: RuleTypeMac}
	}

	for _, rule := range req.Policy.Macs {
		for source, targets := range rule {
			if source != "" && (strings.EqualFold(source, req.SourceMac) || wildcardMatches(strings.ToLower(source), strings.ToLower(req.SourceMac))) {
				return &MatchResult{
					Matched:     true,
					Targets:     targets,
					MatchedRule: source, // Return the original source from the rule
					RuleType:    RuleTypeMac,
				}
			}
		}
	}

	return &MatchResult{Matched: false, RuleType: RuleTypeMac}
}

// wildcardMatches checks if a wildcard pattern matches a string
// This is copied from the original implementation to maintain compatibility
func wildcardMatches(wildcard, str string) bool {
	if wildcard == "" {
		return false
	}
	if wildcard == "*" {
		return true
	}
	if !strings.Contains(wildcard, "*") {
		return wildcard == str
	}

	parts := strings.Split(wildcard, "*")
	if len(parts) != 2 {
		return false
	}

	prefix := parts[0]
	suffix := parts[1]

	if prefix != "" && !strings.HasPrefix(str, prefix) {
		return false
	}
	if suffix != "" && !strings.HasSuffix(str, suffix) {
		return false
	}

	return true
}
