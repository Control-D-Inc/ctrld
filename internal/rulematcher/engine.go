package rulematcher

import (
	"context"
)

// MatchingEngine orchestrates rule matching based on configurable order
type MatchingEngine struct {
	config   *MatchingConfig
	matchers map[RuleType]RuleMatcher
}

// NewMatchingEngine creates a new matching engine with the given configuration
func NewMatchingEngine(config *MatchingConfig) *MatchingEngine {
	if config == nil {
		config = DefaultMatchingConfig()
	}

	engine := &MatchingEngine{
		config: config,
		matchers: map[RuleType]RuleMatcher{
			RuleTypeNetwork: &NetworkRuleMatcher{},
			RuleTypeMac:     &MacRuleMatcher{},
			RuleTypeDomain:  &DomainRuleMatcher{},
		},
	}

	return engine
}

// FindUpstreams determines which upstreams should handle a request based on policy rules
// It implements the original behavior where MAC and domain rules can override network rules
func (e *MatchingEngine) FindUpstreams(ctx context.Context, req *MatchRequest) *MatchingResult {
	result := &MatchingResult{
		Upstreams:       []string{},
		MatchedPolicy:   "no policy",
		MatchedNetwork:  "no network",
		MatchedRule:     "no rule",
		Matched:         false,
		SrcAddr:         req.SourceIP.String(),
		MatchedRuleType: "",
		MatchingOrder:   e.config.Order,
	}

	if req.Policy == nil {
		return result
	}

	result.MatchedPolicy = req.Policy.Name

	var networkMatch *MatchResult
	var macMatch *MatchResult
	var domainMatch *MatchResult

	// Check all rule types and store matches
	for _, ruleType := range e.config.Order {
		matcher, exists := e.matchers[ruleType]
		if !exists {
			continue
		}

		matchResult := matcher.Match(ctx, req)
		if matchResult.Matched {
			switch matchResult.RuleType {
			case RuleTypeNetwork:
				networkMatch = matchResult
			case RuleTypeMac:
				macMatch = matchResult
			case RuleTypeDomain:
				domainMatch = matchResult
			}
		}
	}

	// Determine the final match based on original logic:
	// Domain rules override everything, MAC rules override network rules
	if domainMatch != nil {
		result.Upstreams = domainMatch.Targets
		result.Matched = true
		result.MatchedRuleType = string(domainMatch.RuleType)
		result.MatchedRule = domainMatch.MatchedRule
		// Special case: domain rules override network rules
		if networkMatch != nil {
			result.MatchedNetwork = networkMatch.MatchedRule + " (unenforced)"
		}
	} else if macMatch != nil {
		result.Upstreams = macMatch.Targets
		result.Matched = true
		result.MatchedRuleType = string(macMatch.RuleType)
		result.MatchedNetwork = macMatch.MatchedRule
	} else if networkMatch != nil {
		result.Upstreams = networkMatch.Targets
		result.Matched = true
		result.MatchedRuleType = string(networkMatch.RuleType)
		result.MatchedNetwork = networkMatch.MatchedRule
	}

	return result
}

// MatchingResult represents the result of the matching engine
type MatchingResult struct {
	Upstreams       []string
	MatchedPolicy   string
	MatchedNetwork  string
	MatchedRule     string
	Matched         bool
	SrcAddr         string
	MatchedRuleType string
	MatchingOrder   []RuleType
}
