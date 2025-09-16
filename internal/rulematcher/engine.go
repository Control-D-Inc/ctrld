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
// It evaluates rules in the configured order and returns the first match (if StopOnFirstMatch is true)
// or all matches (if StopOnFirstMatch is false)
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

	var allMatches []*MatchResult

	// Evaluate rules in the configured order
	for _, ruleType := range e.config.Order {
		matcher, exists := e.matchers[ruleType]
		if !exists {
			continue
		}

		matchResult := matcher.Match(ctx, req)
		if matchResult.Matched {
			allMatches = append(allMatches, matchResult)

			// If we should stop on first match, return immediately
			if e.config.StopOnFirstMatch {
				result.Upstreams = matchResult.Targets
				result.Matched = true
				result.MatchedRuleType = string(matchResult.RuleType)

				// Set the appropriate matched field based on rule type
				switch matchResult.RuleType {
				case RuleTypeNetwork:
					result.MatchedNetwork = matchResult.MatchedRule
				case RuleTypeMac:
					result.MatchedNetwork = matchResult.MatchedRule
				case RuleTypeDomain:
					result.MatchedRule = matchResult.MatchedRule
				}

				return result
			}
		}
	}

	// If we get here, either no matches were found or StopOnFirstMatch is false
	if len(allMatches) > 0 {
		// For now, we'll use the first match's targets
		// In the future, we could implement more sophisticated target merging
		result.Upstreams = allMatches[0].Targets
		result.Matched = true
		result.MatchedRuleType = string(allMatches[0].RuleType)

		// Set the appropriate matched field based on rule type
		switch allMatches[0].RuleType {
		case RuleTypeNetwork:
			result.MatchedNetwork = allMatches[0].MatchedRule
		case RuleTypeMac:
			result.MatchedNetwork = allMatches[0].MatchedRule
		case RuleTypeDomain:
			result.MatchedRule = allMatches[0].MatchedRule
		}
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
