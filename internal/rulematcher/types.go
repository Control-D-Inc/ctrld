package rulematcher

import (
	"context"
	"net"

	"github.com/Control-D-Inc/ctrld"
)

// RuleType represents the type of rule being matched
type RuleType string

const (
	RuleTypeNetwork RuleType = "network"
	RuleTypeMac     RuleType = "mac"
	RuleTypeDomain  RuleType = "domain"
)

// RuleMatcher defines the interface for matching different types of rules
type RuleMatcher interface {
	Match(ctx context.Context, request *MatchRequest) *MatchResult
	Type() RuleType
}

// MatchRequest contains all the information needed for rule matching
type MatchRequest struct {
	SourceIP  net.IP
	SourceMac string
	Domain    string
	Policy    *ctrld.ListenerPolicyConfig
	Config    *ctrld.Config
}

// MatchResult represents the result of a rule matching operation
type MatchResult struct {
	Matched     bool
	Targets     []string
	MatchedRule string
	RuleType    RuleType
}

// MatchingConfig defines the configuration for rule matching behavior
type MatchingConfig struct {
	Order            []RuleType `json:"order" yaml:"order"`
	StopOnFirstMatch bool       `json:"stop_on_first_match" yaml:"stop_on_first_match"`
}

// DefaultMatchingConfig returns the default matching configuration
// This maintains backward compatibility with the current behavior
func DefaultMatchingConfig() *MatchingConfig {
	return &MatchingConfig{
		Order:            []RuleType{RuleTypeNetwork, RuleTypeMac, RuleTypeDomain},
		StopOnFirstMatch: true,
	}
}
