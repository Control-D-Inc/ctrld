package ctrld_test

import (
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/require"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/testhelper"
)

// TestValidateConfig_FirewallForwardedSourcesLenient verifies a bad
// firewall_forwarded_sources entry does not fail config validation.
//
// This field is deliberately not validated with `cidr`: validateConfig failure exits
// the process, so a hard validator would turn one typo in an MDM-pushed subnet into a
// host-wide DNS outage. Bad entries are dropped with a warning at use time instead
// (see firewallForwardedSources on darwin), which is what the docs promise.
func TestValidateConfig_FirewallForwardedSourcesLenient(t *testing.T) {
	tests := []struct {
		name    string
		sources []string
	}{
		{"malformed entry", []string{"not-a-cidr"}},
		{"missing prefix length", []string{"192.168.64.0"}},
		{"bad entry alongside good ones", []string{"192.168.64.0/24", "oops", "10.0.0.0/8"}},
		{"non-IPv4 entry", []string{"fd00::/64"}},
		{"empty string", []string{""}},
		{"valid entries", []string{"192.168.64.0/24"}},
		{"unset", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testhelper.SampleConfig(t)
			cfg.Service.FirewallForwardedSources = tc.sources
			require.NoError(t, ctrld.ValidateConfig(validator.New(), cfg),
				"a bad forwarded-source entry must not stop ctrld from starting")
		})
	}
}
