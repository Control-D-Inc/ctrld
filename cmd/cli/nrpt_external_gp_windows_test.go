//go:build windows

package cli

import "testing"

func TestWFPStateNRPTPolicyOwner(t *testing.T) {
	state := &wfpState{}
	state.setNRPTPolicyOwner(nrptRuleOwnerGroupPolicy, "{GP-RULE}")
	owner, ruleName := state.nrptPolicyOwner()
	if owner != nrptRuleOwnerGroupPolicy || ruleName != "{GP-RULE}" {
		t.Fatalf("owner = %v, rule = %q", owner, ruleName)
	}

	state.setNRPTPolicyOwner(nrptRuleOwnerCtrld, "")
	owner, ruleName = state.nrptPolicyOwner()
	if owner != nrptRuleOwnerCtrld || ruleName != "" {
		t.Fatalf("owner = %v, rule = %q", owner, ruleName)
	}
}
