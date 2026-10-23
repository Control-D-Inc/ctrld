package cli

import (
	"fmt"
	"strings"
)

// pfNoRulesMarker is what pfctl prints for a ruleset that contains nothing.
const pfNoRulesMarker = "(no rules)"

// pfFilterRuleLines reduces pfctl output to the lines that are actually pf rules.
//
// It exists because every pfctl reader here uses CombinedOutput, and pfctl on macOS
// writes "No ALTQ support in kernel" and "ALTQ related functions disabled" to stderr on
// essentially every show command, so raw output is never a clean rule list. An empty
// ruleset can also report "(no rules)", which is a status line rather than a rule.
//
// Two consequences follow from getting this wrong, and both have bitten this file:
// callers that test the output for emptiness can never see empty, and callers that feed
// the lines back into "pfctl -f -" would splice non-rule text into a ruleset and have
// the reload rejected.
//
// Registry access and platform specifics stay elsewhere; this is pure string handling
// so it can be tested on any host.
func pfFilterRuleLines(output string) []string {
	var rules []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// pfctl stderr warnings, merged in by CombinedOutput.
		if strings.Contains(line, "ALTQ") {
			continue
		}
		// Status line for an empty ruleset, not a rule.
		if line == pfNoRulesMarker {
			continue
		}
		rules = append(rules, line)
	}
	return rules
}

// pfRulesetEmpty reports whether pfctl output describes a ruleset with no rules.
//
// Use this rather than testing the raw output for emptiness: the merged stderr warnings
// described above mean a raw test is always false, so the condition it guards - an
// anchor whose contents were flushed - would never be detected.
func pfRulesetEmpty(output string) bool {
	return len(pfFilterRuleLines(output)) == 0
}

// pfContainsRule checks if any line in the slice contains the given rule string.
// Uses substring matching because pfctl may append extra tokens like " all" to rules
// (e.g., `rdr-anchor "com.controld.ctrld" all`), which would fail exact matching.
func pfContainsRule(lines []string, rule string) bool {
	for _, line := range lines {
		if strings.Contains(line, rule) {
			return true
		}
	}
	return false
}

// pfAnchorReferencesPresent reports whether ctrld's anchor references appear in the
// running ruleset, given the output of "pfctl -sn" and "pfctl -sr".
//
// Removing the references means reloading the entire main ruleset, and that reload
// carries no options section - so it resets system-wide pf options, including any
// third-party "set skip" directives. Doing that when there is nothing of ours to
// remove is pure collateral damage, which is what a startup rollback would otherwise
// cause after failing before the references were ever added.
func pfAnchorReferencesPresent(natOutput, filterOutput, anchorName string) bool {
	rdrAnchorRef := fmt.Sprintf("rdr-anchor %q", anchorName)
	anchorRef := fmt.Sprintf("anchor %q", anchorName)
	return pfContainsRule(pfFilterRuleLines(natOutput), rdrAnchorRef) ||
		pfContainsRule(pfFilterRuleLines(filterOutput), anchorRef)
}
