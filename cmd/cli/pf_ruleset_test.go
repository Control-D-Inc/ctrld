package cli

import "testing"

// altqNoise is what macOS pfctl writes to stderr on show commands. Because every
// pfctl reader here uses CombinedOutput, it lands in the middle of the data being
// parsed — which is why these helpers exist.
const altqNoise = "No ALTQ support in kernel\nALTQ related functions disabled\n"

// TestPFRulesetEmpty is the regression guard for a flushed anchor being undetectable.
//
// The anchor-content checks in verifyPFState and ensurePFAnchorActive decide whether pf
// still has ctrld's rules. Testing the raw pfctl output for emptiness can never be true
// on macOS, because the merged ALTQ warnings are always present — so a genuinely flushed
// anchor reads as healthy and neither the startup gate nor the watchdog restore fires.
func TestPFRulesetEmpty(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   bool
	}{
		{
			// The case that was broken: nothing but merged stderr.
			name:   "only ALTQ warnings",
			output: altqNoise,
			want:   true,
		},
		{
			// As captured on macOS 26.6 from "pfctl -sn -a com.controld.ctrld".
			name:   "ALTQ warnings plus the empty-ruleset marker",
			output: altqNoise + "(no rules)\n",
			want:   true,
		},
		{
			name:   "empty output",
			output: "",
			want:   true,
		},
		{
			name:   "whitespace only",
			output: "\n  \n\t\n",
			want:   true,
		},
		{
			name:   "a real rdr rule behind the warnings",
			output: altqNoise + "rdr on lo0 inet proto udp from any to ! 127.0.0.1 port = 53 -> 127.0.0.1 port 5354\n",
			want:   false,
		},
		{
			name:   "a real filter rule behind the warnings",
			output: altqNoise + "pass in quick on lo0 reply-to lo0 inet proto udp from any to 127.0.0.1 port = 5354\n",
			want:   false,
		},
		{
			name:   "rule with no warnings at all",
			output: "anchor \"com.controld.ctrld\" all\n",
			want:   false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := pfRulesetEmpty(tc.output); got != tc.want {
				t.Errorf("pfRulesetEmpty() = %v, want %v\noutput:\n%s", got, tc.want, tc.output)
			}
		})
	}
}

// TestPFFilterRuleLines checks what survives filtering, since these lines are fed back
// into "pfctl -f -" by the ruleset-rebuild paths. Splicing a warning or the
// empty-ruleset marker into a ruleset would have the reload rejected outright.
func TestPFFilterRuleLines(t *testing.T) {
	got := pfFilterRuleLines(altqNoise + "(no rules)\nrdr-anchor \"com.controld.ctrld\" all\n\nanchor \"com.controld.ctrld\" all\n")
	want := []string{
		`rdr-anchor "com.controld.ctrld" all`,
		`anchor "com.controld.ctrld" all`,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d lines %q, want %d %q", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}

	if lines := pfFilterRuleLines(altqNoise); lines != nil {
		t.Errorf("warnings alone must yield no rule lines, got %q", lines)
	}
}

// TestPFAnchorReferencesPresent guards when the main ruleset may be rewritten.
//
// Removing our anchor references means reloading the whole main ruleset, and that
// reload carries no options section — so it resets system-wide pf options, including
// third-party "set skip" directives. Startup rollback runs after failures that happen
// before the references were ever added, so without this check it would reset another
// application's pf options while removing nothing of ours.
func TestPFAnchorReferencesPresent(t *testing.T) {
	const anchor = "com.controld.ctrld"
	const otherAppRules = "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.vendor.vpn\" all\n"

	tests := []struct {
		name   string
		nat    string
		filter string
		want   bool
	}{
		{
			name:   "both references present",
			nat:    altqNoise + "rdr-anchor \"com.controld.ctrld\" all\n",
			filter: altqNoise + "anchor \"com.controld.ctrld\" all\n",
			want:   true,
		},
		{
			// pfctl appends tokens like " all", so matching is substring-based.
			name:   "rdr reference only",
			nat:    altqNoise + "rdr-anchor \"com.controld.ctrld\" all\n",
			filter: altqNoise + otherAppRules,
			want:   true,
		},
		{
			name:   "filter reference only",
			nat:    altqNoise,
			filter: altqNoise + "anchor \"com.controld.ctrld\"\n",
			want:   true,
		},
		{
			// The rollback case: we failed before adding anything, and another
			// application owns the ruleset. Rewriting it would be pure collateral.
			name:   "someone else's ruleset, none of ours",
			nat:    altqNoise,
			filter: altqNoise + otherAppRules,
			want:   false,
		},
		{
			name:   "empty ruleset",
			nat:    altqNoise + "(no rules)\n",
			filter: altqNoise + "(no rules)\n",
			want:   false,
		},
		{
			// A different anchor whose name merely contains ours must not count.
			name:   "another anchor with a similar name",
			nat:    altqNoise,
			filter: altqNoise + "anchor \"com.vendor.controld-shim\" all\n",
			want:   false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := pfAnchorReferencesPresent(tc.nat, tc.filter, anchor); got != tc.want {
				t.Errorf("pfAnchorReferencesPresent() = %v, want %v", got, tc.want)
			}
		})
	}
}
