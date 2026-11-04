package cli

import (
	"slices"
	"strings"
	"testing"
)

// pfStatusEnabled is "pfctl -si" output from a Mac with pf enabled.
const pfStatusEnabled = `Status: Enabled for 0 days 02:11:05           Debug: Urgent
`

// Captured from macOS 26.6 with ctrld installed. "pfctl -sr" prints the scrub and
// filter anchors, "pfctl -sn" prints the translation anchors, and both carry the
// ALTQ warnings because every reader here uses CombinedOutput.
const pfShowRules = altqNoise + `scrub-anchor "com.apple/*" all fragment reassemble
anchor "com.apple/*" all
anchor "com.controld.ctrld" all
pass in quick on lo0 reply-to lo0 inet proto udp from any to 127.0.0.1 port = 5354
`

const pfShowNAT = altqNoise + `nat-anchor "com.apple/*" all
rdr-anchor "com.apple/*" all
rdr-anchor "com.controld.ctrld" all
`

func Test_parsePFAnchorNames(t *testing.T) {
	tests := []struct {
		name  string
		rules string
		nat   string
		want  []string
	}{
		{
			name:  "a real ruleset with ctrld installed",
			rules: pfShowRules,
			nat:   pfShowNAT,
			want:  []string{"com.apple/*", "com.controld.ctrld"},
		},
		{
			// The names arrive out of order, so the result proves the sort.
			name: "a VPN adds its own anchors",
			rules: altqNoise + `anchor "windscribe" all
anchor "com.apple/*" all
`,
			nat: altqNoise + `dummynet-anchor "com.apple/*" all
rdr-anchor "windscribe" all
`,
			want: []string{"com.apple/*", "windscribe"},
		},
		{
			name:  "anchors in the translation output only",
			rules: altqNoise,
			nat:   altqNoise + "rdr-anchor \"com.controld.ctrld\" all\n",
			want:  []string{"com.controld.ctrld"},
		},
		{
			name:  "a ruleset with no anchor",
			rules: altqNoise + "block drop in all\n",
			nat:   altqNoise + "(no rules)\n",
			want:  nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parsePFAnchorNames(strings.NewReader(tc.rules), strings.NewReader(tc.nat))
			if !slices.Equal(got, tc.want) {
				t.Fatalf("parsePFAnchorNames() = %v, want %v", got, tc.want)
			}
		})
	}
}

func Test_parsePFStatus(t *testing.T) {
	tests := []struct {
		name        string
		output      string
		wantEnabled bool
		wantSince   string
	}{
		{
			name: "enabled with an uptime",
			output: altqNoise + `Status: Enabled for 3 days 02:11:05           Debug: Urgent

Interface Stats for en0             IPv4             IPv6
  Bytes In                     123456789                0
`,
			wantEnabled: true,
			wantSince:   "3 days 02:11:05",
		},
		{
			name:   "disabled",
			output: altqNoise + "Status: Disabled                              Debug: Urgent\n\n",
		},
		{
			name:        "enabled without an uptime",
			output:      "Status: Enabled                               Debug: Urgent\n",
			wantEnabled: true,
		},
		{
			name:   "no status line",
			output: altqNoise,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			enabled, since := parsePFStatus(strings.NewReader(tc.output))
			if enabled != tc.wantEnabled || since != tc.wantSince {
				t.Fatalf("parsePFStatus() = %v, %q, want %v, %q", enabled, since, tc.wantEnabled, tc.wantSince)
			}
		})
	}
}

// oversizedLine is longer than the largest line a scanner holds, so the read
// of it stops with an error.
var oversizedLine = strings.Repeat("a", 70<<10) + "\n"

// Test_parsePFAnchorNamesRejectsAnOversizedLine covers a truncated read. The
// names collected before the error read as a ruleset that lost its anchors,
// and that is the state the watchdog acts on.
func Test_parsePFAnchorNamesRejectsAnOversizedLine(t *testing.T) {
	if got := parsePFAnchorNames(strings.NewReader(pfShowRules+oversizedLine), strings.NewReader(pfShowNAT)); got != nil {
		t.Fatalf("anchor names of a truncated rule list = %v, want none", got)
	}
	if got := parsePFAnchorNames(strings.NewReader(pfShowRules), strings.NewReader(pfShowNAT+oversizedLine)); got != nil {
		t.Fatalf("anchor names of a truncated translation list = %v, want none", got)
	}
}

// Test_parsePFStatusRejectsAnOversizedLine covers a truncated status read.
func Test_parsePFStatusRejectsAnOversizedLine(t *testing.T) {
	enabled, since := parsePFStatus(strings.NewReader(oversizedLine + pfStatusEnabled))
	if enabled || since != "" {
		t.Fatalf("pf status of a truncated read = %v, %q, want false and an empty uptime", enabled, since)
	}
}
