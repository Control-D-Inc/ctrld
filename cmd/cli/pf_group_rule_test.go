package cli

import "testing"

// Native-format provenance: same adapted pfctl -vvsr layout as
// pfDiagnosticFixture; the header is generatePFRules' blanket group rule as
// pfctl prints it back, with the group name resolved to a number.
const pfGroupRuleFixture = `@0 pass out quick all group = 350 flags S/SA keep state
  [ Owner : nil          Priority : 0     ]
  [ Evaluations: 359       Packets: 215       Bytes: 39876       States: 11    ]
  [ Inserted: uid 0 pid 68 ]
@1 pass out quick on ! lo0 inet proto udp from any to 192.168.77.1 port = 53 group = 350 keep state
  [ Owner : nil          Priority : 0     ]
  [ Evaluations: 183       Packets: 0         Bytes: 0           States: 0     ]
  [ Inserted: uid 0 pid 68 ]
`

func TestPFGroupRuleParse(t *testing.T) {
	s := parsePFGroupRule([]byte(pfGroupRuleFixture))
	if s.Code != "ok" || s.GID != "350" || !s.Known || s.Packets != 215 {
		t.Fatalf("group rule = %+v", s)
	}
	if got := parsePFGroupRule([]byte(pfDiagnosticFixture)); got.Code != "rule_not_observed" || got.Known {
		t.Fatalf("rule absent = %+v", got)
	}
	if got := parsePFGroupRule([]byte(pfGroupRuleFixture + pfGroupRuleFixture)); got.Code != "ambiguous_rules" || got.Known {
		t.Fatalf("duplicate = %+v", got)
	}
	// The per-server exemption also carries "group = 350"; it must not be
	// taken for the blanket rule or lend it its counter.
	only := "@1 pass out quick on ! lo0 inet proto udp from any to 192.168.77.1 port = 53 group = 350 keep state\n  [ Evaluations: 183       Packets: 9         Bytes: 0           States: 0     ]\n"
	if got := parsePFGroupRule([]byte(only)); got.Code != "rule_not_observed" {
		t.Fatalf("per-server rule taken for the blanket rule: %+v", got)
	}
	if got := parsePFGroupRule([]byte("@0 pass out quick all group = 999 flags S/SA keep state\n")); got.Code != "partial_or_malformed" || got.GID != "999" {
		t.Fatalf("no counter = %+v", got)
	}
}
