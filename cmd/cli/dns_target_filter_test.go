package cli

import "testing"

func TestFilterOwnTarget(t *testing.T) {
	tests := []struct {
		name    string
		in      []string
		target  string
		wantLen int
	}{
		// The oscillation guard (MR !997 review): the second recovery on the
		// same DNS-less network must not count ctrld's own entry as
		// network-provided IPv4 DNS.
		{"removes own entry", []string{"127.0.0.1"}, "127.0.0.1", 0},
		{"removes own entry with resolver port", []string{"127.0.0.53:53"}, "127.0.0.53", 0},
		{"keeps user entries", []string{"127.0.0.1", "1.1.1.1"}, "127.0.0.1", 1},
		{"empty target keeps all", []string{"127.0.0.1"}, "", 1},
		{"no match keeps all", []string{"1.1.1.1"}, "127.0.0.53", 1},
		{"nil input", nil, "127.0.0.1", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := filterOwnTarget(tc.in, tc.target)
			if len(got) != tc.wantLen {
				t.Errorf("filterOwnTarget(%v, %q) = %v, want len %d", tc.in, tc.target, got, tc.wantLen)
			}
			for _, s := range got {
				if tc.target != "" && s == tc.target {
					t.Errorf("filterOwnTarget(%v, %q) retained the target entry", tc.in, tc.target)
				}
			}
		})
	}
}

// TestFilterOwnTargetStability pins the recovery-cycle contract: on a
// DNS-less network where ctrld already set its target, needsInterceptDNSTarget
// over the filtered list must still report true (entry kept, no oscillation),
// while a genuine user-added IPv4 server must report false (entry removed).
func TestFilterOwnTargetStability(t *testing.T) {
	target := "127.0.0.1"

	// Second recovery, same tether: only our own entry present. The OS resolver
	// reports it with :53, while networksetup reports the bare address.
	static := filterOwnTarget([]string{target}, target)
	discovered := filterOwnTarget([]string{target + ":53"}, target)
	if !needsInterceptDNSTarget(static, discovered) {
		t.Error("second recovery on the same DNS-less network would remove the target (oscillation)")
	}

	// User manually added a public server meanwhile: target no longer needed.
	static = filterOwnTarget([]string{target, "1.1.1.1"}, target)
	if needsInterceptDNSTarget(static, nil) {
		t.Error("user-added IPv4 DNS not recognized; target would be kept unnecessarily")
	}
}
