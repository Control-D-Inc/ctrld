package cli

import (
	"strings"
	"testing"
)

func Test_ensureSystemdKillMode(t *testing.T) {
	tests := []struct {
		name       string
		unitFile   string
		wantChange bool
	}{
		{"no KillMode", "[Service]\nExecStart=/bin/sleep 1", true},
		{"not KillMode=process", "[Service]\nExecStart=/bin/sleep 1\nKillMode=mixed", true},
		{"KillMode=process", "[Service]\nExecStart=/bin/sleep 1\nKillMode=process", false},
		{"invalid unit file", "[Service\nExecStart=/bin/sleep 1\nKillMode=process", false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, change := ensureSystemdKillMode(strings.NewReader(tc.unitFile)); tc.wantChange != change {
				t.Errorf("ensureSystemdKillMode(%q) = %v, want %v", tc.unitFile, change, tc.wantChange)
			}
		})
	}
}
