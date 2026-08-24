//go:build darwin

package cli

import "testing"

func TestServiceArgumentPresent(t *testing.T) {
	out := []byte("Array {\n    /usr/local/bin/ctrld\n    run\n    --config=/Users/officer/ctrld.toml\n    --intercept-mode=dns\n}\n")
	if !serviceArgumentPresent(out, "--intercept-mode=dns") {
		t.Fatal("exact inline argument was not found")
	}
	if serviceArgumentPresent(out, "--intercept-mode") {
		t.Fatal("inline flag was mistaken for a separate flag argument")
	}
	if serviceArgumentPresent(out, "off") {
		t.Fatal("substring in an unrelated path was mistaken for the off argument")
	}
}

func TestServiceFlagPosition(t *testing.T) {
	tests := []struct {
		name         string
		entries      []string
		wantIndex    int
		wantHasValue bool
	}{
		{
			name:         "split form",
			entries:      []string{"run", "--cd=uid", "--intercept-mode", "dns"},
			wantIndex:    2,
			wantHasValue: true,
		},
		{
			name:      "inline form",
			entries:   []string{"run", "--cd=uid", "--intercept-mode=dns"},
			wantIndex: 2,
		},
		{
			name:      "flag followed by another flag",
			entries:   []string{"run", "--intercept-mode", "--config=/etc/ctrld.toml"},
			wantIndex: 1,
		},
		{
			name:      "absent",
			entries:   []string{"run", "--cd=uid"},
			wantIndex: -1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			index, hasValue := serviceFlagPosition(tc.entries, "--intercept-mode")
			if index != tc.wantIndex || hasValue != tc.wantHasValue {
				t.Fatalf("serviceFlagPosition() = (%d, %v), want (%d, %v)", index, hasValue, tc.wantIndex, tc.wantHasValue)
			}
		})
	}
}
