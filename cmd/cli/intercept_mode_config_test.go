package cli

import (
	"testing"

	"github.com/Control-D-Inc/ctrld"
)

func TestUpdateConfigInterceptMode(t *testing.T) {
	tests := []struct {
		name        string
		current     string
		mode        string
		want        string
		wantUpdated bool
	}{
		{name: "empty flag preserves config", current: "dns", mode: "", want: "dns"},
		{name: "dns is persisted", mode: "dns", want: "dns", wantUpdated: true},
		{name: "hard is persisted", current: "dns", mode: "hard", want: "hard", wantUpdated: true},
		{name: "off clears persisted mode", current: "dns", mode: "off", want: "", wantUpdated: true},
		{name: "off is idempotent", mode: "off", want: ""},
		{name: "invalid flag preserves config", current: "hard", mode: "invalid", want: "hard"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &ctrld.Config{}
			cfg.Service.InterceptMode = tc.current
			updated := updateConfigInterceptMode(cfg, tc.mode)
			if updated != tc.wantUpdated {
				t.Fatalf("updateConfigInterceptMode() updated = %v, want %v", updated, tc.wantUpdated)
			}
			if cfg.Service.InterceptMode != tc.want {
				t.Fatalf("service.intercept_mode = %q, want %q", cfg.Service.InterceptMode, tc.want)
			}
		})
	}
}
