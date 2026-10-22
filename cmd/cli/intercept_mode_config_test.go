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
		// "off" is kept as "off": an unset value now means the platform
		// default, which is "dns" on Windows and macOS (issue #589).
		{name: "off replaces persisted dns", current: "dns", mode: "off", want: "off", wantUpdated: true},
		{name: "off replaces persisted hard", current: "hard", mode: "off", want: "off", wantUpdated: true},
		{name: "off persists over unset", current: "", mode: "off", want: "off", wantUpdated: true},
		{name: "off already persisted", current: "off", mode: "off", want: "off"},
		{name: "dns replaces persisted off", current: "off", mode: "dns", want: "dns", wantUpdated: true},
		{name: "empty flag preserves config", current: "hard", mode: "", want: "hard"},
		{name: "empty flag leaves unset alone", current: "", mode: "", want: ""},
		{name: "new mode persists", current: "", mode: "dns", want: "dns", wantUpdated: true},
		{name: "same mode is unchanged", current: "dns", mode: "dns", want: "dns"},
		{name: "invalid mode is ignored", current: "dns", mode: "bogus", want: "dns"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &ctrld.Config{}
			cfg.Service.InterceptMode = tt.current
			if updated := updateConfigInterceptMode(cfg, tt.mode); updated != tt.wantUpdated {
				t.Fatalf("updateConfigInterceptMode() updated = %v, want %v", updated, tt.wantUpdated)
			}
			if cfg.Service.InterceptMode != tt.want {
				t.Fatalf("service.intercept_mode = %q, want %q", cfg.Service.InterceptMode, tt.want)
			}
		})
	}
}

func TestConfiguredInterceptMode(t *testing.T) {
	oldInterceptMode := interceptMode
	t.Cleanup(func() { interceptMode = oldInterceptMode })

	tests := []struct {
		name      string
		flag      string
		config    string
		supported bool
		want      string
	}{
		{name: "empty flag falls back to config", flag: "", config: "dns", supported: true, want: "dns"},
		{name: "explicit off is final", flag: "off", config: "dns", supported: true, want: "off"},
		{name: "explicit hard wins over config", flag: "hard", config: "dns", supported: true, want: "hard"},
		{name: "config off is final over the default", flag: "", config: "off", supported: true, want: "off"},
		{name: "unset uses the dns default", flag: "", config: "", supported: true, want: "dns"},
		{name: "unset on an unsupported platform stays off", flag: "", config: "", supported: false, want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			useInterceptByDefault(t, tc.supported)
			p := &prog{cfg: &ctrld.Config{}}
			p.cfg.Service.InterceptMode = tc.config
			interceptMode = tc.flag
			if got := p.configuredInterceptMode(); got != tc.want {
				t.Fatalf("configuredInterceptMode() = %q, want %q", got, tc.want)
			}
		})
	}
}
