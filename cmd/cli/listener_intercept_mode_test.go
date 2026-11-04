package cli

import (
	"testing"

	"github.com/Control-D-Inc/ctrld"
)

func TestListenerInterceptModeExplicitOff(t *testing.T) {
	oldIntercept := interceptMode
	t.Cleanup(func() { interceptMode = oldIntercept })

	cfg := &ctrld.Config{}
	cfg.Service.InterceptMode = "dns"

	tests := []struct {
		name string
		flag string
		want string
	}{
		{name: "explicit off is final", flag: "off", want: "off"},
		{name: "empty flag falls back to config", flag: "", want: "dns"},
		{name: "explicit dns wins over config", flag: "dns", want: "dns"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			interceptMode = tc.flag
			if got := listenerInterceptMode(cfg); got != tc.want {
				t.Fatalf("listenerInterceptMode() = %q, want %q", got, tc.want)
			}
		})
	}
}
