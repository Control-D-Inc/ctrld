package cli

import (
	ctrld "github.com/Control-D-Inc/ctrld"
	"testing"
)

func TestCustomListener5353Contract(t *testing.T) {
	for _, tc := range []struct{ ip, target string }{
		{"127.0.0.1", "127.0.0.53"}, {"127.0.0.2", "127.0.0.53"},
		{"127.0.0.53", "127.0.0.54"}, {"192.0.2.10", "127.0.0.53"},
	} {
		t.Run(tc.ip, func(t *testing.T) {
			if !isExplicitInterceptListener(tc.ip, 5353) {
				t.Fatal("5353 was not explicit")
			}
			p := &prog{cfg: &ctrld.Config{Listener: map[string]*ctrld.ListenerConfig{"0": {IP: tc.ip, Port: 5353}}}}
			if got := p.interceptDNSTargetValue(); got != tc.target {
				t.Fatalf("target=%s want %s", got, tc.target)
			}
			current := p.cfg.Listener
			generated := map[string]*ctrld.ListenerConfig{"0": {IP: "127.0.0.1", Port: 53}}
			preserveBoundListeners(generated, current)
			if generated["0"].IP != tc.ip || generated["0"].Port != 5353 {
				t.Fatalf("generated reload lost bound listener: %+v", generated["0"])
			}
			explicit := map[string]*ctrld.ListenerConfig{"0": {IP: tc.ip, Port: 5353}}
			preserveBoundListeners(explicit, map[string]*ctrld.ListenerConfig{"0": {IP: "127.0.0.1", Port: 5354}})
			if explicit["0"].IP != tc.ip || explicit["0"].Port != 5353 {
				t.Fatalf("explicit reload normalized: %+v", explicit["0"])
			}
		})
	}
}
