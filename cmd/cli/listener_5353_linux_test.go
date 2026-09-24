//go:build linux

package cli

import (
	ctrld "github.com/Control-D-Inc/ctrld"
	"net"
	"testing"
)

// Socket-only Linux control. Native macOS PF delivery is a separate QA gate.
func TestCustomListener5353Binding(t *testing.T) {
	captureDebugMainLog(t)
	for _, ip := range []string{"127.0.0.1", "127.0.0.2"} {
		t.Run(ip, func(t *testing.T) {
			cfg := &ctrld.Config{Listener: map[string]*ctrld.ListenerConfig{"0": {IP: ip, Port: 5353}}}
			changed, ok := tryUpdateListenerConfigIntercept(cfg, func() {}, false)
			if !ok || changed {
				t.Fatalf("custom listener did not bind unchanged: changed=%v ok=%v", changed, ok)
			}
			occupied, err := net.Listen("tcp4", net.JoinHostPort(ip, "5353"))
			if err != nil {
				t.Fatal(err)
			}
			defer occupied.Close()
			changed, ok = tryUpdateListenerConfigIntercept(cfg, func() {}, false)
			if ok || changed || cfg.Listener["0"].IP != ip || cfg.Listener["0"].Port != 5353 {
				t.Fatal("occupied explicit listener silently fell back")
			}
		})
	}
}
