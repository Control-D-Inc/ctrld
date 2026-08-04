package cli

import (
	"testing"

	"github.com/Control-D-Inc/ctrld"
)

func TestIsExplicitInterceptListener(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		port int
		want bool
	}{
		{name: "empty", ip: "", port: 0, want: false},
		{name: "wildcard", ip: "0.0.0.0", port: 53, want: false},
		{name: "zero port", ip: "127.0.0.1", port: 0, want: false},
		{name: "default intercept listener", ip: "127.0.0.1", port: 53, want: false},
		{name: "fallback port explicit", ip: "127.0.0.1", port: 5354, want: true},
		{name: "custom loopback explicit", ip: "127.0.0.2", port: 53, want: true},
		{name: "custom address explicit", ip: "192.0.2.10", port: 53, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isExplicitInterceptListener(tt.ip, tt.port); got != tt.want {
				t.Fatalf("isExplicitInterceptListener(%q, %d) = %v, want %v", tt.ip, tt.port, got, tt.want)
			}
		})
	}
}

// TestPreserveBoundListeners is a regression test for #551: on reload, the on-disk
// generated config still declares 127.0.0.1:53, but the running listener has fallen back
// to 127.0.0.1:5354. preserveBoundListeners must keep the in-memory config on the actual
// bound port so pf rdr rules and probes do not target the dead default port.
func TestPreserveBoundListeners(t *testing.T) {
	// cur = actual running listener (fell back to 5354); newCfg = freshly read from disk (53).
	cur := map[string]*ctrld.ListenerConfig{"0": {IP: "127.0.0.1", Port: 5354}}
	newListeners := map[string]*ctrld.ListenerConfig{"0": {IP: "127.0.0.1", Port: 53}}

	preserveBoundListeners(newListeners, cur)

	if got := newListeners["0"].Port; got != 5354 {
		t.Errorf("listener port after reload = %d, want 5354 (actual bound port)", got)
	}
	if got := newListeners["0"].IP; got != "127.0.0.1" {
		t.Errorf("listener IP after reload = %q, want 127.0.0.1", got)
	}
}

// TestPreserveBoundListeners_NoChange verifies that when the on-disk config matches the
// running listener, the config is left untouched (a legitimate reload with the same port).
func TestPreserveBoundListeners_NoChange(t *testing.T) {
	cur := map[string]*ctrld.ListenerConfig{"0": {IP: "127.0.0.1", Port: 5354}}
	newListeners := map[string]*ctrld.ListenerConfig{"0": {IP: "127.0.0.1", Port: 5354}}

	preserveBoundListeners(newListeners, cur)

	if got := newListeners["0"].Port; got != 5354 {
		t.Errorf("listener port = %d, want 5354", got)
	}
}

// TestPreserveBoundListeners_MissingCurrent verifies that a listener present on disk but not
// in the current running set (e.g. newly added) is left as configured.
func TestPreserveBoundListeners_MissingCurrent(t *testing.T) {
	cur := map[string]*ctrld.ListenerConfig{"0": {IP: "127.0.0.1", Port: 5354}}
	newListeners := map[string]*ctrld.ListenerConfig{
		"0": {IP: "127.0.0.1", Port: 53},
		"1": {IP: "127.0.0.1", Port: 5355},
	}

	preserveBoundListeners(newListeners, cur)

	if got := newListeners["0"].Port; got != 5354 {
		t.Errorf("listener 0 port = %d, want 5354 (preserved)", got)
	}
	if got := newListeners["1"].Port; got != 5355 {
		t.Errorf("listener 1 port = %d, want 5355 (unchanged, no current binding)", got)
	}
}

// TestPreserveBoundListeners_ExplicitChangeNotMasked verifies that an explicit, non-default
// listener in the reloaded config is applied rather than reverted to the old bound listener.
// Reverting an explicit change would make the control-server reload comparison return 200
// instead of 201, silently dropping the new listener. Regression guard for #551 review.
func TestPreserveBoundListeners_ExplicitChangeNotMasked(t *testing.T) {
	// Running listener fell back to 5354; user reloads with an explicit new listener.
	cur := map[string]*ctrld.ListenerConfig{"0": {IP: "127.0.0.1", Port: 5354}}
	newListeners := map[string]*ctrld.ListenerConfig{"0": {IP: "127.0.0.2", Port: 5399}}

	preserveBoundListeners(newListeners, cur)

	if got := newListeners["0"].IP; got != "127.0.0.2" {
		t.Errorf("explicit listener IP = %q, want 127.0.0.2 (not reverted)", got)
	}
	if got := newListeners["0"].Port; got != 5399 {
		t.Errorf("explicit listener port = %d, want 5399 (not reverted)", got)
	}
}

// TestPreserveBoundListeners_ExplicitDefaultPreserved verifies that the default
// 127.0.0.1:53 listener remains fallback-eligible: when it diverges from the running
// fallback port it is still preserved (isExplicitInterceptListener treats :53 as non-explicit).
func TestPreserveBoundListeners_ExplicitDefaultPreserved(t *testing.T) {
	cur := map[string]*ctrld.ListenerConfig{"0": {IP: "127.0.0.1", Port: 5354}}
	newListeners := map[string]*ctrld.ListenerConfig{"0": {IP: "127.0.0.1", Port: 53}}

	preserveBoundListeners(newListeners, cur)

	if got := newListeners["0"].Port; got != 5354 {
		t.Errorf("default listener port = %d, want 5354 (preserved fallback)", got)
	}
}
