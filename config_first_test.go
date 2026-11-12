package ctrld_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Control-D-Inc/ctrld"
)

// The config check accepts any upstream key, so FirstUpstream must not crash
// on a key such as "01" or "main". ctrld makes internal_N keys itself.
func TestFirstUpstream(t *testing.T) {
	tests := []struct {
		name string
		keys []string
		want string
	}{
		{"lowest number", []string{"1", "0"}, "0"},
		{"numeric order", []string{"10", "2"}, "2"},
		{"leading zero", []string{"01"}, "01"},
		{"leading zero next to a number", []string{"02", "1"}, "1"},
		{"plain number before leading zero", []string{"01", "1"}, "1"},
		{"two leading zeros", []string{"01", "001"}, "001"},
		{"name next to a number", []string{"main", "internal_1", "3"}, "3"},
		{"name only", []string{"main"}, ""},
		{"internal only", []string{"internal_0"}, ""},
		{"no upstream", nil, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &ctrld.Config{Upstream: map[string]*ctrld.UpstreamConfig{}}
			for _, k := range tc.keys {
				cfg.Upstream[k] = &ctrld.UpstreamConfig{Name: k}
			}

			got := cfg.FirstUpstream()

			if tc.want == "" {
				require.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			require.Equal(t, tc.want, got.Name)
		})
	}
}

// The router cleanup reads the config from disk with no check, and asks
// FirstListener whether ctrld listens on port 53 itself. It must get an
// answer, not a crash, for a key that is not a number.
func TestFirstListener(t *testing.T) {
	tests := []struct {
		name string
		keys []string
		want string
	}{
		{"lowest number", []string{"1", "0"}, "0"},
		{"numeric order", []string{"10", "2"}, "2"},
		{"leading zero", []string{"01"}, "01"},
		{"plain number before leading zero", []string{"01", "1"}, "1"},
		{"name next to a number", []string{"main", "4"}, "4"},
		{"name only", []string{"main"}, ""},
		{"no listener", nil, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &ctrld.Config{Listener: map[string]*ctrld.ListenerConfig{}}
			for i, k := range tc.keys {
				cfg.Listener[k] = &ctrld.ListenerConfig{IP: k, Port: 53 + i}
			}

			var got *ctrld.ListenerConfig
			require.NotPanics(t, func() {
				got = cfg.FirstListener()
				_ = got.IsDirectDnsListener()
			})

			if tc.want == "" {
				require.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			require.Equal(t, tc.want, got.IP)
		})
	}
}
