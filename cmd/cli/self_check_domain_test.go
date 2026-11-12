package cli

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Control-D-Inc/ctrld"
)

// The config check accepts any upstream key, so the self-check of "ctrld
// start" must not crash on a key such as "01" or "main".
func TestSelfCheckExternalDomain(t *testing.T) {
	controld := &ctrld.UpstreamConfig{Endpoint: "https://dns.controld.com/testuid"}
	tests := []struct {
		name      string
		upstreams map[string]*ctrld.UpstreamConfig
		want      string
	}{
		{"leading zero", map[string]*ctrld.UpstreamConfig{"01": controld}, "verify.controld.com"},
		{"name only", map[string]*ctrld.UpstreamConfig{"main": controld}, ""},
		{"no upstream", nil, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &ctrld.Config{Upstream: tc.upstreams}

			require.Equal(t, tc.want, selfCheckExternalDomain(cfg))
		})
	}
}
