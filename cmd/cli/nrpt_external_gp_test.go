package cli

import (
	"errors"
	"fmt"
	"testing"
)

func TestIsMatchingGPNRPTRule(t *testing.T) {
	tests := []struct {
		name       string
		ruleName   string
		namespaces []string
		servers    string
		listener   string
		want       bool
	}{
		{
			name:       "exact IPv4 catch-all",
			ruleName:   "{A1B2C3D4}",
			namespaces: []string{"."},
			servers:    "127.0.0.1",
			listener:   "127.0.0.1",
			want:       true,
		},
		{
			name:       "normalized IPv4-mapped listener",
			ruleName:   "{A1B2C3D4}",
			namespaces: []string{"."},
			servers:    "::ffff:127.0.0.1",
			listener:   "127.0.0.1",
			want:       true,
		},
		{
			name:       "ctrld GP key is not external",
			ruleName:   "ctrldcatchall",
			namespaces: []string{"."},
			servers:    "127.0.0.1",
			listener:   "127.0.0.1",
		},
		{
			name:       "partial namespace",
			ruleName:   "{A1B2C3D4}",
			namespaces: []string{"corp.example"},
			servers:    "127.0.0.1",
			listener:   "127.0.0.1",
		},
		{
			name:       "multiple namespaces",
			ruleName:   "{A1B2C3D4}",
			namespaces: []string{".", "corp.example"},
			servers:    "127.0.0.1",
			listener:   "127.0.0.1",
		},
		{
			name:       "wrong listener",
			ruleName:   "{A1B2C3D4}",
			namespaces: []string{"."},
			servers:    "127.0.0.2",
			listener:   "127.0.0.1",
		},
		{
			name:       "multiple nameservers",
			ruleName:   "{A1B2C3D4}",
			namespaces: []string{"."},
			servers:    "127.0.0.1;127.0.0.2",
			listener:   "127.0.0.1",
		},
		{
			name:       "malformed nameserver",
			ruleName:   "{A1B2C3D4}",
			namespaces: []string{"."},
			servers:    "localhost",
			listener:   "127.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isMatchingGPNRPTRule(tt.ruleName, tt.namespaces, tt.servers, tt.listener); got != tt.want {
				t.Fatalf("isMatchingGPNRPTRule() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestIsExternalGPCatchAll(t *testing.T) {
	tests := []struct {
		name       string
		ruleName   string
		namespaces []string
		want       bool
	}{
		{name: "external catch-all", ruleName: "{GP-RULE}", namespaces: []string{"."}, want: true},
		{name: "ctrld key", ruleName: nrptRuleName, namespaces: []string{"."}},
		{name: "partial namespace", ruleName: "{GP-RULE}", namespaces: []string{"corp.example"}},
		{name: "multiple namespaces", ruleName: "{GP-RULE}", namespaces: []string{".", "corp.example"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isExternalGPCatchAll(tt.ruleName, tt.namespaces); got != tt.want {
				t.Fatalf("isExternalGPCatchAll() = %t, want %t", got, tt.want)
			}
		})
	}
}

// TestInterceptFailedWithVerifiedExternalDNS covers the distinction the interface-DNS
// fallback turns on. "A GP rule exists" is not enough: if it is not actually routing and
// intercept failed too, skipping the fallback leaves the machine with no NRPT, no WFP and
// no adapter DNS - that is, unfiltered. Only a probe-verified route earns the skip.
func TestInterceptFailedWithVerifiedExternalDNS(t *testing.T) {
	wfpErr := errors.New("FwpmEngineOpen0 failed: HRESULT 0x5")

	verified := fmt.Errorf("dns intercept: WFP setup failed: %w: %w", wfpErr, errGPNRPTVerified)
	if !interceptFailedWithVerifiedExternalDNS(verified) {
		t.Error("a failure carrying errGPNRPTVerified must skip the interface-DNS fallback")
	}
	if !errors.Is(verified, wfpErr) {
		t.Error("the underlying cause must stay inspectable for logs and callers")
	}

	if interceptFailedWithVerifiedExternalDNS(fmt.Errorf("dns intercept: WFP setup failed: %w", wfpErr)) {
		t.Error("an unverified failure must take the interface-DNS fallback rather than leave the machine unfiltered")
	}
	if interceptFailedWithVerifiedExternalDNS(nil) {
		t.Error("no error must not read as a verified external route")
	}
}
