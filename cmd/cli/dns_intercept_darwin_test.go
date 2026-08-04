//go:build darwin

package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/Control-D-Inc/ctrld"
)

// =============================================================================
// buildPFAnchorRules tests
// =============================================================================

func TestPFBuildAnchorRules_Basic(t *testing.T) {
	p := &prog{cfg: &ctrld.Config{Listener: map[string]*ctrld.ListenerConfig{"0": {IP: "127.0.0.1", Port: 53}}}}
	rules := p.buildPFAnchorRules(nil)

	// rdr (translation) must come before pass (filtering)
	rdrIdx := strings.Index(rules, "rdr on lo0 inet proto udp")
	passRouteIdx := strings.Index(rules, "pass out quick on ! lo0 route-to lo0 inet proto udp")
	passInIdx := strings.Index(rules, "pass in quick on lo0 reply-to lo0")

	if rdrIdx < 0 {
		t.Fatal("missing rdr rule")
	}
	if passRouteIdx < 0 {
		t.Fatal("missing pass out route-to rule")
	}
	if passInIdx < 0 {
		t.Fatal("missing pass in on lo0 rule")
	}
	if rdrIdx >= passRouteIdx {
		t.Error("rdr rules must come before pass out route-to rules")
	}
	if passRouteIdx >= passInIdx {
		t.Error("pass out route-to must come before pass in on lo0")
	}

	// Both UDP and TCP rdr rules
	if !strings.Contains(rules, "proto udp") || !strings.Contains(rules, "proto tcp") {
		t.Error("must have both UDP and TCP rdr rules")
	}
}

func TestPFBuildAnchorRules_WithVPNServers(t *testing.T) {
	p := &prog{cfg: &ctrld.Config{Listener: map[string]*ctrld.ListenerConfig{"0": {IP: "127.0.0.1", Port: 53}}}}
	vpnServers := []vpnDNSExemption{
		{Server: "10.8.0.1"},
		{Server: "10.8.0.2"},
	}
	rules := p.buildPFAnchorRules(vpnServers)

	// VPN exemption rules must appear
	for _, s := range vpnServers {
		if !strings.Contains(rules, s.Server) {
			t.Errorf("missing VPN exemption for %s", s.Server)
		}
	}

	// VPN exemptions must come before route-to
	exemptIdx := strings.Index(rules, "10.8.0.1 port 53 group")
	routeIdx := strings.Index(rules, "pass out quick on ! lo0 route-to lo0 inet proto udp")
	if exemptIdx < 0 {
		t.Fatal("missing VPN exemption rule for 10.8.0.1")
	}
	if routeIdx < 0 {
		t.Fatal("missing route-to rule")
	}
	if exemptIdx >= routeIdx {
		t.Error("VPN exemptions must come before route-to rules")
	}
}

func TestPFBuildAnchorRules_IPv4AndIPv6VPN(t *testing.T) {
	p := &prog{cfg: &ctrld.Config{Listener: map[string]*ctrld.ListenerConfig{"0": {IP: "127.0.0.1", Port: 53}}}}
	vpnServers := []vpnDNSExemption{
		{Server: "10.8.0.1"},
		{Server: "fd00::1"},
	}
	rules := p.buildPFAnchorRules(vpnServers)

	// IPv4 server should use "inet"
	lines := strings.Split(rules, "\n")
	for _, line := range lines {
		if strings.Contains(line, "10.8.0.1") && strings.HasPrefix(line, "pass") {
			if !strings.Contains(line, "inet ") {
				t.Error("IPv4 VPN server rule should contain 'inet'")
			}
			if strings.Contains(line, "inet6") {
				t.Error("IPv4 VPN server rule should not contain 'inet6'")
			}
		}
		if strings.Contains(line, "fd00::1") && strings.HasPrefix(line, "pass") {
			if !strings.Contains(line, "inet6") {
				t.Error("IPv6 VPN server rule should contain 'inet6'")
			}
		}
	}
}

func TestPFBuildAnchorRules_Ordering(t *testing.T) {
	p := &prog{cfg: &ctrld.Config{Listener: map[string]*ctrld.ListenerConfig{"0": {IP: "127.0.0.1", Port: 53}}}}
	vpnServers := []vpnDNSExemption{
		{Server: "10.8.0.1"},
	}
	rules := p.buildPFAnchorRules(vpnServers)

	// Verify ordering: rdr → exemptions → route-to → pass in on lo0
	rdrIdx := strings.Index(rules, "rdr on lo0 inet proto udp")
	exemptIdx := strings.Index(rules, "pass out quick on ! lo0 inet proto { udp, tcp } from any to 10.8.0.1 port 53 group _ctrld")
	routeIdx := strings.Index(rules, "pass out quick on ! lo0 route-to lo0 inet proto udp")
	passInIdx := strings.Index(rules, "pass in quick on lo0 reply-to lo0")

	if rdrIdx < 0 || exemptIdx < 0 || routeIdx < 0 || passInIdx < 0 {
		t.Fatalf("missing expected rules: rdr=%d exempt=%d route=%d passIn=%d", rdrIdx, exemptIdx, routeIdx, passInIdx)
	}

	if !(rdrIdx < exemptIdx && exemptIdx < routeIdx && routeIdx < passInIdx) {
		t.Errorf("incorrect rule ordering: rdr(%d) < exempt(%d) < route(%d) < passIn(%d)", rdrIdx, exemptIdx, routeIdx, passInIdx)
	}
}

// TestPFBuildAnchorRules_FallbackPort verifies that when the listener falls back
// to an alternate local port (e.g. 5354 because mDNSResponder owns *:53), the pf
// rdr rules redirect DNS to the ACTUAL bound port, not the configured default 53.
// Regression test for #551: pf redirected to a dead port after listener fallback.
func TestPFBuildAnchorRules_FallbackPort(t *testing.T) {
	// Configured/generated listener is 127.0.0.1:53, but the runtime bound port is 5354.
	p := &prog{cfg: &ctrld.Config{Listener: map[string]*ctrld.ListenerConfig{"0": {IP: "127.0.0.1", Port: 5354}}}}
	rules := p.buildPFAnchorRules(nil)

	// rdr must redirect to the actual bound port 5354.
	if !strings.Contains(rules, "rdr on lo0 inet proto udp from any to ! 127.0.0.1 port 53 -> 127.0.0.1 port 5354") {
		t.Errorf("UDP rdr must redirect to bound port 5354, got:\n%s", rules)
	}
	if !strings.Contains(rules, "rdr on lo0 inet proto tcp from any to ! 127.0.0.1 port 53 -> 127.0.0.1 port 5354") {
		t.Errorf("TCP rdr must redirect to bound port 5354, got:\n%s", rules)
	}

	// The rdr redirect target must NOT point at the dead default port 53.
	// Match the exact port at line end so "port 5354" is not a false positive.
	if strings.Contains(rules, "-> 127.0.0.1 port 53\n") {
		t.Errorf("rdr must not redirect to dead port 53 after fallback, got:\n%s", rules)
	}

	// The inbound accept rule must also target the actual bound port.
	if !strings.Contains(rules, "127.0.0.1 port 5354") {
		t.Errorf("pass in rule must reference bound port 5354, got:\n%s", rules)
	}
}

// TestPFAddressFamily tests the pfAddressFamily helper.
func TestPFAddressFamily(t *testing.T) {
	tests := []struct {
		ip   string
		want string
	}{
		{"10.0.0.1", "inet"},
		{"192.168.1.1", "inet"},
		{"127.0.0.1", "inet"},
		{"::1", "inet6"},
		{"fd00::1", "inet6"},
		{"2001:db8::1", "inet6"},
	}
	for _, tt := range tests {
		if got := pfAddressFamily(tt.ip); got != tt.want {
			t.Errorf("pfAddressFamily(%q) = %q, want %q", tt.ip, got, tt.want)
		}
	}
}

func TestIsResourceExhaustion(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		output []byte
		want   bool
	}{
		{
			name: "exec start failure",
			err:  errors.New("fork/exec /sbin/pfctl: resource temporarily unavailable"),
			want: true,
		},
		{
			name:   "fd exhaustion from stderr output",
			err:    errors.New("exit status 1"),
			output: []byte("pfctl: Pipe: Too many open files"),
			want:   true,
		},
		{
			name: "process exhaustion from wrapped restore error",
			err:  errors.New("failed to dump running filter rules: exit status 1 (output: too many processes)"),
			want: true,
		},
		{
			name:   "ordinary pf syntax failure",
			err:    errors.New("exit status 1"),
			output: []byte("pfctl: syntax error"),
			want:   false,
		},
		{
			name: "nil error and empty output",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isResourceExhaustion(tt.err, tt.output); got != tt.want {
				t.Fatalf("isResourceExhaustion() = %v, want %v", got, tt.want)
			}
		})
	}
}
