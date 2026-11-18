//go:build darwin

package cli

import (
	"strings"
	"testing"

	"github.com/Control-D-Inc/ctrld"
)

// The pf anchor that recovery writes for a Tailscale network. The VPN DNS
// interface keeps its passthrough rules and stays out of the tunnel intercept
// rules, as in the anchor before recovery. The recovery nameservers alone,
// which recovery wrote before #654, remove both.
func TestPFRecoveryAnchorKeepsVPNDNSInterface(t *testing.T) {
	p := &prog{cfg: &ctrld.Config{Listener: map[string]*ctrld.ListenerConfig{"0": {IP: "127.0.0.1", Port: 53}}}}
	recovery := []vpnDNSExemption{{Server: "100.100.100.100"}, {Server: "10.50.50.1"}}
	tunnels := []string{"utun23"}

	passthrough := "pass out quick on utun23 inet proto udp from any to ! <vpn_dns> port 53"
	intercept := "pass out quick on utun23 route-to lo0"

	merged := p.buildPFAnchorRulesForTunnels(mergeRecoveryExemptions(tailnetExemptions(), recovery), tunnels)
	if !strings.Contains(merged, passthrough) {
		t.Fatalf("recovery anchor lost the VPN DNS passthrough:\n%s", merged)
	}
	if strings.Contains(merged, intercept) {
		t.Fatalf("recovery anchor intercepts the VPN DNS interface:\n%s", merged)
	}
	if !strings.Contains(merged, "to 10.50.50.1 port 53 group "+pfGroupName) {
		t.Fatalf("recovery anchor is missing the network's nameserver:\n%s", merged)
	}

	recoveryOnly := p.buildPFAnchorRulesForTunnels(recovery, tunnels)
	if strings.Contains(recoveryOnly, passthrough) || !strings.Contains(recoveryOnly, intercept) {
		t.Fatalf("fixture no longer shows the #654 anchor shape:\n%s", recoveryOnly)
	}
}
