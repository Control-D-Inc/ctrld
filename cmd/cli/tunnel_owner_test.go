package cli

import (
	"strings"
	"testing"
)

// Captured from "ifconfig -v utunN" on macOS. A tunnel that a network extension
// owns carries an agent line with the product name in desc.
const ifconfigWindscribeTunnel = `utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1420
	index 22
	eflags=1002080<NOAUTOIPV6LL,IPV6_ND6_ALT,TXSTART,NOACKPRI>
	options=6460<TSO4,TSO6,CHANNEL_DRV,PARTIAL_CSUM,ZEROINVERT_CSUM>
	inet 100.96.0.2 --> 100.96.0.2 netmask 0xffffffff
	nd6 options=201<PERFORMNUD,DAD>
	agent domain:NetworkExtension type:NetworkExtension flags:0xf desc:"Windscribe VPN"
	agent domain:Multipath type:Path Source flags:0x3 desc:"Multipath path manager"
	netif: 6d1e1b2a-4c55-4f0b-9f0a-1d2e3f4a5b6c
	scheduler: FQ_CODEL
	link quality: 100 (good)
`

const ifconfigTailscaleTunnel = `utun6: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1280
	index 24
	agent domain:NetworkExtension type:NetworkExtension flags:0xf desc:"Tailscale Tunnel"
	nd6 options=201<PERFORMNUD,DAD>
`

const ifconfigSystemTunnel = `utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500
	index 16
	eflags=1002080<NOAUTOIPV6LL,IPV6_ND6_ALT,TXSTART,NOACKPRI>
	inet6 fe80::e1a2:3b4c:5d6e:7f80%utun0 prefixlen 64 scopeid 0x10
	nd6 options=201<PERFORMNUD,DAD>
	scheduler: FQ_CODEL
`

func Test_parseIfconfigAgent(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{
			name:   "a VPN network extension owns the tunnel",
			output: ifconfigWindscribeTunnel,
			want:   "Windscribe VPN",
		},
		{
			name:   "a mesh client owns the tunnel",
			output: ifconfigTailscaleTunnel,
			want:   "Tailscale Tunnel",
		},
		{
			name:   "no agent line",
			output: ifconfigSystemTunnel,
		},
		{
			name:   "no output",
			output: "",
		},
		{
			name:   "an agent line without a description",
			output: "\tagent domain:Multipath type:Path Source flags:0x3\n\tagent domain:NetworkExtension type:NetworkExtension flags:0xf desc:\"Windscribe VPN\"\n",
			want:   "Windscribe VPN",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseIfconfigAgent(strings.NewReader(tc.output)); got != tc.want {
				t.Fatalf("parseIfconfigAgent() = %q, want %q", got, tc.want)
			}
		})
	}
}

// Test_parseIfconfigAgentRejectsAnOversizedLine covers a truncated read. An
// owner that the reader did not reach is not an owner that does not exist.
func Test_parseIfconfigAgentRejectsAnOversizedLine(t *testing.T) {
	output := strings.Repeat("a", 70<<10) + "\n" + ifconfigWindscribeTunnel
	if got := parseIfconfigAgent(strings.NewReader(output)); got != "" {
		t.Fatalf("tunnel owner of a truncated read = %q, want an empty owner", got)
	}
}
