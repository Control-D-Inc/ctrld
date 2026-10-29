package cli

import (
	"reflect"
	"strings"
	"testing"

	"howett.net/plist"
)

// Real systemextensionsctl output shape (macOS 26/27), team IDs replaced.
const systemExtensionsSample = `3 extension(s)
--- com.apple.system_extension.network_extension (Go to 'System Settings > General > Login Items & Extensions > Network Extensions' to modify these system extension(s))
enabled	active	teamID	bundleID (version)	name	[state]
*	*	ABCDE12345	io.tailscale.ipn.macsys.network-extension (1.102.4/101.102.4)	Tailscale Network Extension	[activated enabled]
	*	ABCDE12346	com.example.filter.old (1.0/1)	Old Filter	[terminated waiting to uninstall on reboot]
--- com.apple.system_extension.endpoint_security (Go to 'System Settings > General > Login Items & Extensions > Endpoint Security Extensions' to modify these system extension(s))
enabled	active	teamID	bundleID (version)	name	[state]
*	*	ABCDE12347	com.jamf.protect.security-extension (5.0/5)	Jamf Protect	[activated enabled]
`

func TestParseSystemExtensions(t *testing.T) {
	all, network := parseSystemExtensions(systemExtensionsSample)
	wantAll := []string{"endpoint_security:com.jamf.protect.security-extension", "network:io.tailscale.ipn.macsys.network-extension"}
	if !reflect.DeepEqual(all, wantAll) {
		t.Errorf("all = %v, want %v", all, wantAll)
	}
	if !reflect.DeepEqual(network, []string{"io.tailscale.ipn.macsys.network-extension"}) {
		t.Errorf("network = %v", network)
	}
}

func TestParseNCListKeepsNoServiceName(t *testing.T) {
	out := `Available network connection services in the current set (*=enabled):
* (Connected)      2AA54A8D-6EC5-462A-BC64-FFB86753E398 VPN (io.tailscale.ipn.macsys) "Acme Corp VPN"                      [VPN:io.tailscale.ipn.macsys]
  (Disconnected)   11111111-2222-3333-4444-555555555555 IPSec              "Office"                             [IPSec]
`
	got := parseNCList(out)
	want := []string{"IPSec:builtin:disconnected", "VPN:io.tailscale.ipn.macsys:connected"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for _, s := range got {
		if strings.Contains(s, "Acme") || strings.Contains(s, "Office") {
			t.Errorf("service name leaked: %s", s)
		}
	}
}

// buildNEArchive makes a keyed archive with the structure of
// com.apple.networkextension.plist: configurations whose payloads are
// referenced by UID, as on a live host.
func buildNEArchive(t *testing.T) []byte {
	t.Helper()
	objects := []any{
		"$null",
		// 1: an app-bundled DNS proxy pushed by MDM, enabled
		map[string]any{"Identifier": plist.UID(2), "Application": plist.UID(3), "Name": plist.UID(4), "DNSProxy": plist.UID(5)},
		map[string]any{"NS.uuidbytes": []byte{1}},
		"com.example.agent",
		"Example Corp Secure DNS",
		map[string]any{"Enabled": true, "Protocol": plist.UID(6)},
		map[string]any{"ProviderBundleIdentifier": plist.UID(7)},
		"com.example.agent.dnsproxy",
		// 8: Apple's firewall content filter, disabled
		map[string]any{"Identifier": plist.UID(2), "Application": plist.UID(9), "ContentFilter": plist.UID(10), "VPN": plist.UID(0)},
		"com.apple.ALF.ApplicationFirewall",
		map[string]any{"Enabled": false, "Provider": plist.UID(11)},
		map[string]any{"DataProviderBundleIdentifier": plist.UID(12)},
		"com.apple.ALF.filter",
	}
	data, err := plist.Marshal(map[string]any{"$archiver": "NSKeyedArchiver", "$objects": objects, "$top": map[string]any{}}, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseNEConfigurations(t *testing.T) {
	got, code := parseNEConfigurations(buildNEArchive(t))
	if code != "ok" {
		t.Fatalf("code = %s", code)
	}
	want := []string{
		"content_filter:com.apple.ALF.ApplicationFirewall:com.apple.ALF.filter:disabled",
		"dns_proxy:com.example.agent:com.example.agent.dnsproxy:enabled",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for _, s := range got {
		if strings.Contains(s, "Example Corp") {
			t.Errorf("configuration name leaked: %s", s)
		}
	}
	if _, code := parseNEConfigurations([]byte("not a plist")); code != "parse_failed" {
		t.Errorf("garbage code = %s", code)
	}
}

func TestParseThirdPartyKexts(t *testing.T) {
	out := `No variant specified, falling back to release
    3  198 0                  0          0          com.apple.kpi.bsd (27.0.0) 77F5F1F1-C717-3A42-A5FA-487ACF280495 <>
  201    0 0xffffff7f8 0x5000     0x5000     com.example.netfilter (2.1) 11111111-2222-3333-4444-555555555555 <8 6 5 3>
`
	if got := parseThirdPartyKexts(out); !reflect.DeepEqual(got, []string{"com.example.netfilter"}) {
		t.Fatalf("got %v", got)
	}
}

func TestParsePFAnchors(t *testing.T) {
	out := "  com.apple\n  com.controld.ctrld\n  com.example.firewall\n  com.example.firewall/dns\n"
	got := parsePFAnchors(out, "com.controld.ctrld")
	want := []string{"com.apple", "com.example.firewall", "com.example.firewall/dns"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
