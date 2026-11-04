package cli

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func nativeTargetTestServiceOrder(name, device string) string {
	return fmt.Sprintf("An asterisk (*) denotes that a network service is disabled.\n(1) %s\n(Hardware Port: Test, Device: %s)\n", name, device)
}

// networksetup output captured on the failing USB fixture. The Dynamic Store
// name below models the name observed in ctrld's native-reader diagnostic.
const capturedUSBServiceOrder = `An asterisk (*) denotes that a network service is disabled.
(1) USB 10/100/1000 LAN
(Hardware Port: USB 10/100/1000 LAN, Device: en7)

(2) Thunderbolt Bridge
(Hardware Port: Thunderbolt Bridge, Device: bridge0)

(3) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(4) iPhone USB
(Hardware Port: iPhone USB, Device: en8)

(5) Tailscale
(Hardware Port: io.tailscale.ipn.macos, Device: )
`

func TestNativeUSBServiceName(t *testing.T) {
	global := nativeTargetTestGlobal(nativeTargetTestServiceID, "en8")
	outputs := []string{global, strings.ReplaceAll(nativeTargetTestState(), "en1", "en8"), "<dictionary> {\n  UserDefinedName : iPhone\n}", capturedUSBServiceOrder, global}
	var calls []string
	reader := nativeTargetTestReader(t, outputs, &calls)
	got, err := reader.defaultService(context.Background(), "en8")
	if err != nil || got.ID != nativeTargetTestServiceID || got.Device != "en8" || got.Name != "iPhone USB" {
		t.Fatalf("service=%+v err=%v", got, err)
	}
	dns, err := parseTargetStaticDNS("There aren't any DNS Servers set on iPhone USB.\n", got.Name)
	if err != nil || len(dns) != 0 {
		t.Fatalf("recognized USB DNS response rejected: %v %v", dns, err)
	}
}

func TestTargetNetworkServiceName(t *testing.T) {
	base := nativeTargetTestServiceOrder("iPhone USB", "en8")
	for _, tc := range []struct{ name, listing, want string }{
		{"captured USB", capturedUSBServiceOrder, "iPhone USB"},
		{"renamed", nativeTargetTestServiceOrder("Téléphone personnel", "en8"), "Téléphone personnel"},
		{"spaces preserved", nativeTargetTestServiceOrder(" iPhone USB ", "en8"), " iPhone USB "},
		{"enabled and disabled same device", base + "(*) Old USB\n(Hardware Port: Test, Device: en8)\n", ""},
		{"disabled duplicate on another device", base + "(*) iPhone USB\n(Hardware Port: Test, Device: en9)\n", ""},
		{"device boundary", nativeTargetTestServiceOrder("Other", "en80"), ""},
		{"disabled", strings.Replace(base, "(1)", "(*)", 1), ""},
		{"two enabled same device", base + "(2) Backup USB\n(Hardware Port: Test, Device: en8)\n", ""},
		{"duplicate command name", base + "(2) iPhone USB\n(Hardware Port: Test, Device: en9)\n", ""},
		{"truncated", base + "(2) Incomplete\n", ""},
		{"malformed device", strings.Replace(base, "Device: en8", "Device: en8 extra", 1), ""},
		{"unrecognized output", "Error: invalid parameter", ""},
		{"unsafe name", nativeTargetTestServiceOrder("../other", "en8"), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := targetNetworkServiceName(tc.listing, "en8")
			if tc.want == "" {
				if err == nil {
					t.Fatalf("accepted %q", got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got=%q err=%v", got, err)
			}
		})
	}
}

func TestNativeUSBServiceMappingRechecked(t *testing.T) {
	outputs := nativeTargetTestOutputs()
	var calls []string
	reader := nativeTargetTestReader(t, outputs, &calls)
	first, err := reader.defaultService(context.Background(), "en1")
	if err != nil {
		t.Fatal(err)
	}
	outputs[3] = nativeTargetTestServiceOrder("Renamed Wi-Fi", "en1")
	calls = nil
	second, err := reader.defaultService(context.Background(), "en1")
	if err != nil || first == second || second.Name != "Renamed Wi-Fi" {
		t.Fatalf("mapping change invisible: %+v %+v %v", first, second, err)
	}
}
