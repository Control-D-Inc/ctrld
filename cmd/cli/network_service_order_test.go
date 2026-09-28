package cli

import (
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestNetworkServiceOrderEntries(t *testing.T) {
	const listing = `An asterisk (*) denotes that a network service is disabled.
(1) *Téléphone personnel
(Hardware Port: USB, Device: en8)
(*) Disabled USB
(Hardware Port: USB, Device: en8)
(2)  Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)
(3) Tunnel
(Hardware Port: VPN, Device: )
`
	want := []networkServiceEntry{
		{Name: "*Téléphone personnel", Device: "en8"},
		{Name: "Disabled USB", Device: "en8", Disabled: true},
		{Name: " Wi-Fi", Device: "en0"},
		{Name: "Tunnel"},
	}
	got, err := parseNetworkServiceOrder(strings.NewReader(listing))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("entries=%+v err=%v", got, err)
	}
}

func TestNetworkServiceOrderSelectionPolicies(t *testing.T) {
	base := nativeTargetTestServiceOrder("*iPhone USB", "en8")
	for _, tc := range []struct {
		name, listing, lookup, target string
	}{
		{"enabled asterisk name", base, "*iPhone USB", "*iPhone USB"},
		{"embedded asterisk", nativeTargetTestServiceOrder("My * USB", "en8"), "My * USB", "My * USB"},
		{"name whitespace", nativeTargetTestServiceOrder(" USB ", "en8"), " USB ", " USB "},
		{"disabled", strings.Replace(base, "(1)", "(*)", 1), "", ""},
		{"disabled neighbor", base + "(*) Ethernet\n(Hardware Port: Ethernet, Device: en9)\n", "*iPhone USB", "*iPhone USB"},
		{"enabled then disabled same device", base + "(*) Old USB\n(Hardware Port: USB, Device: en8)\n", "*iPhone USB", ""},
		{"disabled then enabled same device", strings.Replace(base, "(1)", "(*)", 1) + "(2) New USB\n(Hardware Port: USB, Device: en8)\n", "New USB", ""},
		{"two enabled same device", base + "(2) Other USB\n(Hardware Port: USB, Device: en8)\n", "*iPhone USB", ""},
		{"duplicate name on another device", base + "(2) *iPhone USB\n(Hardware Port: USB, Device: en9)\n", "*iPhone USB", ""},
		{"case-insensitive duplicate", base + "(*) *IPHONE USB\n(Hardware Port: USB, Device: en9)\n", "*iPhone USB", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			names := serviceNamesByDevice(strings.NewReader(tc.listing))
			if names["en8"] != tc.lookup {
				t.Fatalf("lookup=%v, want %q", names, tc.lookup)
			}
			if tc.name == "disabled neighbor" {
				if _, exists := names["en9"]; exists {
					t.Fatal("disabled neighbor inherited an enabled service name")
				}
			}
			got, err := targetNetworkServiceName(tc.listing, "en8")
			if got != tc.target || (err != nil) != (tc.target == "") {
				t.Fatalf("target=%q err=%v, want %q", got, err, tc.target)
			}
		})
	}
}

func TestNetworkServiceOrderRejectsIncompleteReads(t *testing.T) {
	base := nativeTargetTestServiceOrder("USB", "en8")
	for _, listing := range []string{
		"", "unexpected output", base + "(2) Incomplete\n",
		base + "(2) \n(Hardware Port: USB, Device: en9)\n",
		base + "(2) Broken\nmissing device line\n",
		base + strings.Repeat("x", maxNetworksetupLine+1),
		strings.Replace(base, "Device: en8", "Device: en8 extra", 1),
		strings.Replace(base, "(1) USB", "(0) USB", 1),
		strings.Replace(base, "(1) USB", "(1) USB\x00", 1),
	} {
		entries, err := parseNetworkServiceOrder(strings.NewReader(listing))
		if err == nil || entries != nil {
			t.Fatalf("invalid listing returned entries=%+v err=%v", entries, err)
		}
		if got := serviceNamesByDevice(strings.NewReader(listing)); got != nil {
			t.Fatalf("invalid listing returned partial names: %v", got)
		}
		if got, err := targetNetworkServiceName(listing, "en8"); err == nil || got != "" {
			t.Fatalf("invalid listing admitted target=%q err=%v", got, err)
		}
	}
	readErr := errors.New("interrupted service-order read")
	reader := func() io.Reader { return io.MultiReader(strings.NewReader(base), serviceOrderErrorReader{readErr}) }
	if entries, err := parseNetworkServiceOrder(reader()); !errors.Is(err, readErr) || entries != nil {
		t.Fatalf("partial read returned entries=%+v err=%v", entries, err)
	}
	if names := serviceNamesByDevice(reader()); names != nil {
		t.Fatalf("failed read returned partial names: %v", names)
	}
}

type serviceOrderErrorReader struct{ err error }

func (r serviceOrderErrorReader) Read([]byte) (int, error) { return 0, r.err }
