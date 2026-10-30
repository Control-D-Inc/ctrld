package cli

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

// Captured on the ctrld-qa macOS 26 guest on an IPv6-only network without
// DHCPv4 or PREF64, before the CLAT started (ctrld#629).
const (
	ipv6OnlyTestGlobal6 = "<dictionary> {\n  PrimaryInterface : en1\n  PrimaryService : " + nativeTargetTestServiceID + "\n  Router : fe80::5054:ff:fe51:3\n}"
	ipv6OnlyTestNoKey   = "  No such key"
	// The same guest about 25 s after joining, once DHCPv4 gave up and macOS
	// self-assigned an IPv4 link-local address (Global/IPv4 still absent).
	ipv6OnlyTestLinkLocal4 = "<dictionary> {\n  AdditionalRoutes : <array> {\n    0 : <dictionary> {\n      DestinationAddress : 169.254.131.113\n      SubnetMask : 255.255.255.255\n    }\n  }\n  Addresses : <array> {\n    0 : 169.254.131.113\n  }\n  ConfirmedInterfaceName : en1\n  InterfaceName : en1\n  SubnetMasks : <array> {\n    0 : 255.255.0.0\n  }\n}"
)

func ipv6OnlyTestOutputs() []string {
	return []string{
		ipv6OnlyTestNoKey,   // State:/Network/Global/IPv4
		ipv6OnlyTestGlobal6, // State:/Network/Global/IPv6
		ipv6OnlyTestNoKey,   // State:/Network/Service/<id>/IPv4
		"<dictionary> {\n  UserDefinedName : Primary Wi-Fi\n}",
		nativeTargetTestServiceOrder("Primary Wi-Fi", "en1"),
		ipv6OnlyTestNoKey,   // recheck Global/IPv4
		ipv6OnlyTestGlobal6, // recheck Global/IPv6
	}
}

func ipv6OnlyTestReader(t *testing.T, outputs []string, calls *[]string, addrs ...string) nativeTargetReader {
	t.Helper()
	r := nativeTargetTestReader(t, outputs, calls)
	if len(addrs) == 0 {
		addrs = []string{"fd66:6:6:0:1876:fb78:b312:107b/64", "fe80::440:5b5a:3e67:23fe/64"}
	}
	r.interfaceAddrs = func(*net.Interface) ([]net.Addr, error) { return nativeTargetTestAddrs(addrs...), nil }
	return r
}

func TestNativeIPv6OnlyReader(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*nativeTargetReader, []string)
		addrs  []string
		want   bool
	}{
		{name: "captured IPv6-only state", want: true},
		{name: "global IPv4 present", change: func(_ *nativeTargetReader, out []string) {
			out[0] = nativeTargetTestGlobal(nativeTargetTestServiceID, "en1")
		}},
		{name: "service IPv4 present", change: func(_ *nativeTargetReader, out []string) {
			out[2] = nativeTargetTestState()
		}},
		{name: "IPv6 primary is another device", change: func(_ *nativeTargetReader, out []string) {
			out[1] = strings.Replace(ipv6OnlyTestGlobal6, "en1", "en9", 1)
		}},
		{name: "CLAT address on the interface", addrs: []string{"192.0.0.2/32", "2001:db8::1/64"}},
		{name: "routable IPv4 address on the interface", addrs: []string{"10.0.0.2/24", "2001:db8::1/64"}},
		// After DHCPv4 gives up, macOS self-assigns 169.254.x.x. That is still
		// no usable IPv4, so the evidence holds (issue #629 review).
		{name: "DHCPv4 gave up: IPv4 link-local on service and interface", want: true,
			addrs:  []string{"169.254.131.113/16", "fd66:6:6:0:1876:fb78:b312:107b/64", "fe80::440:5b5a:3e67:23fe/64"},
			change: func(_ *nativeTargetReader, out []string) { out[2] = ipv6OnlyTestLinkLocal4 }},
		{name: "link-local service state with a router", change: func(_ *nativeTargetReader, out []string) {
			out[2] = strings.Replace(ipv6OnlyTestLinkLocal4, "  InterfaceName : en1\n", "  InterfaceName : en1\n  Router : 169.254.0.1\n", 1)
		}},
		{name: "link-local service state plus a routable address", change: func(_ *nativeTargetReader, out []string) {
			out[2] = strings.Replace(ipv6OnlyTestLinkLocal4, "    0 : 169.254.131.113\n  }\n  Confirmed", "    0 : 169.254.131.113\n    1 : 10.0.0.2\n  }\n  Confirmed", 1)
		}},
		{name: "link-local service state on another device", change: func(_ *nativeTargetReader, out []string) {
			out[2] = strings.ReplaceAll(ipv6OnlyTestLinkLocal4, ": en1", ": en9")
		}},
		{name: "link-local service state with an unknown field", change: func(_ *nativeTargetReader, out []string) {
			out[2] = strings.Replace(ipv6OnlyTestLinkLocal4, "  InterfaceName : en1\n", "  InterfaceName : en1\n  Surprise : 1\n", 1)
		}},
		{name: "link-local IPv6 only", addrs: []string{"fe80::1/64"}},
		{name: "unknown store response", change: func(_ *nativeTargetReader, out []string) {
			out[0] = "scutil: permission denied"
		}},
		{name: "unknown IPv6 field", change: func(_ *nativeTargetReader, out []string) {
			out[1] = strings.Replace(ipv6OnlyTestGlobal6, "}", "  Surprise : 1\n}", 1)
		}},
		{name: "IPv4 appears before recheck", change: func(_ *nativeTargetReader, out []string) {
			out[5] = nativeTargetTestGlobal(nativeTargetTestServiceID, "en1")
		}},
		{name: "primary changes before recheck", change: func(_ *nativeTargetReader, out []string) {
			out[6] = strings.Replace(ipv6OnlyTestGlobal6, nativeTargetTestServiceID, nativeTargetOtherServiceID, 1)
		}},
		{name: "ambiguous service mapping", change: func(_ *nativeTargetReader, out []string) {
			out[4] += "(2) Secondary Wi-Fi\n(Hardware Port: Wi-Fi, Device: en1)\n"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			out := ipv6OnlyTestOutputs()
			r := ipv6OnlyTestReader(t, out, &calls, tc.addrs...)
			if tc.change != nil {
				tc.change(&r, out)
			}
			svc, err := r.ipv6OnlyService(context.Background(), "en1")
			got := err == nil && svc.ID == nativeTargetTestServiceID && svc.Name == "Primary Wi-Fi" && svc.Device == "en1"
			if got != tc.want {
				t.Fatalf("service=%+v err=%v, want admitted=%v", svc, err, tc.want)
			}
			if !tc.want && svc != (nativeTargetService{}) {
				t.Fatalf("rejected state returned a service: %+v", svc)
			}
		})
	}
}

func TestNativeIPv6OnlyReaderHonorsBudget(t *testing.T) {
	var calls []string
	r := ipv6OnlyTestReader(t, ipv6OnlyTestOutputs(), &calls)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if svc, err := r.ipv6OnlyService(ctx, "en1"); !errors.Is(err, context.Canceled) || svc != (nativeTargetService{}) || len(calls) != 0 {
		t.Fatalf("expired budget read state: svc=%+v err=%v calls=%v", svc, err, calls)
	}
}

func TestNativeStoreAbsent(t *testing.T) {
	for out, want := range map[string]bool{"  No such key\n": true, "<dictionary> {\n}": false} {
		if got, err := nativeStoreAbsent(out); err != nil || got != want {
			t.Fatalf("%q: got %v %v", out, got, err)
		}
	}
	for _, out := range []string{"", "No such key here", "error"} {
		if _, err := nativeStoreAbsent(out); err == nil {
			t.Fatalf("%q accepted as known", out)
		}
	}
}

func TestParseNativeIPv6GlobalRejectsUnsafe(t *testing.T) {
	for _, out := range []string{
		strings.Replace(ipv6OnlyTestGlobal6, "fe80::5054:ff:fe51:3", "192.168.1.1", 1),
		strings.Replace(ipv6OnlyTestGlobal6, nativeTargetTestServiceID, "not-a-uuid", 1),
		strings.Replace(ipv6OnlyTestGlobal6, "PrimaryInterface : en1", "PrimaryInterface : en1 en2", 1),
		strings.Replace(ipv6OnlyTestGlobal6, "}", "  PrimaryInterface : en1\n}", 1),
		"<dictionary> {\n  Router : fe80::1\n}",
	} {
		if _, _, err := parseNativeIPv6Global(out); err == nil {
			t.Fatalf("accepted %q", out)
		}
	}
}

func TestNativeIPv6OnlyAddresses(t *testing.T) {
	for _, tc := range []struct {
		name  string
		addrs []string
		want  bool
	}{
		{name: "global IPv6", addrs: []string{"2001:db8::1/64"}, want: true},
		{name: "ULA with link-local", addrs: []string{"fd66:6:6::10/64", "fe80::1/64"}, want: true},
		{name: "link-local only", addrs: []string{"fe80::1/64"}},
		{name: "no addresses"},
		{name: "IPv4 address beside global IPv6", addrs: []string{"2001:db8::1/64", "10.0.0.2/24"}},
		{name: "IPv4 link-local beside global IPv6", addrs: []string{"2001:db8::1/64", "169.254.131.113/16"}, want: true},
		{name: "IPv4 link-local only", addrs: []string{"169.254.131.113/16"}},
		{name: "CLAT address beside global IPv6", addrs: []string{"2001:db8::1/64", "192.0.0.2/32"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := nativeIPv6OnlyAddresses(nativeTargetTestAddrs(tc.addrs...)); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
