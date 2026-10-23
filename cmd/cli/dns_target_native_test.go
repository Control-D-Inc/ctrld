package cli

import (
	"net"
	"strings"
	"testing"
)

func TestNativeIPv4Store(t *testing.T) {
	valid := "<dictionary> {\n  CLAT46 : TRUE\n  InterfaceName : en7\n  Router : 192.0.0.1\n  Addresses : <array> {\n    0 : 192.0.0.2\n  }\n}"
	if got, err := parseNativeIPv4Store(valid); err != nil || got["CLAT46"] != "TRUE" {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []string{"", "No such key", strings.Replace(valid, "TRUE", "1", 1), strings.Replace(valid, "InterfaceName", "DHCPPacket", 1), strings.Replace(valid, "  Router", "  CLAT46 : TRUE\n  Router", 1), valid + "\n<dictionary> {}", "<dictionary> {\nPrimaryService : bad\n}"} {
		if _, err := parseNativeIPv4Store(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestTargetStaticDNSStrict(t *testing.T) {
	for _, good := range []string{"There aren't any DNS Servers set on Wi-Fi.", "2001:db8::53\n", "1.1.1.1\n2001:db8::53"} {
		if _, err := parseTargetStaticDNS(good, "Wi-Fi"); err != nil {
			t.Fatal(err)
		}
	}
	for _, bad := range []string{"", "read failed", "There aren't any DNS Servers set on Other.", "1.1.1.1\nunexpected"} {
		if _, err := parseTargetStaticDNS(bad, "Wi-Fi"); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestNativeCLATAddresses(t *testing.T) {
	for _, tc := range []struct {
		ips  []string
		want bool
	}{
		{[]string{"192.0.0.2/32", "2001:db8::1/64"}, true},
		{[]string{"192.0.0.5/32", "2001:db8::1/64", "fe80::1/64"}, true},
		{[]string{"192.0.0.2/32", "2001:db8::1/64", "192.168.1.2/24"}, false},
		{[]string{"192.0.0.2/32", "fe80::1/64"}, false},
		{[]string{"2001:db8::1/64"}, false},
	} {
		var addrs []net.Addr
		for _, s := range tc.ips {
			ip, n, _ := net.ParseCIDR(s)
			n.IP = ip
			addrs = append(addrs, n)
		}
		if got := nativeCLATAddresses(addrs); got != tc.want {
			t.Fatalf("%v: %v", tc.ips, got)
		}
	}
}
