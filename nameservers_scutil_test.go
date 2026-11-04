package ctrld

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestScutilNameserversIPv6AndZones(t *testing.T) {
	output := []byte(`DNS configuration
resolver #1
 nameserver[0] : 192.0.2.53
 nameserver[1] : 2001:db8::53
 nameserver[2] : fe80::1%en0
 nameserver[3] : 2001:db8::53
 nameserver[4] : fe80::1%en1
 nameserver[5] : 127.0.0.1
 nameserver[6] : ::1
 nameserver[7] : fe80::2%en0
 nameserver[8] : not-an-address
 search domain[0] : internal.example
`)
	local := []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1"), netip.MustParseAddr("fe80::2%en0")}
	got, err := parseScutilNameservers(output, local)
	want := []string{"192.0.2.53", "2001:db8::53", "fe80::1%en0", "fe80::1%en1"}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("nameservers=%v err=%v", got, err)
	}
	effective := initializeOsResolver(got)
	r := newResolverWithNameserver(effective)
	if !slices.Contains(*r.lanServers.Load(), "[fe80::1%en0]:53") || !slices.Contains(*r.lanServers.Load(), "[fe80::1%en1]:53") {
		t.Fatalf("zones lost in effective resolver: %v", effective)
	}
	if !slices.Contains(*r.publicServers.Load(), "[2001:db8::53]:53") {
		t.Fatalf("global IPv6 lost: %v", effective)
	}
}

func TestScutilNameserversLocalExclusion(t *testing.T) {
	for _, tt := range []struct {
		name, local, server string
		excluded            bool
	}{
		{"unzoned link-local does not exclude scoped router", "fe80::1", "fe80::1%en0", false},
		{"loopback link-local does not exclude router", "fe80::1%lo0", "fe80::1%en0", false},
		{"other link does not exclude router", "fe80::1%en1", "fe80::1%en0", false},
		{"same link excludes local address", "fe80::1%en0", "fe80::1%en0", true},
		{"unzoned link-local matches unzoned local", "fe80::1", "fe80::1", true},
		{"scoped local does not exclude unzoned candidate", "fe80::1%en0", "fe80::1", false},
		{"global ignores zones", "2001:db8::1%en0", "2001:db8::1%en1", true},
		{"loopback ignores zones", "::1%lo0", "::1", true},
		{"IPv4 mapped local", "::ffff:192.0.2.1", "192.0.2.1", true},
		{"IPv4 mapped candidate", "192.0.2.1", "::ffff:192.0.2.1", true},
		{"IPv4 link-local mapped candidate", "169.254.1.1", "::ffff:169.254.1.1", true},
		{"other global is retained", "2001:db8::1", "2001:db8::53", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseScutilNameservers([]byte("nameserver[0] : "+tt.server+"\n"), []netip.Addr{netip.MustParseAddr(tt.local)})
			if err != nil {
				t.Fatal(err)
			}
			var want []string
			if !tt.excluded {
				want = []string{tt.server}
			}
			if !slices.Equal(got, want) {
				t.Fatalf("nameservers=%v, want %v", got, want)
			}
		})
	}
}

func TestScutilNameserversRejectsPartialScan(t *testing.T) {
	output := []byte("nameserver[0] : 192.0.2.53\n" + strings.Repeat("x", 128*1024))
	got, err := parseScutilNameservers(output, nil)
	if err == nil || got != nil {
		t.Fatalf("partial scan accepted: %v, %v", got, err)
	}
}
