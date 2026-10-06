//go:build darwin

package cli

import (
	"context"
	"errors"
	"slices"
	"testing"
)

// Issue #629: an IPv6-only network without DHCPv4 and before macOS starts
// its CLAT has neither a lease to read nor a CLAT to prove.
func TestIPv6OnlyTargetAdmission(t *testing.T) {
	for _, tc := range []struct {
		name            string
		ipv6Only, clat  bool
		ipv6Err         error
		static, dhcp    []string
		dhcpErr         error
		want            bool
		wantIPv6Checked bool
	}{
		{name: "no IPv4 at all", ipv6Only: true, dhcpErr: errors.New("getoption: exit status 1; getpacket: exit status 1"), want: true, wantIPv6Checked: true},
		{name: "IPv6 static DNS kept for restore", ipv6Only: true, static: []string{"2001:db8::53"}, dhcpErr: errors.New("no lease"), want: true, wantIPv6Checked: true},
		{name: "unknown native state", ipv6Err: errors.New("scutil failed"), dhcpErr: errors.New("no lease"), wantIPv6Checked: true},
		{name: "IPv4 present", dhcpErr: errors.New("no lease"), wantIPv6Checked: true},
		{name: "static IPv4 wins", ipv6Only: true, static: []string{"9.9.9.9"}, dhcpErr: errors.New("no lease"), wantIPv6Checked: true},
		{name: "readable DHCP never consults IPv6-only evidence", ipv6Only: true, dhcp: []string{"192.168.1.1"}},
		{name: "CLAT evidence takes precedence", clat: true, ipv6Only: true, dhcpErr: errors.New("no lease"), want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newInterceptTargetHarness(t)
			h.ipv6Only, h.ipv6OnlyErr, h.nativeCLAT = tc.ipv6Only, tc.ipv6Err, tc.clat
			h.dns["Wi-Fi"], h.dhcp, h.dhcpErr = slices.Clone(tc.static), tc.dhcp, tc.dhcpErr
			p := newInterceptTargetProg()
			p.ensureInterceptDNSTarget([]string{})
			if got := len(h.setCalls) > 0; got != tc.want || len(h.resetCalls) != 0 {
				t.Fatalf("set=%v reset=%v, want set=%v", h.setCalls, h.resetCalls, tc.want)
			}
			if (h.ipv6Calls > 0) != tc.wantIPv6Checked {
				t.Fatalf("IPv6-only evidence consulted %d times, want consulted=%v", h.ipv6Calls, tc.wantIPv6Checked)
			}
			if tc.want && !slices.Equal(h.dns["Wi-Fi"], []string{"127.0.0.53"}) {
				t.Fatalf("target = %v, want [127.0.0.53]", h.dns["Wi-Fi"])
			}
		})
	}
}

// The admitted target is removed when the network gains IPv4, and the
// original IPv6 static DNS comes back.
func TestIPv6OnlyTargetLifecycle(t *testing.T) {
	h := newInterceptTargetHarness(t)
	h.ipv6Only = true
	h.dhcpErr = errors.New("no lease")
	h.dns["Wi-Fi"] = []string{"2001:db8::53"}
	p := newInterceptTargetProg()
	p.ensureInterceptDNSTarget([]string{})
	if p.interceptDNSTargetService != "Wi-Fi" {
		t.Fatal("no target on IPv6-only network")
	}
	// Repeated reconciliation is idempotent.
	p.ensureInterceptDNSTarget([]string{})
	if len(h.setCalls) != 1 {
		t.Fatalf("target churn: %v", h.setCalls)
	}
	// Unknown native state later never removes or rewrites ownership.
	h.ipv6Only, h.ipv6OnlyErr = false, errors.New("store unavailable")
	p.ensureInterceptDNSTarget([]string{})
	if p.interceptDNSTargetService != "Wi-Fi" || len(h.setCalls) != 1 || len(h.resetCalls) != 0 {
		t.Fatal("unknown state changed ownership")
	}
	// Back on a DHCPv4 network: the target goes, the user's IPv6 DNS returns.
	h.ipv6OnlyErr, h.dhcpErr, h.dhcp = nil, nil, []string{"192.168.1.1"}
	p.ensureInterceptDNSTarget([]string{})
	if p.interceptDNSTargetService != "" || !slices.Equal(h.dns["Wi-Fi"], []string{"2001:db8::53"}) {
		t.Fatalf("target not removed on DHCPv4 return: owner=%q dns=%v", p.interceptDNSTargetService, h.dns["Wi-Fi"])
	}
}

// The IPv6-only path rechecks with its own reader, not the CLAT reader, and a
// changed tuple during the transaction blocks the write.
func TestIPv6OnlyTargetRecheck(t *testing.T) {
	h := newInterceptTargetHarness(t)
	h.ipv6Only = true
	h.dhcpErr = errors.New("no lease")
	read := interceptNativeIPv6OnlyServiceFn
	calls := 0
	interceptNativeIPv6OnlyServiceFn = func(ctx context.Context, device string) (nativeTargetService, error) {
		calls++
		svc, err := read(ctx, device)
		if calls == 2 {
			svc.ID = nativeTargetOtherServiceID
		}
		return svc, err
	}
	p := newInterceptTargetProg()
	p.ensureInterceptDNSTarget([]string{})
	if calls != 2 || len(h.setCalls) != 0 || p.interceptDNSTargetService != "" {
		t.Fatalf("changed IPv6-only tuple admitted a target: calls=%d set=%v", calls, h.setCalls)
	}
}
