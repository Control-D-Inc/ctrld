//go:build darwin

package cli

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

// confirmIPv6Only runs the first observation and the confirming pass one
// ipv6OnlyConfirmDelay later, as the scheduled follow-up would.
func confirmIPv6Only(h *interceptTargetHarness, p *prog) {
	p.ensureInterceptDNSTarget([]string{})
	h.now = h.now.Add(ipv6OnlyConfirmDelay)
	p.ensureInterceptDNSTarget([]string{})
}

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
			confirmIPv6Only(h, p)
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

// One IPv6-only observation is not enough: it also matches a dual-stack
// network between its router advertisement and DHCPv4 ACK. The first pass
// only starts the clock and schedules the confirming reconcile.
func TestIPv6OnlyTargetWaitsForConfirmation(t *testing.T) {
	h := newInterceptTargetHarness(t)
	h.ipv6Only = true
	h.dhcpErr = errors.New("no lease")
	p := newInterceptTargetProg()

	p.ensureInterceptDNSTarget([]string{})
	if len(h.setCalls) != 0 || !slices.Equal(h.confirms, []time.Duration{ipv6OnlyConfirmDelay}) {
		t.Fatalf("first observation: set=%v confirms=%v, want no set and one %s follow-up", h.setCalls, h.confirms, ipv6OnlyConfirmDelay)
	}
	h.now = h.now.Add(ipv6OnlyConfirmDelay - 1)
	p.ensureInterceptDNSTarget([]string{})
	if len(h.setCalls) != 0 || len(h.confirms) != 1 {
		t.Fatalf("before the delay: set=%v confirms=%v", h.setCalls, h.confirms)
	}
	h.now = h.now.Add(1)
	p.ensureInterceptDNSTarget([]string{})
	if !slices.Equal(h.dns["Wi-Fi"], []string{"127.0.0.53"}) {
		t.Fatalf("confirmed IPv6-only network not admitted: %v", h.dns["Wi-Fi"])
	}
	if p.interceptIPv6OnlySeen != (ipv6OnlyObservation{}) {
		t.Fatal("confirmation state kept after admission")
	}
}

// The scheduled follow-up itself admits the target after the delay. It runs
// as network activity, so the WaitGroup must be balanced when it returns.
func TestIPv6OnlyTargetScheduledConfirmationAdmits(t *testing.T) {
	h := newInterceptTargetHarness(t)
	h.ipv6Only = true
	h.dhcpErr = errors.New("no lease")
	p := newInterceptTargetProg()

	p.ensureInterceptDNSTarget([]string{})
	if len(h.confirmFns) != 1 || len(h.setCalls) != 0 {
		t.Fatalf("first observation: confirms=%d set=%v", len(h.confirmFns), h.setCalls)
	}
	h.now = h.now.Add(ipv6OnlyConfirmDelay)
	h.confirmFns[0]()
	if !slices.Equal(h.dns["Wi-Fi"], []string{"127.0.0.53"}) {
		t.Fatalf("scheduled confirmation did not admit: %v", h.dns["Wi-Fi"])
	}
	waitNetworkActivity(t, p)
}

// After shutdown has closed network activity, the scheduled follow-up does
// nothing and leaves the WaitGroup balanced. With intercept already torn
// down it also does nothing.
func TestIPv6OnlyTargetScheduledConfirmationSkips(t *testing.T) {
	for _, tc := range []struct {
		name string
		stop func(*prog)
	}{
		{name: "network activity closed", stop: func(p *prog) { p.closeNetMonitor() }},
		{name: "intercept stopped", stop: func(p *prog) { p.dnsInterceptState = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newInterceptTargetHarness(t)
			h.ipv6Only = true
			h.dhcpErr = errors.New("no lease")
			p := newInterceptTargetProg()

			p.ensureInterceptDNSTarget([]string{})
			calls := h.ipv6Calls
			tc.stop(p)
			h.now = h.now.Add(ipv6OnlyConfirmDelay)
			h.confirmFns[0]()
			if len(h.setCalls) != 0 || h.ipv6Calls != calls {
				t.Fatalf("follow-up reconciled after stop: set=%v evidence reads=%d->%d", h.setCalls, calls, h.ipv6Calls)
			}
			waitNetworkActivity(t, p)
		})
	}
}

// waitNetworkActivity fails if a follow-up left netMonitorWG unbalanced.
func waitNetworkActivity(t *testing.T, p *prog) {
	t.Helper()
	done := make(chan struct{})
	go func() { p.netMonitorWG.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("netMonitorWG not balanced after the follow-up")
	}
}

// Dual-stack network, DHCPv4 late: the RA arrives first, so the first pass
// sees the IPv6-only shape. The lease then arrives before the confirming
// pass, and the service is never modified.
func TestIPv6OnlyTargetDualStackDHCPv4Late(t *testing.T) {
	for _, tc := range []struct {
		name string
		late func(*interceptTargetHarness)
	}{
		{name: "lease readable", late: func(h *interceptTargetHarness) {
			h.dhcpErr, h.dhcp = nil, []string{"192.168.1.1"}
		}},
		{name: "IPv4 state published before the lease is readable", late: func(h *interceptTargetHarness) {
			h.ipv6Only = false
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newInterceptTargetHarness(t)
			h.ipv6Only = true
			h.dhcpErr = errors.New("no lease")
			h.dns["Wi-Fi"] = []string{"2001:db8::53"}
			p := newInterceptTargetProg()

			p.ensureInterceptDNSTarget([]string{})
			tc.late(h)
			h.now = h.now.Add(ipv6OnlyConfirmDelay)
			p.ensureInterceptDNSTarget([]string{})
			// Even a later return to the IPv6-only shape restarts the clock.
			h.ipv6Only, h.dhcpErr, h.dhcp = true, errors.New("no lease"), nil
			p.ensureInterceptDNSTarget([]string{})

			if len(h.setCalls) != 0 || len(h.resetCalls) != 0 || !slices.Equal(h.dns["Wi-Fi"], []string{"2001:db8::53"}) {
				t.Fatalf("dual-stack service modified: set=%v reset=%v dns=%v", h.setCalls, h.resetCalls, h.dns["Wi-Fi"])
			}
			if len(h.confirms) != 2 {
				t.Fatalf("confirmation not restarted after IPv4 appeared: %v", h.confirms)
			}
		})
	}
}

// Failing before the evidence is read (no default route mid-transition)
// learns nothing new, so it neither admits nor restarts a confirmation.
func TestIPv6OnlyTargetConfirmationSurvivesNoDecision(t *testing.T) {
	h := newInterceptTargetHarness(t)
	h.ipv6Only = true
	h.dhcpErr = errors.New("no lease")
	p := newInterceptTargetProg()

	p.ensureInterceptDNSTarget([]string{})
	route := interceptDefaultRouteInterfaceFn
	interceptDefaultRouteInterfaceFn = func() (string, error) { return "", errors.New("no default route") }
	p.ensureInterceptDNSTarget([]string{})
	interceptDefaultRouteInterfaceFn = route
	h.now = h.now.Add(ipv6OnlyConfirmDelay)
	p.ensureInterceptDNSTarget([]string{})

	if len(h.setCalls) != 1 || len(h.confirms) != 1 {
		t.Fatalf("set=%v confirms=%v, want one admission from one confirmation", h.setCalls, h.confirms)
	}
}

// A different service on the same evidence path starts a new confirmation.
func TestIPv6OnlyTargetServiceChangeRestartsConfirmation(t *testing.T) {
	h := newInterceptTargetHarness(t)
	h.ipv6Only = true
	h.dhcpErr = errors.New("no lease")
	p := newInterceptTargetProg()

	p.ensureInterceptDNSTarget([]string{})
	read := interceptNativeIPv6OnlyServiceFn
	interceptNativeIPv6OnlyServiceFn = func(ctx context.Context, device string) (nativeTargetService, error) {
		svc, err := read(ctx, device)
		svc.ID = nativeTargetOtherServiceID
		return svc, err
	}
	h.now = h.now.Add(ipv6OnlyConfirmDelay)
	p.ensureInterceptDNSTarget([]string{})
	if len(h.setCalls) != 0 || len(h.confirms) != 2 {
		t.Fatalf("service change admitted on the old clock: set=%v confirms=%v", h.setCalls, h.confirms)
	}
}

// Shutdown drops a pending confirmation and its follow-up.
func TestIPv6OnlyTargetShutdownDropsConfirmation(t *testing.T) {
	h := newInterceptTargetHarness(t)
	h.ipv6Only = true
	h.dhcpErr = errors.New("no lease")
	p := newInterceptTargetProg()

	p.ensureInterceptDNSTarget([]string{})
	p.removeInterceptDNSTarget("intercept shutdown")
	if p.interceptIPv6OnlySeen != (ipv6OnlyObservation{}) || p.interceptIPv6OnlyTimer != nil {
		t.Fatal("shutdown kept a pending IPv6-only confirmation")
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
	confirmIPv6Only(h, p)
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
		if calls == 4 {
			svc.ID = nativeTargetOtherServiceID
		}
		return svc, err
	}
	p := newInterceptTargetProg()
	confirmIPv6Only(h, p)
	if calls != 4 || len(h.setCalls) != 0 || p.interceptDNSTargetService != "" {
		t.Fatalf("changed IPv6-only tuple admitted a target: calls=%d set=%v", calls, h.setCalls)
	}
}
