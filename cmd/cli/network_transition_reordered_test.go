package cli

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/net/netmon"

	"github.com/Control-D-Inc/ctrld"
)

func TestLateSameEpochCallbacksCannotRestoreRemovedSource(t *testing.T) {
	for _, initial := range []string{"192.0.2.1", "192.0.2.10"} {
		t.Run(initial, func(t *testing.T) {
			sourceTestGlobals(t)
			dnsIntercept = false
			oldCurrent, oldRead := networkChangeCurrentStateFn, readNetworkSourceStateFn
			t.Cleanup(func() { networkChangeCurrentStateFn, readNetworkSourceStateFn = oldCurrent, oldRead })
			mon := netmon.NewStatic()
			before := sourceTestState("en0", true, "192.0.2.1/24")
			major := sourceTestState("ipsec0", true, "192.0.2.1/24")
			major.Interface["ipsec0"] = netmon.Interface{Interface: &net.Interface{Name: "ipsec0", Flags: net.FlagUp | net.FlagPointToPoint}}
			major.InterfaceIPs["ipsec0"] = []netip.Prefix{netip.MustParsePrefix("192.0.2.10/24")}
			latest := sourceTestState("ipsec0", true, "192.0.2.1/24")
			latest.Interface["ipsec0"] = major.Interface["ipsec0"]
			// netmon ignores ipsec address changes on Darwin. Its major cache
			// stays at A while B removes the source. These are OS-read seams.
			networkChangeCurrentStateFn = func(*netmon.ChangeDelta) *netmon.State { return major }
			reads := 0
			readNetworkSourceStateFn = func() (*netmon.State, error) { reads++; return latest, nil }
			ctrld.SetDefaultLocalIPv4(context.Background(), net.ParseIP(initial))
			ctrld.SetDefaultLocalIPv6(context.Background(), nil)
			p := sourceTestProg(&prog{cfg: &ctrld.Config{}})
			reconciled := 0
			networkChangeReconcileFn = func(*prog, context.Context, uint64) { reconciled++ }
			// B finishes before A's major callback even enters. A second, older
			// minor callback also arrives late in that same cache epoch.
			p.handleNetworkChange(context.Background(), &netmon.ChangeDelta{Monitor: mon, Old: major, New: latest}, false)
			olderMinor := *major
			p.handleNetworkChange(context.Background(), &netmon.ChangeDelta{Monitor: mon, Old: major, New: &olderMinor}, false)
			if len(p.networkSourceState.InterfaceIPs["ipsec0"]) != 0 {
				t.Fatal("late minor callback replaced current source validity")
			}
			p.handleNetworkChange(context.Background(), &netmon.ChangeDelta{Monitor: mon, Old: before, New: major}, true)
			want := net.IP(nil)
			if initial == "192.0.2.1" {
				want = net.ParseIP(initial)
			}
			if !ctrld.GetDefaultLocalIPv4().Equal(want) {
				t.Fatalf("late major restored an obsolete source: got %v want %v", ctrld.GetDefaultLocalIPv4(), want)
			}
			if reads != 3 || reconciled != 1 {
				t.Fatalf("fresh reads=%d reconciliation=%d", reads, reconciled)
			}
		})
	}
}

func TestMinorSourceReadFailureDoesNotSkipReconciliation(t *testing.T) {
	sourceTestGlobals(t)
	oldRead := readNetworkSourceStateFn
	t.Cleanup(func() { readNetworkSourceStateFn = oldRead })
	readNetworkSourceStateFn = func() (*netmon.State, error) { return nil, errors.New("read failed") }
	mon := netmon.NewStatic()
	old := mon.InterfaceState()
	next := *old
	networkChangeValidInterfacesFn = func(context.Context) map[string]struct{} { return map[string]struct{}{} }
	calls := 0
	networkChangeIgnoredInterceptFn = func(*prog, *netmon.ChangeDelta, time.Time) { calls++ }
	p := sourceTestProg(&prog{cfg: &ctrld.Config{}, dnsInterceptState: &interceptStateStub{}})
	p.handleNetworkChange(context.Background(), &netmon.ChangeDelta{Monitor: mon, Old: old, New: &next}, false)
	if calls != 1 || p.networkSourceState != nil || !p.networkSourceReadFailed {
		t.Fatal("source-read failure skipped reconciliation or treated unknown data as current")
	}
}

func TestReadNetworkSourceState(t *testing.T) {
	state, err := readNetworkSourceState()
	if err != nil {
		t.Fatal(err)
	}
	for name, iface := range state.Interface {
		if iface.Interface == nil || iface.Name != name {
			t.Fatal("interface snapshots share the wrong object")
		}
		for _, prefix := range state.InterfaceIPs[name] {
			if !prefix.IsValid() {
				t.Fatalf("invalid source prefix on %s", name)
			}
		}
	}
}
