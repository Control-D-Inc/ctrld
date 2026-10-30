package cli

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/net/netmon"

	"github.com/Control-D-Inc/ctrld"
)

func TestNetmonMinorAndWakeSnapshotReconciliation(t *testing.T) {
	for _, timeJump := range []bool{false, true} {
		t.Run(map[bool]string{false: "minor", true: "time_jump"}[timeJump], func(t *testing.T) {
			sourceTestGlobals(t)
			mon := netmon.NewStatic()
			// NewStatic has no monitoring resources to close.
			old := mon.InterfaceState()
			next := *old
			// An identical snapshot is non-major; NewStatic has no OS monitor for IsMajorChangeFrom.
			major := false
			networkChangeValidInterfacesFn = func(context.Context) map[string]struct{} { return map[string]struct{}{} }
			calls := 0
			networkChangeIgnoredInterceptFn = func(*prog, *netmon.ChangeDelta, time.Time) { calls++ }
			p := sourceTestProg(&prog{cfg: &ctrld.Config{}, dnsInterceptState: &interceptStateStub{}})
			delta := &netmon.ChangeDelta{Monitor: mon, Old: old, New: &next, TimeJumped: timeJump}
			//lint:ignore SA1019 This fixture reproduces netmon v1.74.0's legacy wake flag.
			delta.Major = timeJump
			p.handleNetworkChange(context.Background(), delta, major)
			if calls != 1 {
				t.Fatalf("real netmon non-major delta discarded: ignored-path calls=%d transition ID=%d", calls, p.networkTransitionGen.Load())
			}
		})
	}
}

func TestIgnoredDeltaPreservesAcceptedRecovery(t *testing.T) {
	sourceTestGlobals(t)
	dnsIntercept = false
	oldRecovery := handleRecoveryForTransitionFn
	t.Cleanup(func() { handleRecoveryForTransitionFn = oldRecovery })
	calls := make(chan uint64, 2)
	handleRecoveryForTransitionFn = func(_ *prog, _ RecoveryReason, id uint64) { calls <- id }
	networkChangeReconcileFn = (*prog).reconcileNetworkChange // Real accepted-path wiring, with recovery stubbed below.
	p := sourceTestProg(&prog{cfg: &ctrld.Config{}})
	a := sourceTestState("en0", true, "192.0.2.20/24")
	p.handleNetworkChange(context.Background(), &netmon.ChangeDelta{Old: sourceTestState("en0", true, "192.0.2.10/24"), New: a}, true)
	b := sourceTestState("en0", true, "192.0.2.20/24")
	p.handleNetworkChange(context.Background(), &netmon.ChangeDelta{Old: a, New: b}, false)
	select {
	case <-calls:
	case <-time.After(1200 * time.Millisecond):
		t.Fatal("ignored delta canceled accepted recovery; no replacement was scheduled")
	}
}

func TestIgnoredDeltaPreservesValidPendingSource(t *testing.T) {
	sourceTestGlobals(t)
	dnsIntercept = false
	ctrld.SetDefaultLocalIPv4(context.Background(), nil)
	ctrld.SetDefaultLocalIPv6(context.Background(), nil)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	networkChangeDefaultRouteIPFn = func(*prog) string { close(entered); <-release; return "192.0.2.20" }
	reconciled := make(chan uint64, 2)
	networkChangeReconcileFn = func(_ *prog, _ context.Context, id uint64) { reconciled <- id }
	p := sourceTestProg(&prog{cfg: &ctrld.Config{}})
	a := sourceTestState("en0", true, "192.0.2.20/24")
	go func() {
		defer close(done)
		p.handleNetworkChange(context.Background(), &netmon.ChangeDelta{Old: sourceTestState("en0", true, "192.0.2.10/24"), New: a}, true)
	}()
	<-entered
	p.handleNetworkChange(context.Background(), &netmon.ChangeDelta{Old: a, New: sourceTestState("en0", true, "192.0.2.20/24")}, false)
	close(release)
	<-done
	if !ctrld.GetDefaultLocalIPv4().Equal(net.ParseIP("192.0.2.20")) || len(reconciled) != 1 {
		t.Fatalf("valid source discarded after ignored delta: source=%v reconciliations=%d", ctrld.GetDefaultLocalIPv4(), len(reconciled))
	}
}

func TestNewAcceptedDeltaSupersedesPendingAcceptedSource(t *testing.T) {
	sourceTestGlobals(t)
	dnsIntercept = false
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var lookups atomic.Int32
	networkChangeDefaultRouteIPFn = func(*prog) string {
		if lookups.Add(1) == 1 {
			close(entered)
			<-release
			return "192.0.2.20"
		}
		return ""
	}
	reconciled := make(chan uint64, 2)
	networkChangeReconcileFn = func(_ *prog, _ context.Context, id uint64) { reconciled <- id }
	p := sourceTestProg(&prog{cfg: &ctrld.Config{}})
	a := sourceTestState("en0", true, "192.0.2.20/24")
	go func() {
		defer close(done)
		p.handleNetworkChange(context.Background(), &netmon.ChangeDelta{Old: sourceTestState("en0", true, "192.0.2.10/24"), New: a}, true)
	}()
	<-entered
	p.handleNetworkChange(context.Background(), &netmon.ChangeDelta{Old: a, New: sourceTestState("en0", true, "192.0.2.30/24")}, true)
	close(release)
	<-done
	if !ctrld.GetDefaultLocalIPv4().Equal(net.ParseIP("192.0.2.30")) || len(reconciled) != 1 || <-reconciled != 2 {
		t.Fatal("older accepted delta replaced the newer source or recovery")
	}
}

func TestSourceCommitUsesCurrentMajorEpoch(t *testing.T) {
	mon := netmon.NewStatic()
	latest := mon.InterfaceState()
	minor := *latest
	p := sourceTestProg(&prog{networkSourceState: &minor, networkSourceEpoch: latest})
	delta := &netmon.ChangeDelta{Monitor: mon, Old: latest, New: &minor}
	if p.sourceCommitState(delta) != &minor {
		t.Fatal("discarded the observed minor update within the current epoch")
	}
	p.networkSourceEpoch = &minor
	if p.sourceCommitState(delta) != latest {
		t.Fatal("did not refresh from a newer major epoch")
	}
	if networkSnapshotCurrent(&netmon.ChangeDelta{Monitor: mon, Old: &minor, New: &minor}, false, latest) {
		t.Fatal("accepted a minor callback from an obsolete major epoch")
	}
}
