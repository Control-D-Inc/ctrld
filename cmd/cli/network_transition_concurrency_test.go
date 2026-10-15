package cli

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"tailscale.com/net/netmon"

	ctrld "github.com/Control-D-Inc/ctrld"
)

func TestNetworkChangeOverlappingCallbackCannotRestoreRemovedSource(t *testing.T) {
	sourceTestGlobals(t)
	logs := captureTransitionLogs(t)
	ctrld.SetDefaultLocalIPv4(context.Background(), net.ParseIP("192.0.2.10"))
	ctrld.SetDefaultLocalIPv6(context.Background(), nil)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	networkChangeDefaultRouteIPFn = func(*prog) string {
		close(entered)
		<-release
		return "192.0.2.10"
	}
	reconciliations := 0
	networkChangeReconcileFn = func(*prog, context.Context, uint64) { reconciliations++ }
	networkChangeIgnoredInterceptFn = func(*prog, *netmon.ChangeDelta, time.Time) {}
	p := sourceTestProg(&prog{cfg: &ctrld.Config{}, dnsInterceptState: &interceptStateStub{}})
	stateA := sourceTestState("en0", true, "192.0.2.10/24")
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
		<-done
	})
	go func() {
		defer close(done)
		p.handleNetworkChange(context.Background(), &netmon.ChangeDelta{Old: sourceTestState("en0", true, "192.0.2.20/24"), New: stateA}, true)
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("first callback did not reach route discovery")
	}
	// The newer callback completes while A is paused. Its ignored/address-loss
	// path clears the source and deliberately schedules no replacement recovery.
	p.handleNetworkChange(context.Background(), &netmon.ChangeDelta{Old: stateA, New: sourceTestState("en0", true)}, true)
	close(release)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("superseded callback did not finish")
	}
	if ctrld.GetDefaultLocalIPv4() != nil {
		t.Fatal("older callback restored the removed source")
	}
	if reconciliations != 1 || !strings.Contains(logs.String(), `"outcome":"accepted"`) {
		t.Fatal("an ignored address-loss delta must preserve the accepted recovery")
	}
}

func TestNetworkChangeLateOldSnapshotIsRejected(t *testing.T) {
	sourceTestGlobals(t)
	old := networkChangeCurrentStateFn
	t.Cleanup(func() { networkChangeCurrentStateFn = old })
	latest := sourceTestState("en0", true)
	networkChangeCurrentStateFn = func(*netmon.ChangeDelta) *netmon.State { return latest }
	ctrld.SetDefaultLocalIPv4(context.Background(), nil)
	ctrld.SetDefaultLocalIPv6(context.Background(), nil)
	networkChangeReconcileFn = func(*prog, context.Context, uint64) { t.Fatal("old snapshot reconciled") }
	networkChangeIgnoredInterceptFn = func(*prog, *netmon.ChangeDelta, time.Time) { t.Fatal("old snapshot reconciled") }
	p := sourceTestProg(&prog{cfg: &ctrld.Config{}})
	p.handleNetworkChange(context.Background(), &netmon.ChangeDelta{Old: latest, New: sourceTestState("en0", true, "192.0.2.10/24")}, true)
	if p.networkTransitionGen.Load() != 0 || ctrld.GetDefaultLocalIPv4() != nil {
		t.Fatal("old snapshot became a new transition/source")
	}
}

func TestRecoveryRejectsSupersededTransition(t *testing.T) {
	p := sourceTestProg(&prog{cfg: &ctrld.Config{}})
	p.networkAcceptedGen.Store(2)
	p.handleRecoveryForTransition(RecoveryReasonNetworkChange, 1)
	if p.recoveryGen.Load() != 0 || p.recoveryRunning.Load() {
		t.Fatal("superseded transition started recovery")
	}
}
