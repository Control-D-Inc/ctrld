package cli

import (
	"context"
	"errors"
	"net"
	"testing"

	"tailscale.com/net/netmon"

	"github.com/Control-D-Inc/ctrld"
)

func TestSourceReadFailureDefersAcceptedWrites(t *testing.T) {
	sourceTestGlobals(t)
	dnsIntercept = false
	oldCurrent, oldRead := networkChangeCurrentStateFn, readNetworkSourceStateFn
	t.Cleanup(func() { networkChangeCurrentStateFn, readNetworkSourceStateFn = oldCurrent, oldRead })
	major := sourceTestState("en0", true, "192.0.2.10/24")
	networkChangeCurrentStateFn = func(*netmon.ChangeDelta) *netmon.State { return major }
	readNetworkSourceStateFn = func() (*netmon.State, error) { return nil, errors.New("read failed") }
	ctrld.SetDefaultLocalIPv4(context.Background(), net.ParseIP("192.0.2.1"))
	ctrld.SetDefaultLocalIPv6(context.Background(), nil)
	p := sourceTestProg(&prog{cfg: &ctrld.Config{}, networkSourceEpoch: major})
	calls := 0
	networkChangeReconcileFn = func(*prog, context.Context, uint64) { calls++ }
	p.handleNetworkChange(context.Background(), &netmon.ChangeDelta{
		Monitor: netmon.NewStatic(),
		Old:     sourceTestState("en0", true, "192.0.2.1/24"), New: major,
	}, true)
	if calls != 1 || !ctrld.GetDefaultLocalIPv4().Equal(net.ParseIP("192.0.2.1")) {
		t.Fatal("unknown source validity changed a binding or skipped accepted recovery")
	}
}
