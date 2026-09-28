package cli

import (
	"net"
	"testing"

	ctrld "github.com/Control-D-Inc/ctrld"
	"tailscale.com/net/netmon"
)

type sourceTestMonitor struct {
	callback netmon.ChangeFunc
	started  bool
}

func (*sourceTestMonitor) Close() error { return nil }

func (m *sourceTestMonitor) RegisterChangeCallback(fn netmon.ChangeFunc) func() {
	m.callback = fn
	return func() {}
}
func (*sourceTestMonitor) IsMajorChangeFrom(*netmon.State, *netmon.State) bool { return true }
func (m *sourceTestMonitor) Start()                                            { m.started = true }

func TestNetworkMonitorRegistersSourceCleanup(t *testing.T) {
	sourceTestGlobals(t)
	old := newNetworkChangeMonitorFn
	t.Cleanup(func() { newNetworkChangeMonitorFn = old })
	mon := &sourceTestMonitor{}
	newNetworkChangeMonitorFn = func(func(string, ...any)) (networkChangeMonitor, error) { return mon, nil }
	ctrld.SetDefaultLocalIPv4(net.ParseIP("192.0.2.10"))
	ctrld.SetDefaultLocalIPv6(net.ParseIP("2001:db8::10"))
	calls := 0
	networkChangeReconcileFn = func(*prog, uint64) {
		calls++
		if ctrld.GetDefaultLocalIPv4() != nil {
			t.Fatal("departed IPv4 survived to reconciliation")
		}
	}
	p := &prog{cfg: &ctrld.Config{}, dnsInterceptState: &interceptStateStub{}}
	if err := p.monitorNetworkChanges(); err != nil {
		t.Fatal(err)
	}
	if !mon.started || mon.callback == nil {
		t.Fatal("monitor did not register/start")
	}
	mon.callback(&netmon.ChangeDelta{
		Old: sourceTestState("en0", true, "192.0.2.10/24", "2001:db8::10/64"),
		New: sourceTestState("en0", true, "2001:db8::10/64"),
	})
	if calls != 1 {
		t.Fatalf("registered callback never reached source reconciliation: %d", calls)
	}
}
