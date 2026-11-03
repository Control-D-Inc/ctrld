package cli

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"

	ctrld "github.com/Control-D-Inc/ctrld"
)

// tailnetConfig is the Tailscale split DNS that macOS publishes.
func tailnetConfig() []ctrld.VPNDNSConfig {
	return []ctrld.VPNDNSConfig{{
		InterfaceName: "utun23",
		Servers:       []string{"100.100.100.100", "fd7a:115c:a1e0::53"},
		Domains:       []string{"int.example.com"},
	}}
}

func tailnetExemptions() []vpnDNSExemption {
	return []vpnDNSExemption{
		{Server: "100.100.100.100", Interface: "utun23"},
		{Server: "fd7a:115c:a1e0::53", Interface: "utun23"},
	}
}

// exemptionWrites records each exemption set that reaches the intercept rules.
type exemptionWrites struct {
	mu   sync.Mutex
	sets [][]vpnDNSExemption
}

func (w *exemptionWrites) write(exemptions []vpnDNSExemption) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.sets = append(w.sets, append([]vpnDNSExemption(nil), exemptions...))
	return nil
}

func (w *exemptionWrites) last() []vpnDNSExemption {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.sets) == 0 {
		return nil
	}
	return w.sets[len(w.sets)-1]
}

func (w *exemptionWrites) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.sets)
}

func containsExemption(set []vpnDNSExemption, want vpnDNSExemption) bool {
	for _, ex := range set {
		if ex == want {
			return true
		}
	}
	return false
}

func TestMergeRecoveryExemptionsKeepsVPNEntries(t *testing.T) {
	recovery := []vpnDNSExemption{
		{Server: "100.100.100.100"},
		{Server: "fd7a:115c:a1e0::53"},
		{Server: "10.50.50.1"},
		{Server: "76.76.2.0"},
	}
	got := mergeRecoveryExemptions(tailnetExemptions(), recovery)
	want := append(tailnetExemptions(), vpnDNSExemption{Server: "10.50.50.1"}, vpnDNSExemption{Server: "76.76.2.0"})
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("merged exemptions = %+v, want %+v", got, want)
	}
	if got := mergeRecoveryExemptions(nil, recovery); !reflect.DeepEqual(got, recovery) {
		t.Fatalf("without VPN DNS, merged exemptions = %+v, want %+v", got, recovery)
	}
}

// The #654 sequence through the real recovery handler: a network change
// starts recovery and recovery exempts the new network's nameservers, which
// include the Tailscale resolvers. The write must keep the interface-scoped
// Tailscale exemptions. Before the fix it replaced them with interface-less
// entries, and the refresh at the end of recovery found no change in the
// discovered set, so pf kept the recovery anchor until the watchdog reload.
func TestNetworkChangeRecoveryKeepsVPNDNSExemptions(t *testing.T) {
	h := newRecoveryEventHarness(t)
	h.dhcpServers = []string{"100.100.100.100", "10.50.50.1"}

	writes := &exemptionWrites{}
	previousExempt := recoveryExemptFn
	recoveryExemptFn = func(_ *prog, exemptions []vpnDNSExemption) error { return writes.write(exemptions) }
	t.Cleanup(func() { recoveryExemptFn = previousExempt })

	m := newVPNDNSManager(writes.write)
	m.discoverVPNDNS = func(context.Context) []ctrld.VPNDNSConfig { return tailnetConfig() }
	m.discoverTailscaleRoutes = nil
	h.prog.vpnDNS = m
	m.Refresh(true)
	if got := writes.last(); writes.count() != 1 || !reflect.DeepEqual(got, tailnetExemptions()) {
		t.Fatalf("startup exemption write = %+v (writes %d)", got, writes.count())
	}

	h.prog.handleRecoveryForTransition(RecoveryReasonNetworkChange, 0)

	if writes.count() != 2 {
		t.Fatalf("exemption writes = %d, want startup and recovery", writes.count())
	}
	recoverySet := writes.last()
	for _, ex := range tailnetExemptions() {
		if !containsExemption(recoverySet, ex) {
			t.Fatalf("recovery write %+v dropped VPN DNS exemption %+v", recoverySet, ex)
		}
	}
	if !containsExemption(recoverySet, vpnDNSExemption{Server: "10.50.50.1"}) {
		t.Fatalf("recovery write %+v is missing the network's nameserver", recoverySet)
	}
	if containsExemption(recoverySet, vpnDNSExemption{Server: "100.100.100.100"}) {
		t.Fatalf("recovery write %+v repeats a VPN DNS server without its interface", recoverySet)
	}
}

func TestRecoveryExemptionsWithoutVPNDNSManager(t *testing.T) {
	writes := &exemptionWrites{}
	previousExempt := recoveryExemptFn
	recoveryExemptFn = func(_ *prog, exemptions []vpnDNSExemption) error { return writes.write(exemptions) }
	t.Cleanup(func() { recoveryExemptFn = previousExempt })

	recovery := []vpnDNSExemption{{Server: "10.50.50.1"}}
	if err := (&prog{}).exemptRecoveryNameservers(recovery); err != nil {
		t.Fatal(err)
	}
	if got := writes.last(); !reflect.DeepEqual(got, recovery) {
		t.Fatalf("write = %+v, want %+v", got, recovery)
	}

	failed := errors.New("fixture write failed")
	recoveryExemptFn = func(*prog, []vpnDNSExemption) error { return failed }
	if err := (&prog{}).exemptRecoveryNameservers(recovery); !errors.Is(err, failed) {
		t.Fatalf("error = %v, want %v", err, failed)
	}
}
