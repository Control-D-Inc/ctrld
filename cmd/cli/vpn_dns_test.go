package cli

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Control-D-Inc/ctrld"
)

func withVPNDNSSettlingEnabled(t *testing.T) {
	t.Helper()
	old := vpnDNSSettlingEnabled
	vpnDNSSettlingEnabled = true
	t.Cleanup(func() { vpnDNSSettlingEnabled = old })
}

func TestVPNDNSRefreshSkipsConcurrentDuplicate(t *testing.T) {
	m := newVPNDNSManager(&mainLog, nil)
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	var once sync.Once
	var calls atomic.Int32

	m.discoverVPNDNS = func(context.Context) []ctrld.VPNDNSConfig {
		calls.Add(1)
		once.Do(func() { close(started) })
		<-release
		return nil
	}

	go func() {
		defer close(done)
		m.Refresh(context.Background(), true)
	}()

	<-started
	m.Refresh(context.Background(), true)
	close(release)
	<-done

	if calls.Load() != 1 {
		t.Fatalf("expected overlapping refresh to be skipped, got %d discovery calls", calls.Load())
	}
}

func TestVPNDNSRefreshRetainsStateForOneGuardedEmptyDiscovery(t *testing.T) {
	withVPNDNSSettlingEnabled(t)
	var gotExemptions []vpnDNSExemption
	m := newVPNDNSManager(&mainLog, func(exemptions []vpnDNSExemption) error {
		gotExemptions = exemptions
		return nil
	})
	m.discoverVPNDNS = func(context.Context) []ctrld.VPNDNSConfig { return nil }
	m.configs = []ctrld.VPNDNSConfig{{
		InterfaceName: "Ethernet 6",
		Servers:       []string{"10.25.37.21", "10.25.37.22"},
	}}
	m.domainlessServers = []string{"10.25.37.21", "10.25.37.22"}

	m.Refresh(context.Background(), true)

	if got := m.DomainlessServers(); len(got) != 2 {
		t.Fatalf("expected retained domainless servers, got %v", got)
	}
	if len(gotExemptions) != 2 {
		t.Fatalf("expected retained exemptions to be re-applied, got %v", gotExemptions)
	}
	if !m.retainedAfterEmptyDiscovery {
		t.Fatal("expected empty discovery retention to be marked")
	}
}

func TestVPNDNSRefreshClearsOnSecondGuardedEmptyDiscovery(t *testing.T) {
	withVPNDNSSettlingEnabled(t)
	var gotExemptions []vpnDNSExemption
	m := newVPNDNSManager(&mainLog, func(exemptions []vpnDNSExemption) error {
		gotExemptions = exemptions
		return nil
	})
	m.discoverVPNDNS = func(context.Context) []ctrld.VPNDNSConfig { return nil }
	m.configs = []ctrld.VPNDNSConfig{{
		InterfaceName: "Ethernet 6",
		Servers:       []string{"10.25.37.21"},
	}}
	m.domainlessServers = []string{"10.25.37.21"}
	m.retainedAfterEmptyDiscovery = true

	m.Refresh(context.Background(), true)

	if got := m.DomainlessServers(); len(got) != 0 {
		t.Fatalf("expected domainless servers to be cleared on second empty discovery, got %v", got)
	}
	if len(gotExemptions) != 0 {
		t.Fatalf("expected empty exemptions after clearing stale state, got %v", gotExemptions)
	}
	if m.retainedAfterEmptyDiscovery {
		t.Fatal("expected retained empty-discovery marker to be cleared with stale state")
	}
}

func TestVPNDNSRefreshSkipsUnchangedInterceptExemptions(t *testing.T) {
	var updates [][]vpnDNSExemption
	m := newVPNDNSManager(&mainLog, func(exemptions []vpnDNSExemption) error {
		updates = append(updates, append([]vpnDNSExemption{}, exemptions...))
		return nil
	})
	m.discoverVPNDNS = func(context.Context) []ctrld.VPNDNSConfig {
		return []ctrld.VPNDNSConfig{{
			InterfaceName: "utun-test",
			Servers:       []string{"10.102.26.10"},
			Domains:       []string{"example.internal"},
		}}
	}

	m.Refresh(context.Background(), true)
	m.Refresh(context.Background(), true)

	if len(updates) != 1 {
		t.Fatalf("expected exactly one intercept exemption update for unchanged VPN DNS state, got %d", len(updates))
	}
	if len(updates[0]) != 1 || updates[0][0].Server != "10.102.26.10" || updates[0][0].Interface != "utun-test" {
		t.Fatalf("unexpected exemption update: %+v", updates[0])
	}
}

func TestVPNDNSTransportFailureSuppressesFallbackOnlyWhileRetainingState(t *testing.T) {
	withVPNDNSSettlingEnabled(t)
	m := newVPNDNSManager(&mainLog, nil)
	m.domainlessServers = []string{"10.25.37.21"}

	if m.ShouldFailClosedAfterVPNDNSTransportFailure("splunk.aws.arena.net.", []string{"10.25.37.21"}) {
		t.Fatal("did not expect transport failure to suppress OS fallback outside retained empty-discovery state")
	}

	m.retainedAfterEmptyDiscovery = true
	if !m.ShouldFailClosedAfterVPNDNSTransportFailure("splunk.aws.arena.net.", []string{"10.25.37.21"}) {
		t.Fatal("expected transport failure to suppress OS fallback while retained state is active")
	}

	m.VPNDNSReachable()
	if m.retainedAfterEmptyDiscovery {
		t.Fatal("expected reachable DNS response to clear retained empty-discovery state")
	}
}
