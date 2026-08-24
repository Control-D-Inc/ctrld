package cli

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Control-D-Inc/ctrld"
)

func withVPNDNSSettlingEnabled(t *testing.T) {
	t.Helper()
	old := vpnDNSSettlingEnabled
	vpnDNSSettlingEnabled = true
	t.Cleanup(func() { vpnDNSSettlingEnabled = old })
}

func TestVPNDNSRefreshCoalescesConcurrentTrailingRefresh(t *testing.T) {
	m := newVPNDNSManager(nil)
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	var once sync.Once
	var calls atomic.Int32

	m.discoverVPNDNS = func(context.Context) []ctrld.VPNDNSConfig {
		call := calls.Add(1)
		once.Do(func() { close(started) })
		<-release
		if call == 2 {
			return []ctrld.VPNDNSConfig{{
				InterfaceName: "utun-latest",
				Servers:       []string{"10.0.0.2"},
				Domains:       []string{"latest.internal"},
			}}
		}
		return nil
	}

	go func() {
		defer close(done)
		m.Refresh(true)
	}()

	<-started
	m.Refresh(true)
	close(release)
	<-done

	if calls.Load() != 2 {
		t.Fatalf("expected one active and one trailing discovery call, got %d", calls.Load())
	}
	if got := m.Routes()["latest.internal"]; len(got) != 1 || got[0] != "10.0.0.2" {
		t.Fatalf("trailing refresh did not publish latest OS snapshot: %v", got)
	}
}

func TestVPNDNSRefreshRetainsStateForOneGuardedEmptyDiscovery(t *testing.T) {
	withVPNDNSSettlingEnabled(t)
	var gotExemptions []vpnDNSExemption
	m := newVPNDNSManager(func(exemptions []vpnDNSExemption) error {
		gotExemptions = exemptions
		return nil
	})
	m.discoverVPNDNS = func(context.Context) []ctrld.VPNDNSConfig { return nil }
	m.configs = []ctrld.VPNDNSConfig{{
		InterfaceName: "Ethernet 6",
		Servers:       []string{"10.25.37.21", "10.25.37.22"},
	}}
	m.domainlessServers = []string{"10.25.37.21", "10.25.37.22"}

	m.Refresh(true)

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
	updates := 0
	m := newVPNDNSManager(func(exemptions []vpnDNSExemption) error {
		updates++
		gotExemptions = exemptions
		return nil
	})
	m.discoverVPNDNS = func(context.Context) []ctrld.VPNDNSConfig { return nil }
	m.configs = []ctrld.VPNDNSConfig{{
		InterfaceName: "Ethernet 6",
		Servers:       []string{"10.25.37.21"},
	}}
	m.domainlessServers = []string{"10.25.37.21"}
	m.appliedExemptions = []vpnDNSExemption{{Server: "10.25.37.21", Interface: "Ethernet 6"}}
	m.retainedAfterEmptyDiscovery = true

	m.Refresh(true)

	if got := m.DomainlessServers(); len(got) != 0 {
		t.Fatalf("expected domainless servers to be cleared on second empty discovery, got %v", got)
	}
	if updates != 1 || len(gotExemptions) != 0 {
		t.Fatalf("expected one empty exemption update after clearing stale state, calls=%d exemptions=%v", updates, gotExemptions)
	}
	if m.retainedAfterEmptyDiscovery {
		t.Fatal("expected retained empty-discovery marker to be cleared with stale state")
	}
}

func TestVPNDNSRefreshSkipsUnchangedInterceptExemptions(t *testing.T) {
	var updates [][]vpnDNSExemption
	m := newVPNDNSManager(func(exemptions []vpnDNSExemption) error {
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

	m.Refresh(true)
	m.Refresh(true)

	if len(updates) != 1 {
		t.Fatalf("expected exactly one intercept exemption update for unchanged VPN DNS state, got %d", len(updates))
	}
	if len(updates[0]) != 1 || updates[0][0].Server != "10.102.26.10" || updates[0][0].Interface != "utun-test" {
		t.Fatalf("unexpected exemption update: %+v", updates[0])
	}
}

func TestVPNDNSRefreshRetriesFailedInterceptExemptionUpdate(t *testing.T) {
	attempts := 0
	m := newVPNDNSManager(func([]vpnDNSExemption) error {
		attempts++
		if attempts == 1 {
			return errors.New("pf update failed")
		}
		return nil
	})
	m.discoverVPNDNS = func(context.Context) []ctrld.VPNDNSConfig {
		return []ctrld.VPNDNSConfig{{
			InterfaceName: "utun-test",
			Servers:       []string{"10.102.26.10"},
			Domains:       []string{"internal.test"},
		}}
	}

	m.Refresh(true)
	if !m.interceptExemptionsPending() {
		t.Fatal("failed intercept exemption update was not retained for retry")
	}
	m.Refresh(true)
	if m.interceptExemptionsPending() {
		t.Fatal("successful intercept exemption retry did not advance applied state")
	}
	m.Refresh(true)

	if attempts != 2 {
		t.Fatalf("intercept exemption update attempts = %d, want failed attempt plus one retry", attempts)
	}
	if len(m.appliedExemptions) != 1 || m.appliedExemptions[0].Server != "10.102.26.10" {
		t.Fatalf("applied exemptions = %+v, want successful retry state", m.appliedExemptions)
	}
}

func TestVPNDNSMarkAppliedExemptionsRejectsStaleSnapshot(t *testing.T) {
	m := newVPNDNSManager(nil)
	m.configs = []ctrld.VPNDNSConfig{{InterfaceName: "utun-new", Servers: []string{"10.0.0.2"}}}

	m.markInterceptExemptionsApplied([]vpnDNSExemption{{Server: "10.0.0.1", Interface: "utun-old"}})
	if !m.interceptExemptionsPending() {
		t.Fatal("stale PF snapshot incorrectly advanced applied exemptions")
	}

	m.markInterceptExemptionsApplied([]vpnDNSExemption{{Server: "10.0.0.2", Interface: "utun-new"}})
	if m.interceptExemptionsPending() {
		t.Fatal("current PF snapshot did not advance applied exemptions")
	}
}

func TestVPNDNSTransportFailureSuppressesFallbackOnlyWhileRetainingState(t *testing.T) {
	withVPNDNSSettlingEnabled(t)
	m := newVPNDNSManager(nil)
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

func TestVPNDNSFullAndRouteOnlyDiscoveryAreSerialized(t *testing.T) {
	var updateMu sync.Mutex
	var exemptionUpdates []string
	m := newVPNDNSManager(func(exemptions []vpnDNSExemption) error {
		updateMu.Lock()
		defer updateMu.Unlock()
		if len(exemptions) == 0 {
			exemptionUpdates = append(exemptionUpdates, "")
		} else {
			exemptionUpdates = append(exemptionUpdates, exemptions[0].Server)
		}
		return nil
	})
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondStarted := make(chan struct{})
	var calls atomic.Int32

	m.discoverVPNDNS = func(context.Context) []ctrld.VPNDNSConfig {
		switch calls.Add(1) {
		case 1:
			close(firstStarted)
			<-releaseFirst
			return []ctrld.VPNDNSConfig{{
				InterfaceName: "utun-old",
				Servers:       []string{"10.0.0.1"},
				Domains:       []string{"old.internal"},
			}}
		case 2:
			close(secondStarted)
			return []ctrld.VPNDNSConfig{{
				InterfaceName: "utun-new",
				Servers:       []string{"10.0.0.2"},
				Domains:       []string{"new.internal"},
			}}
		default:
			t.Fatalf("unexpected discovery call %d", calls.Load())
			return nil
		}
	}

	routesDone := make(chan struct{})
	go func() {
		defer close(routesDone)
		m.RefreshRoutesOnly()
	}()
	<-firstStarted

	fullDone := make(chan struct{})
	go func() {
		defer close(fullDone)
		m.Refresh(false)
	}()

	select {
	case <-secondStarted:
		t.Fatal("full and route-only VPN DNS discovery overlapped")
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseFirst)

	select {
	case <-routesDone:
	case <-time.After(time.Second):
		t.Fatal("route-only refresh did not finish")
	}
	select {
	case <-fullDone:
	case <-time.After(time.Second):
		t.Fatal("full refresh did not finish")
	}

	routes := m.Routes()
	if _, ok := routes["old.internal"]; ok {
		t.Fatalf("older route-only snapshot overwrote newer full refresh: %v", routes)
	}
	if got := routes["new.internal"]; len(got) != 1 || got[0] != "10.0.0.2" {
		t.Fatalf("final VPN DNS routes = %v, want new.internal -> 10.0.0.2", routes)
	}
	updateMu.Lock()
	defer updateMu.Unlock()
	if len(exemptionUpdates) != 2 || exemptionUpdates[0] != "10.0.0.1" || exemptionUpdates[1] != "10.0.0.2" {
		t.Fatalf("serialized exemption updates = %v, want old then new", exemptionUpdates)
	}
}
