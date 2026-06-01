package cli

import (
	"context"
	"testing"

	"github.com/Control-D-Inc/ctrld"
)

func withVPNDNSSettlingEnabled(t *testing.T) {
	t.Helper()
	old := vpnDNSSettlingEnabled
	vpnDNSSettlingEnabled = true
	t.Cleanup(func() { vpnDNSSettlingEnabled = old })
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
	m := newVPNDNSManager(func(exemptions []vpnDNSExemption) error {
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

	m.Refresh(true)

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
