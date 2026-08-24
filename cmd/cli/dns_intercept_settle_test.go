package cli

import (
	"context"
	"testing"

	"github.com/Control-D-Inc/ctrld"
)

func TestRefreshDNSAfterVPNSettleRefreshesOSResolverAndVPNRoutes(t *testing.T) {
	oldInitialize := initializeOsResolver
	defer func() { initializeOsResolver = oldInitialize }()

	var initialized []bool
	initializeOsResolver = func(force bool) []string {
		initialized = append(initialized, force)
		return []string{"10.102.26.10:53"}
	}

	var exemptionUpdates [][]vpnDNSExemption
	p := &prog{}
	p.vpnDNS = newVPNDNSManager(func(exemptions []vpnDNSExemption) error {
		exemptionUpdates = append(exemptionUpdates, append([]vpnDNSExemption{}, exemptions...))
		return nil
	})
	p.vpnDNS.discoverVPNDNS = func(context.Context) []ctrld.VPNDNSConfig {
		return []ctrld.VPNDNSConfig{{
			InterfaceName: "utun4",
			Servers:       []string{"10.102.26.10"},
			Domains:       []string{"bmwgroup.net"},
		}}
	}

	routes, domainlessServers, exemptions := p.refreshDNSAfterVPNSettle("test")

	if routes != 1 || domainlessServers != 0 || exemptions != 1 {
		t.Fatalf("expected 1 route, 0 domainless servers, 1 exemption, got routes=%d domainless=%d exemptions=%d",
			routes, domainlessServers, exemptions)
	}
	if len(initialized) != 1 || !initialized[0] {
		t.Fatalf("expected forced OS resolver refresh once, got %v", initialized)
	}
	if got := p.vpnDNS.UpstreamForDomain("jira.cc.bmwgroup.net."); len(got) != 1 || got[0] != "10.102.26.10" {
		t.Fatalf("expected refreshed VPN DNS route, got %v", got)
	}
	if len(exemptionUpdates) != 1 || len(exemptionUpdates[0]) != 1 || exemptionUpdates[0][0].Server != "10.102.26.10" {
		t.Fatalf("expected one serialized pf exemption update for the late VPN DNS server, got %+v", exemptionUpdates)
	}

	p.refreshDNSAfterVPNSettle("test-repeat")
	if len(exemptionUpdates) != 1 {
		t.Fatalf("unchanged post-settle VPN DNS state rewrote pf: %+v", exemptionUpdates)
	}
}
