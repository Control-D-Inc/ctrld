package cli

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
)

// The field sequence behind the "NXDOMAIN right after the VPN connects"
// report. A fallback-mode Internal Domain resolver is reachable only through
// the VPN. While the VPN is off, lookups fail and the monitor marks it down.
// The VPN connects and settles. The resolver now answers, but proxy() still
// skips it as down and serves the network's NXDOMAIN, which the host caches.
//
// After the VPN settles, the first lookup must ask the configured resolver and
// get its answer, not the network's NXDOMAIN.
func TestInternalDomainsResolverDownWhileVPNOffIsAskedAfterVPNSettles(t *testing.T) {
	// The network's own DNS does not know the VPN-only name.
	network := startRcodeDNSFixture(t, dns.RcodeNameError, false)
	useOSResolverFixture(t, network)

	oldInitialize := initializeOsResolver
	t.Cleanup(func() { initializeOsResolver = oldInitialize })
	initializeOsResolver = func(bool, string) []string { return nil }

	// The organization resolver, reachable again once the VPN is up.
	internal := startRcodeDNSFixture(t, dns.RcodeSuccess, false)

	cfg := internalDomainsTestConfig()
	applyInternalDomains(cfg, []controld.SplitDNS{{Domain: "corp.example", Mode: controld.SplitDNSModeResolvers, Resolvers: []string{internal.addr}}})
	p := newInternalDomainsProg(t, cfg)
	captureInternalDomainProbes(p) // background re-checks run only if the test calls them

	const upstream = upstreamPrefix + internalDomainUpstreamPrefix + "0"
	// While the VPN was off, the resolver timed out and was marked down.
	p.um.mu.Lock()
	p.um.markDown(upstream, maxFailureRequest, "timer")
	p.um.mu.Unlock()

	// The VPN connects and pf settles.
	p.refreshDNSAfterVPNSettle("pf_stabilized")

	addr, err := net.ResolveUDPAddr("udp", "192.168.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), ctrld.ReqIdCtxKey{}, requestID())
	ufr := p.upstreamFor(ctx, "0", cfg.Listener["0"], addr, "", "host.corp.example")
	res := p.proxy(ctx, &proxyRequest{msg: newDnsMsgWithHostname("host.corp.example.", dns.TypeA), ufr: ufr})

	if res == nil || res.answer == nil {
		t.Fatalf("no answer after the VPN settled")
	}
	if res.answer.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s after the VPN settled, want the organization resolver's NOERROR (network asked %d times)",
			dns.RcodeToString[res.answer.Rcode], len(network.questions()))
	}
	if got := internal.questions(); len(got) != 1 {
		t.Errorf("organization resolver questions = %v, want the lookup", got)
	}
	if got := network.questions(); len(got) != 0 {
		t.Errorf("network resolver asked %v although the organization resolver answered", got)
	}
}

// The settle only lifts the skip. A resolver that is still unreachable after
// the VPN settles costs one timeout, gets marked down again, and the
// off-network shortcut applies to the lookups after that.
func TestInternalDomainsVPNSettleClearsOnlyFallbackModeDownMarks(t *testing.T) {
	cfg := internalDomainsTestConfig()
	applyInternalDomains(cfg, []controld.SplitDNS{
		{Domain: "a.example", Mode: controld.SplitDNSModeResolvers, Resolvers: []string{"10.0.0.53"}},
		{Domain: "b.example", Mode: controld.SplitDNSModeResolversOnly, Resolvers: []string{"10.0.0.54"}},
	})
	p := newInternalDomainsProg(t, cfg)

	oldInitialize := initializeOsResolver
	t.Cleanup(func() { initializeOsResolver = oldInitialize })
	initializeOsResolver = func(bool, string) []string { return nil }

	marks := []string{upstreamPrefix + "internal_0", upstreamPrefix + "internal_1", upstreamPrefix + "0"}
	p.um.mu.Lock()
	for _, u := range marks {
		p.um.markDown(u, maxFailureRequest, "timer")
	}
	p.um.mu.Unlock()

	p.refreshDNSAfterVPNSettle("pf_stabilized")

	if p.um.isDown(upstreamPrefix + "internal_0") {
		t.Error("fallback-mode Internal Domain resolver still down after the VPN settled")
	}
	if !p.um.isDown(upstreamPrefix + "internal_1") {
		t.Error("explicit-only Internal Domain resolver was changed; it is never skipped, so it needs no reset")
	}
	if !p.um.isDown(upstreamPrefix + "0") {
		t.Error("the Control D upstream's state was changed by a VPN settle")
	}
}
