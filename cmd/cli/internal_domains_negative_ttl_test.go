package cli

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
)

// startSOANegativeFixture answers every question NXDOMAIN with the root zone's
// SOA in the authority section, TTL 3600 and MINIMUM 86400, the way a home
// router forwarding to a public resolver answers a name nobody knows.
func startSOANegativeFixture(t *testing.T) *dnsFixture {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &dnsFixture{addr: pc.LocalAddr().String()}
	started := make(chan struct{})
	server := &dns.Server{
		PacketConn:        pc,
		NotifyStartedFunc: func() { close(started) },
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, msg *dns.Msg) {
			f.mu.Lock()
			if len(msg.Question) > 0 {
				f.qs = append(f.qs, msg.Question[0].Name)
			}
			f.mu.Unlock()
			reply := new(dns.Msg)
			reply.SetRcode(msg, dns.RcodeNameError)
			soa, _ := dns.NewRR(". 3600 IN SOA a.root-servers.net. nstld.verisign-grs.com. 2026111202 1800 900 604800 86400")
			reply.Ns = append(reply.Ns, soa)
			_ = w.WriteMsg(reply)
		}),
	}
	go func() { _ = server.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("DNS fixture did not start")
	}
	t.Cleanup(func() { _ = server.Shutdown() })
	return f
}

// negativeLifetime is how long an RFC 2308 resolver caches a negative answer:
// the smaller of the SOA record's TTL and its MINIMUM field.
func negativeLifetime(t *testing.T, m *dns.Msg) uint32 {
	t.Helper()
	for _, rr := range m.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			return min(soa.Hdr.Ttl, soa.Minttl)
		}
	}
	t.Fatalf("negative answer has no SOA record: %v", m)
	return 0
}

// The organization resolver is unreachable (the VPN is off) and the network's
// DNS answers NXDOMAIN with an hour-long negative lifetime. That answer is what
// a fallback-mode Internal Domain query ends with, and the host cache keeps it
// for its negative lifetime. It must be short, or the name stays broken after
// the VPN is back.
func TestInternalDomainsFallbackNXDOMAINHasShortNegativeLifetime(t *testing.T) {
	network := startSOANegativeFixture(t)
	useOSResolverFixture(t, network)
	internal := blackholeUDPAddr(t)

	cfg := internalDomainsTestConfig()
	applyInternalDomains(cfg, []controld.SplitDNS{{Domain: "corp.example", Mode: controld.SplitDNSModeResolvers, Resolvers: []string{internal}}})
	cfg.Upstream["internal_0"].Timeout = 300
	p := newInternalDomainsProg(t, cfg)
	captureInternalDomainProbes(p)

	addr, err := net.ResolveUDPAddr("udp", "192.168.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), ctrld.ReqIdCtxKey{}, requestID())
	ufr := p.upstreamFor(ctx, "0", cfg.Listener["0"], addr, "", "host.corp.example")
	res := p.proxy(ctx, &proxyRequest{msg: newDnsMsgWithHostname("host.corp.example.", dns.TypeA), ufr: ufr})

	if res == nil || res.answer == nil || res.answer.Rcode != dns.RcodeNameError {
		t.Fatalf("answer = %v, want the network's NXDOMAIN", res)
	}
	if got := len(network.questions()); got != 1 {
		t.Fatalf("network resolver asked %d times, want the fallback once", got)
	}
	if got := negativeLifetime(t, res.answer); got > internalDomainNegativeTTL {
		t.Errorf("negative lifetime = %ds, want at most %ds so the host asks again soon", got, internalDomainNegativeTTL)
	}
}

// Only the negative answer of an Internal Domain fallback is shortened. The
// same NXDOMAIN for an ordinary name, and an Internal Domain answer from the
// organization resolver, keep the lifetimes their servers gave them.
func TestCapInternalDomainNegativeTTLLeavesOthersAlone(t *testing.T) {
	m := new(dns.Msg)
	m.SetRcode(new(dns.Msg).SetQuestion("host.corp.example.", dns.TypeA), dns.RcodeNameError)
	soa, _ := dns.NewRR(". 3600 IN SOA a.root-servers.net. nstld.verisign-grs.com. 1 1800 900 604800 2")
	m.Ns = append(m.Ns, soa)
	capInternalDomainNegativeTTL(m)
	s := m.Ns[0].(*dns.SOA)
	if s.Hdr.Ttl != internalDomainNegativeTTL || s.Minttl != 2 {
		t.Errorf("SOA ttl/minimum = %d/%d, want %d/2: only values above the cap change", s.Hdr.Ttl, s.Minttl, internalDomainNegativeTTL)
	}
	capInternalDomainNegativeTTL(nil) // must not panic
}

// The organization resolver answered: its NOERROR keeps its own TTL.
func TestInternalDomainsResolverAnswerKeepsTTL(t *testing.T) {
	useOSResolverFixture(t, startSOANegativeFixture(t))
	internal := startRcodeDNSFixture(t, dns.RcodeSuccess, false)

	cfg := internalDomainsTestConfig()
	applyInternalDomains(cfg, []controld.SplitDNS{{Domain: "corp.example", Mode: controld.SplitDNSModeResolvers, Resolvers: []string{internal.addr}}})
	p := newInternalDomainsProg(t, cfg)

	addr, err := net.ResolveUDPAddr("udp", "192.168.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), ctrld.ReqIdCtxKey{}, requestID())
	ufr := p.upstreamFor(ctx, "0", cfg.Listener["0"], addr, "", "host.corp.example")
	res := p.proxy(ctx, &proxyRequest{msg: newDnsMsgWithHostname("host.corp.example.", dns.TypeA), ufr: ufr})
	if res == nil || res.answer == nil || res.answer.Rcode != dns.RcodeSuccess || len(res.answer.Answer) != 1 {
		t.Fatalf("answer = %v, want the resolver's NOERROR", res)
	}
	if got := res.answer.Answer[0].Header().Ttl; got != 60 {
		t.Errorf("answer TTL = %d, want the resolver's 60", got)
	}
}
