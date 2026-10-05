package cli

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
)

// startRcodeDNSFixture is startDNSFixture answering every question with rcode.
// A NOERROR answer carries an A record unless empty is set, which gives the
// name-exists-but-no-record-of-that-type answer.
func startRcodeDNSFixture(t *testing.T, rcode int, empty bool) *dnsFixture {
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
			reply.SetRcode(msg, rcode)
			if rcode == dns.RcodeSuccess && !empty && len(msg.Question) > 0 {
				rr, _ := dns.NewRR(msg.Question[0].Name + " 60 IN A 10.9.9.9")
				reply.Answer = append(reply.Answer, rr)
			}
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

func deadLoopbackAddr(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()
	return addr
}

// Explicit resolver with network fallback is the default explicit mode: the
// configured resolver is asked first, and a timeout, an unreachable resolver,
// SERVFAIL or NXDOMAIN hands the query to the network's resolver. A valid
// empty answer is final, and "explicit resolver only" never falls back.
func TestInternalDomainsNetworkFallback(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode string
		// internal is the configured resolver's rcode; -1 is unreachable.
		internal      int
		internalEmpty bool
		network       int
		wantNetwork   bool
		wantRcode     int
		wantAnswer    bool
	}{
		{name: "nxdomain falls back", mode: controld.SplitDNSModeResolvers, internal: dns.RcodeNameError, network: dns.RcodeSuccess, wantNetwork: true, wantRcode: dns.RcodeSuccess, wantAnswer: true},
		{name: "servfail falls back", mode: controld.SplitDNSModeResolvers, internal: dns.RcodeServerFailure, network: dns.RcodeSuccess, wantNetwork: true, wantRcode: dns.RcodeSuccess, wantAnswer: true},
		{name: "unreachable falls back", mode: controld.SplitDNSModeResolvers, internal: -1, network: dns.RcodeSuccess, wantNetwork: true, wantRcode: dns.RcodeSuccess, wantAnswer: true},
		{name: "absent mode falls back", mode: "", internal: dns.RcodeNameError, network: dns.RcodeSuccess, wantNetwork: true, wantRcode: dns.RcodeSuccess, wantAnswer: true},
		{name: "answer is final", mode: controld.SplitDNSModeResolvers, internal: dns.RcodeSuccess, network: dns.RcodeSuccess, wantRcode: dns.RcodeSuccess, wantAnswer: true},
		{name: "empty answer is final", mode: controld.SplitDNSModeResolvers, internal: dns.RcodeSuccess, internalEmpty: true, network: dns.RcodeSuccess, wantRcode: dns.RcodeSuccess},
		{name: "refused falls back", mode: controld.SplitDNSModeResolvers, internal: dns.RcodeRefused, network: dns.RcodeSuccess, wantNetwork: true, wantRcode: dns.RcodeSuccess, wantAnswer: true},
		{name: "notimp falls back", mode: controld.SplitDNSModeResolvers, internal: dns.RcodeNotImplemented, network: dns.RcodeSuccess, wantNetwork: true, wantRcode: dns.RcodeSuccess, wantAnswer: true},
		{name: "refused and network nxdomain", mode: controld.SplitDNSModeResolvers, internal: dns.RcodeRefused, network: dns.RcodeNameError, wantNetwork: true, wantRcode: dns.RcodeNameError},
		{name: "formerr is final", mode: controld.SplitDNSModeResolvers, internal: dns.RcodeFormatError, network: dns.RcodeSuccess, wantRcode: dns.RcodeFormatError},
		{name: "only mode keeps refused", mode: controld.SplitDNSModeResolversOnly, internal: dns.RcodeRefused, network: dns.RcodeSuccess, wantRcode: dns.RcodeRefused},
		{name: "unknown mode fails closed", mode: "explicit_only", internal: dns.RcodeNameError, network: dns.RcodeSuccess, wantRcode: dns.RcodeNameError},
		{name: "nobody knows the name", mode: controld.SplitDNSModeResolvers, internal: dns.RcodeNameError, network: dns.RcodeNameError, wantNetwork: true, wantRcode: dns.RcodeNameError},
		{name: "configured nxdomain beats network servfail", mode: controld.SplitDNSModeResolvers, internal: dns.RcodeNameError, network: dns.RcodeServerFailure, wantNetwork: true, wantRcode: dns.RcodeNameError},
		{name: "unreachable and network nxdomain", mode: controld.SplitDNSModeResolvers, internal: -1, network: dns.RcodeNameError, wantNetwork: true, wantRcode: dns.RcodeNameError},
		{name: "only mode keeps nxdomain", mode: controld.SplitDNSModeResolversOnly, internal: dns.RcodeNameError, network: dns.RcodeSuccess, wantRcode: dns.RcodeNameError},
		{name: "only mode keeps servfail", mode: controld.SplitDNSModeResolversOnly, internal: dns.RcodeServerFailure, network: dns.RcodeSuccess, wantRcode: dns.RcodeServerFailure},
		{name: "only mode fails when unreachable", mode: controld.SplitDNSModeResolversOnly, internal: -1, network: dns.RcodeSuccess, wantRcode: dns.RcodeServerFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			network := startRcodeDNSFixture(t, tc.network, false)
			useOSResolverFixture(t, network)

			var internal *dnsFixture
			resolver := deadLoopbackAddr(t)
			if tc.internal >= 0 {
				internal = startRcodeDNSFixture(t, tc.internal, tc.internalEmpty)
				resolver = internal.addr
			}

			cfg := internalDomainsTestConfig()
			cfg.Service.LeakOnUpstreamFailure = func(v bool) *bool { return &v }(true)
			applyInternalDomains(cfg, []controld.SplitDNS{{Domain: "corp.example", Mode: tc.mode, Resolvers: []string{resolver}}})
			p := newInternalDomainsProg(t, cfg)

			addr, err := net.ResolveUDPAddr("udp", "192.168.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.WithValue(context.Background(), ctrld.ReqIdCtxKey{}, requestID())
			ufr := p.upstreamFor(ctx, "0", cfg.Listener["0"], addr, "", "host.corp.example")
			res := p.proxy(ctx, &proxyRequest{msg: newDnsMsgWithHostname("host.corp.example.", dns.TypeA), ufr: ufr})

			if internal != nil {
				if got := internal.questions(); len(got) != 1 {
					t.Errorf("configured resolver questions = %v, want it asked first", got)
				}
			}
			if got := network.questions(); (len(got) > 0) != tc.wantNetwork {
				t.Errorf("network resolver questions = %v, want asked = %v", got, tc.wantNetwork)
			}
			if res == nil || res.answer == nil {
				t.Fatalf("no answer")
			}
			if res.answer.Rcode != tc.wantRcode {
				t.Errorf("rcode = %s, want %s", dns.RcodeToString[res.answer.Rcode], dns.RcodeToString[tc.wantRcode])
			}
			if got := len(res.answer.Answer) > 0; got != tc.wantAnswer {
				t.Errorf("answer records = %v, want records = %v", res.answer.Answer, tc.wantAnswer)
			}
		})
	}
}

// The configured resolvers are all tried, in order, before the network: an
// NXDOMAIN from the first does not skip the second.
func TestInternalDomainsNetworkFallbackTriesEveryConfiguredResolverFirst(t *testing.T) {
	network := startRcodeDNSFixture(t, dns.RcodeSuccess, false)
	useOSResolverFixture(t, network)
	first := startRcodeDNSFixture(t, dns.RcodeNameError, false)
	second := startRcodeDNSFixture(t, dns.RcodeSuccess, false)

	cfg := internalDomainsTestConfig()
	applyInternalDomains(cfg, []controld.SplitDNS{{Domain: "corp.example", Mode: controld.SplitDNSModeResolvers, Resolvers: []string{first.addr, second.addr}}})
	p := newInternalDomainsProg(t, cfg)

	addr, err := net.ResolveUDPAddr("udp", "192.168.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), ctrld.ReqIdCtxKey{}, requestID())
	ufr := p.upstreamFor(ctx, "0", cfg.Listener["0"], addr, "", "host.corp.example")
	res := p.proxy(ctx, &proxyRequest{msg: newDnsMsgWithHostname("host.corp.example.", dns.TypeA), ufr: ufr})

	if len(first.questions()) != 1 || len(second.questions()) != 1 {
		t.Errorf("configured resolvers asked %v, %v; want both once", first.questions(), second.questions())
	}
	if got := network.questions(); len(got) != 0 {
		t.Errorf("network resolver asked %v although a configured resolver answered", got)
	}
	if res == nil || res.answer == nil || res.answer.Rcode != dns.RcodeSuccess {
		t.Errorf("answer = %v, want the second resolver's NOERROR", res)
	}
}

// The fallback is no reason to log the private resolver address above debug,
// or the domain: the summary-only REPLY line carries neither.
func TestInternalDomainsNetworkFallbackLogsNoPrivateValues(t *testing.T) {
	network := startRcodeDNSFixture(t, dns.RcodeSuccess, false)
	useOSResolverFixture(t, network)
	internal := startRcodeDNSFixture(t, dns.RcodeNameError, false)

	cfg := internalDomainsTestConfig()
	applyInternalDomains(cfg, []controld.SplitDNS{{Domain: "corp.example", Resolvers: []string{internal.addr}}})
	p := newInternalDomainsProg(t, cfg)

	addr, err := net.ResolveUDPAddr("udp", "192.168.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), ctrld.ReqIdCtxKey{}, requestID())
	ufr := p.upstreamFor(ctx, "0", cfg.Listener["0"], addr, "", "host.corp.example")
	before := len(logOutput.String())
	p.proxy(ctx, &proxyRequest{msg: newDnsMsgWithHostname("host.corp.example.", dns.TypeA), ufr: ufr})
	out := logOutput.String()[before:]

	if !strings.Contains(out, "internal domain network fallback") {
		t.Fatalf("expected the fallback REPLY line, got: %s", out)
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" || strings.Contains(line, `"level":"debug"`) {
			continue
		}
		if strings.Contains(line, internal.addr) || strings.Contains(line, "corp.example") {
			t.Errorf("private value disclosed above debug level: %s", line)
		}
	}
}

// internalDomainUpstreamsProg returns a prog whose config has one legacy
// upstream per key, each carrying the given InternalDomain marker.
func internalDomainUpstreamsProg(markers map[string]string) *prog {
	cfg := &ctrld.Config{Upstream: make(map[string]*ctrld.UpstreamConfig, len(markers))}
	for key, marker := range markers {
		cfg.Upstream[key] = &ctrld.UpstreamConfig{
			Name:           internalDomainUpstreamName,
			Type:           ctrld.ResolverTypeLegacy,
			Endpoint:       "10.0.0.53:53",
			InternalDomain: marker,
		}
	}
	return &prog{cfg: cfg}
}

func TestInternalDomainFallbackUpstreams(t *testing.T) {
	p := internalDomainUpstreamsProg(map[string]string{
		"internal_0": internalDomainUpstreamFallback,
		"internal_1": internalDomainUpstreamFallback,
		"internal_2": internalDomainUpstreamOnly,
		"0":          "",
	})
	for _, tc := range []struct {
		in   []string
		want bool
	}{
		{in: nil, want: false},
		{in: []string{"upstream.internal_0", "upstream.internal_1"}, want: true},
		{in: []string{"upstream.internal_2"}, want: false},
		{in: []string{"upstream.internal_0", "upstream.internal_2"}, want: false},
		{in: []string{"upstream.internal_0", "upstream.0"}, want: false},
		{in: []string{upstreamOS}, want: false},
	} {
		if got := p.internalDomainFallbackUpstreams(tc.in); got != tc.want {
			t.Errorf("internalDomainFallbackUpstreams(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
	if !p.internalDomainExplicitUpstreams([]string{"upstream.internal_2"}) {
		t.Error("an explicit-only upstream must still count as an Internal Domain resolver")
	}
}

// Both explicit modes generate internal_<n> upstreams; the mode is carried by
// the InternalDomain marker. Switching between the modes is a routing change
// the next refresh must apply.
func TestInternalDomainsExplicitModes(t *testing.T) {
	cfg := internalDomainsTestConfig()
	summary := applyInternalDomains(cfg, []controld.SplitDNS{
		{Domain: "a.example.com", Mode: controld.SplitDNSModeResolvers, Resolvers: []string{"10.0.0.53"}},
		{Domain: "b.example.com", Mode: " Resolvers_Only ", Resolvers: []string{"10.0.0.54"}},
	})
	if summary.explicit != 2 || summary.only != 1 || summary.resolvers != 2 {
		t.Fatalf("summary = %+v", summary)
	}
	for _, tc := range []struct{ domain, target, marker string }{
		{"a.example.com", "upstream.internal_0", internalDomainUpstreamFallback},
		{"b.example.com", "upstream.internal_1", internalDomainUpstreamOnly},
	} {
		if targets, _ := ruleTargets(t, cfg, tc.domain); strings.Join(targets, ",") != tc.target {
			t.Errorf("%s targets = %v, want %s", tc.domain, targets, tc.target)
		}
		uc := cfg.Upstream[strings.TrimPrefix(tc.target, upstreamPrefix)]
		if uc == nil || uc.InternalDomain != tc.marker {
			t.Errorf("%s upstream = %+v, want marker %q", tc.domain, uc, tc.marker)
		}
	}

	fallback := []controld.SplitDNS{{Domain: "a.example.com", Mode: controld.SplitDNSModeResolvers, Resolvers: []string{"10.0.0.53"}}}
	only := []controld.SplitDNS{{Domain: "a.example.com", Mode: controld.SplitDNSModeResolversOnly, Resolvers: []string{"10.0.0.53"}}}
	legacy := []controld.SplitDNS{{Domain: "a.example.com", Resolvers: []string{"10.0.0.53"}}}
	if internalDomainsEqual(fallback, only) {
		t.Error("switching to explicit resolver only must be detected as a change")
	}
	if !internalDomainsEqual(fallback, legacy) {
		t.Error("an absent mode with resolvers is the default explicit mode")
	}
}

// An upstream a configuration defines is an ordinary upstream, whatever it is
// named and however closely it copies a generated one: a local ctrld.toml that
// names an upstream internal_<n>, gives it the legacy type and the generated
// name, must still get the OS-resolver catch-all when it fails.
func TestInternalDomainsUserDefinedLookalikeIsOrdinaryUpstream(t *testing.T) {
	osFixture := startDNSFixture(t)
	useOSResolverFixture(t, osFixture)

	cfg := internalDomainsTestConfig()
	cfg.Service.LeakOnUpstreamFailure = func(v bool) *bool { return &v }(true)
	cfg.Upstream["internal_0"] = &ctrld.UpstreamConfig{
		Name:     internalDomainUpstreamName,
		Type:     ctrld.ResolverTypeLegacy,
		Endpoint: deadLoopbackAddr(t),
		Timeout:  500,
	}
	cfg.Listener["0"].Policy.Rules = append(cfg.Listener["0"].Policy.Rules,
		ctrld.Rule{"*.corp.example": []string{"upstream.internal_0"}})
	p := newInternalDomainsProg(t, cfg)
	if p.isInternalDomainUpstream("upstream.internal_0") || isGeneratedInternalDomainUpstream(cfg.Upstream["internal_0"]) {
		t.Fatal("a user-defined upstream was recognized as a generated Internal Domain resolver")
	}

	addr, err := net.ResolveUDPAddr("udp", "192.168.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), ctrld.ReqIdCtxKey{}, requestID())
	ufr := p.upstreamFor(ctx, "0", cfg.Listener["0"], addr, "", "host.corp.example")
	res := p.proxy(ctx, &proxyRequest{msg: newDnsMsgWithHostname("host.corp.example.", dns.TypeA), ufr: ufr})

	if got := osFixture.questions(); len(got) != 1 {
		t.Errorf("OS resolver questions = %v, want the ordinary catch all", got)
	}
	if res == nil || res.answer == nil || res.answer.Rcode != dns.RcodeSuccess {
		t.Errorf("answer = %v, want the OS resolver's NOERROR", res)
	}
}

// captureInternalDomainProbes makes p's background re-checks run only when the
// test calls them, and returns the ones scheduled so far.
func captureInternalDomainProbes(p *prog) *[]func() {
	var probes []func()
	p.internalDomainProbes.start = func(run func()) { probes = append(probes, run) }
	return &probes
}

// The off-site case that fallback mode exists for: the organization resolver
// is unreachable and the network answers. Once the monitor reports the
// resolver down, a query must go to the network without waiting on the
// resolver's timeout, and a background re-check must bring it back once it
// answers again.
func TestInternalDomainsDownResolverIsSkippedAndReChecked(t *testing.T) {
	network := startRcodeDNSFixture(t, dns.RcodeSuccess, false)
	useOSResolverFixture(t, network)
	blackhole := blackholeUDPAddr(t)

	cfg := internalDomainsTestConfig()
	applyInternalDomains(cfg, []controld.SplitDNS{{Domain: "corp.example", Mode: controld.SplitDNSModeResolvers, Resolvers: []string{blackhole}}})
	p := newInternalDomainsProg(t, cfg)
	probes := captureInternalDomainProbes(p)

	addr, err := net.ResolveUDPAddr("udp", "192.168.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ask := func() (*proxyResponse, time.Duration) {
		t.Helper()
		ctx := context.WithValue(context.Background(), ctrld.ReqIdCtxKey{}, requestID())
		ufr := p.upstreamFor(ctx, "0", cfg.Listener["0"], addr, "", "host.corp.example")
		start := time.Now()
		res := p.proxy(ctx, &proxyRequest{msg: newDnsMsgWithHostname("host.corp.example.", dns.TypeA), ufr: ufr})
		return res, time.Since(start)
	}

	const upstream = upstreamPrefix + internalDomainUpstreamPrefix + "0"
	p.um.mu.Lock()
	p.um.markDown(upstream, maxFailureRequest, "immediate")
	p.um.mu.Unlock()

	for i := 0; i < 2; i++ {
		res, elapsed := ask()
		if res == nil || res.answer == nil || res.answer.Rcode != dns.RcodeSuccess {
			t.Fatalf("query %d: answer = %v, want the network's NOERROR", i+1, res)
		}
		// The blackholed resolver would cost its 2s read timeout.
		if elapsed > time.Second {
			t.Fatalf("query %d took %v: it waited on a resolver that is down", i+1, elapsed)
		}
	}
	if got := len(*probes); got != 1 {
		t.Fatalf("re-checks scheduled = %d, want one per interval", got)
	}

	// The resolver is still unreachable: the re-check leaves it down.
	(*probes)[0]()
	if !p.um.isDown(upstream) {
		t.Fatal("a failed re-check marked the resolver up")
	}

	// Back on the organization network: the next re-check, once the interval
	// has passed, finds it answering and marks it up, so queries use it again.
	internal := startRcodeDNSFixture(t, dns.RcodeSuccess, false)
	cfg.Upstream["internal_0"].Endpoint = internal.addr
	later := time.Now().Add(internalDomainProbeInterval)
	p.internalDomainProbes.now = func() time.Time { return later }
	ask()
	if got := len(*probes); got != 2 {
		t.Fatalf("re-checks scheduled = %d, want a second one after the interval", got)
	}
	(*probes)[1]()
	if p.um.isDown(upstream) {
		t.Fatal("the resolver answered the re-check but is still down")
	}
	before := len(network.questions())
	if res, _ := ask(); res == nil || res.answer == nil || res.answer.Rcode != dns.RcodeSuccess {
		t.Fatalf("answer = %v, want the resolver's NOERROR", res)
	}
	if got := internal.questions(); len(got) != 2 {
		t.Errorf("resolver questions = %v, want the re-check and the query", got)
	}
	if got := len(network.questions()); got != before {
		t.Errorf("network asked again although the resolver answered")
	}
}

// Explicit resolver only has no fallback to skip to, so a down resolver is
// still asked: skipping it would only turn its answer into a SERVFAIL.
func TestInternalDomainsOnlyModeDoesNotSkipDownResolver(t *testing.T) {
	useOSResolverFixture(t, startDNSFixture(t))
	internal := startRcodeDNSFixture(t, dns.RcodeSuccess, false)

	cfg := internalDomainsTestConfig()
	applyInternalDomains(cfg, []controld.SplitDNS{{Domain: "corp.example", Mode: controld.SplitDNSModeResolversOnly, Resolvers: []string{internal.addr}}})
	p := newInternalDomainsProg(t, cfg)
	probes := captureInternalDomainProbes(p)

	p.um.mu.Lock()
	p.um.markDown(upstreamPrefix+internalDomainUpstreamPrefix+"0", maxFailureRequest, "immediate")
	p.um.mu.Unlock()

	addr, err := net.ResolveUDPAddr("udp", "192.168.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), ctrld.ReqIdCtxKey{}, requestID())
	ufr := p.upstreamFor(ctx, "0", cfg.Listener["0"], addr, "", "host.corp.example")
	res := p.proxy(ctx, &proxyRequest{msg: newDnsMsgWithHostname("host.corp.example.", dns.TypeA), ufr: ufr})

	if got := internal.questions(); len(got) != 1 {
		t.Errorf("resolver questions = %v, want it asked although it is down", got)
	}
	if res == nil || res.answer == nil || res.answer.Rcode != dns.RcodeSuccess {
		t.Errorf("answer = %v, want the resolver's NOERROR", res)
	}
	if len(*probes) != 0 {
		t.Errorf("explicit resolver only scheduled %d re-checks", len(*probes))
	}
}

// fallbackTestQuery sends one query for host.corp.example through proxy().
func fallbackTestQuery(t *testing.T, p *prog, cfg *ctrld.Config) *proxyResponse {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "192.168.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), ctrld.ReqIdCtxKey{}, requestID())
	ufr := p.upstreamFor(ctx, "0", cfg.Listener["0"], addr, "", "host.corp.example")
	return p.proxy(ctx, &proxyRequest{msg: newDnsMsgWithHostname("host.corp.example.", dns.TypeA), ufr: ufr})
}

// The OS step of the fallback is what keeps the private name off public
// nameservers, and it does so through the context it passes. A test that
// swaps the OS resolver for a single-endpoint fixture would pass with any
// context, so this one sees the context itself and runs the step through a
// real OS resolver whose pool holds a LAN and a public nameserver.
func TestInternalDomainsNetworkFallbackOSStepIsLanOnly(t *testing.T) {
	lan := startRcodeDNSFixture(t, dns.RcodeSuccess, false)
	pool := ctrld.NewResolverWithNameserver([]string{lan.addr, "192.0.2.53:53"})
	var lanOnly []bool
	prev := internalDomainOSResolve
	internalDomainOSResolve = func(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
		isLanOnly, _ := ctx.Value(ctrld.LanOnlyQueryCtxKey{}).(bool)
		lanOnly = append(lanOnly, isLanOnly)
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		return pool.Resolve(ctx, msg)
	}
	t.Cleanup(func() { internalDomainOSResolve = prev })

	internal := startRcodeDNSFixture(t, dns.RcodeNameError, false)
	cfg := internalDomainsTestConfig()
	applyInternalDomains(cfg, []controld.SplitDNS{{Domain: "corp.example", Resolvers: []string{internal.addr}}})
	p := newInternalDomainsProg(t, cfg)

	res := fallbackTestQuery(t, p, cfg)
	if len(lanOnly) != 1 || !lanOnly[0] {
		t.Fatalf("OS step contexts LAN-only = %v, want one LAN-only query", lanOnly)
	}
	if got := lan.questions(); len(got) != 1 {
		t.Errorf("LAN nameserver questions = %v, want the fallback query", got)
	}
	if res == nil || res.answer == nil || res.answer.Rcode != dns.RcodeSuccess {
		t.Errorf("answer = %v, want the LAN nameserver's NOERROR", res)
	}
}

// useVPNFallbackFixtures routes the fallback's VPN DNS servers to fixtures:
// real VPN DNS servers are dialed on port 53.
func useVPNFallbackFixtures(t *testing.T, servers map[string]string) {
	t.Helper()
	prev := internalDomainVPNUpstream
	internalDomainVPNUpstream = func(_ *vpnDNSManager, server string) *ctrld.UpstreamConfig {
		return &ctrld.UpstreamConfig{Name: "VPN DNS", Type: ctrld.ResolverTypeLegacy, Endpoint: servers[server], Timeout: 1000}
	}
	t.Cleanup(func() { internalDomainVPNUpstream = prev })
}

// The fallback asks VPN DNS servers that match the domain, then domain-less
// ones, then the OS resolver, and stops at the first NOERROR.
func TestInternalDomainsNetworkFallbackVPNOrder(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		matched, domainless      int
		wantMatched, wantDomless int
		wantOS                   bool
	}{
		{name: "matching VPN server answers", matched: dns.RcodeSuccess, domainless: dns.RcodeSuccess, wantMatched: 1},
		{name: "then the domain-less one", matched: dns.RcodeNameError, domainless: dns.RcodeSuccess, wantMatched: 1, wantDomless: 1},
		{name: "then the OS resolver", matched: dns.RcodeNameError, domainless: dns.RcodeRefused, wantMatched: 1, wantDomless: 1, wantOS: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			useDNSIntercept(t)
			osFixture := startRcodeDNSFixture(t, dns.RcodeSuccess, false)
			useOSResolverFixture(t, osFixture)
			matched := startRcodeDNSFixture(t, tc.matched, false)
			domainless := startRcodeDNSFixture(t, tc.domainless, false)
			useVPNFallbackFixtures(t, map[string]string{"10.8.0.1": matched.addr, "10.8.0.2": domainless.addr})

			internal := startRcodeDNSFixture(t, dns.RcodeNameError, false)
			cfg := internalDomainsTestConfig()
			applyInternalDomains(cfg, []controld.SplitDNS{{Domain: "corp.example", Resolvers: []string{internal.addr}}})
			p := newInternalDomainsProg(t, cfg)
			p.vpnDNS = &vpnDNSManager{
				routes:            map[string][]string{"corp.example": {"10.8.0.1"}},
				domainlessServers: []string{"10.8.0.2"},
			}

			res := fallbackTestQuery(t, p, cfg)
			if got := len(matched.questions()); got != tc.wantMatched {
				t.Errorf("matching VPN server asked %d times, want %d", got, tc.wantMatched)
			}
			if got := len(domainless.questions()); got != tc.wantDomless {
				t.Errorf("domain-less VPN server asked %d times, want %d", got, tc.wantDomless)
			}
			if got := len(osFixture.questions()) > 0; got != tc.wantOS {
				t.Errorf("OS resolver asked = %v, want %v", got, tc.wantOS)
			}
			if res == nil || res.answer == nil || res.answer.Rcode != dns.RcodeSuccess {
				t.Errorf("answer = %v, want NOERROR", res)
			}
		})
	}
}

// While Windows is serving retained VPN DNS state, a VPN transport failure
// stops the fallback before the OS resolver, as it does for VPN split routing.
func TestInternalDomainsNetworkFallbackStopsOnRetainedVPNTransportFailure(t *testing.T) {
	useDNSIntercept(t)
	prevSettling := vpnDNSSettlingEnabled
	vpnDNSSettlingEnabled = true
	t.Cleanup(func() { vpnDNSSettlingEnabled = prevSettling })
	osFixture := startRcodeDNSFixture(t, dns.RcodeSuccess, false)
	useOSResolverFixture(t, osFixture)
	useVPNFallbackFixtures(t, map[string]string{"10.8.0.1": deadLoopbackAddr(t)})

	internal := startRcodeDNSFixture(t, dns.RcodeNameError, false)
	cfg := internalDomainsTestConfig()
	applyInternalDomains(cfg, []controld.SplitDNS{{Domain: "corp.example", Resolvers: []string{internal.addr}}})
	p := newInternalDomainsProg(t, cfg)
	p.vpnDNS = &vpnDNSManager{
		routes:                      map[string][]string{"corp.example": {"10.8.0.1"}},
		retainedAfterEmptyDiscovery: true,
	}

	res := fallbackTestQuery(t, p, cfg)
	if got := osFixture.questions(); len(got) != 0 {
		t.Errorf("OS resolver asked %v while retained VPN DNS state is active", got)
	}
	if res == nil || res.answer == nil || res.answer.Rcode != dns.RcodeNameError {
		t.Errorf("answer = %v, want the configured resolver's NXDOMAIN", res)
	}
}
