package cli

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
)

// dnsFixture is a loopback DNS server that records the questions it is asked,
// so a test can prove where a query actually went on the wire rather than
// inferring it from an rcode.
type dnsFixture struct {
	addr string
	mu   sync.Mutex
	qs   []string
}

func (f *dnsFixture) questions() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.qs...)
}

func startDNSFixture(t *testing.T) *dnsFixture {
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
			reply.SetRcode(msg, dns.RcodeSuccess)
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

// useOSResolverFixture points the OS-resolver boundary at a loopback server for
// the duration of the test, so "went to the OS resolver" is observable.
func useOSResolverFixture(t *testing.T, f *dnsFixture) {
	t.Helper()
	prev := osUpstreamConfig
	osUpstreamConfig = &ctrld.UpstreamConfig{
		Name:     "OS resolver",
		Type:     ctrld.ResolverTypeLegacy,
		Endpoint: f.addr,
		Timeout:  2000,
	}
	t.Cleanup(func() { osUpstreamConfig = prev })
}

func useDNSIntercept(t *testing.T) {
	t.Helper()
	prev := dnsIntercept
	dnsIntercept = true
	t.Cleanup(func() { dnsIntercept = prev })
}

func newInternalDomainsProg(t *testing.T, cfg *ctrld.Config) *prog {
	t.Helper()
	p := &prog{cfg: cfg}
	p.logger.Store(mainLog.Load())
	p.um = newUpstreamMonitor(cfg, p.logger.Load())
	p.lanLoopGuard = newLoopGuard()
	p.ptrLoopGuard = newLoopGuard()
	return p
}

// The DNS-intercept recovery bypass forwards everything to the OS/DHCP resolver
// while general DNS is broken. An Internal Domain with explicit resolvers must
// not take part: its resolvers may be perfectly healthy, and the private name
// must not reach the network's DNS.
func TestInternalDomainsExplicitResolverSurvivesRecoveryBypass(t *testing.T) {
	osFixture := startDNSFixture(t)
	internalFixture := startDNSFixture(t)
	useOSResolverFixture(t, osFixture)
	useDNSIntercept(t)

	cfg := internalDomainsTestConfig()
	applyInternalDomains(cfg, []controld.SplitDNS{
		{Domain: "corp.example", Resolvers: []string{internalFixture.addr}},
	})
	p := newInternalDomainsProg(t, cfg)
	p.recoveryBypass.Store(true)

	addr, err := net.ResolveUDPAddr("udp", "192.168.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ask := func(name string) *proxyResponse {
		t.Helper()
		ctx := context.WithValue(ctrld.LoggerCtx(context.Background(), p.logger.Load()), ctrld.ReqIdCtxKey{}, requestID())
		ufr := p.upstreamFor(ctx, "0", cfg.Listener["0"], addr, "", strings.TrimSuffix(name, "."))
		return p.proxy(ctx, &proxyRequest{msg: newDnsMsgWithHostname(name, dns.TypeA), ufr: ufr})
	}

	res := ask("host.corp.example.")
	if got := internalFixture.questions(); len(got) != 1 || got[0] != "host.corp.example." {
		t.Errorf("internal resolver questions = %v, want the query to reach it", got)
	}
	if got := osFixture.questions(); len(got) != 0 {
		t.Errorf("recovery bypass leaked an Internal Domain query to the OS resolver: %v", got)
	}
	if res == nil || res.answer == nil || res.answer.Rcode != dns.RcodeSuccess {
		t.Errorf("answer = %v, want the internal resolver's NOERROR", res)
	}

	// Control: an ordinary query still takes the bypass.
	if res := ask("www.example.net."); res == nil || res.answer == nil {
		t.Errorf("ordinary query during recovery bypass = %v", res)
	}
	if got := osFixture.questions(); len(got) != 1 || got[0] != "www.example.net." {
		t.Errorf("OS resolver questions = %v, want the ordinary query to take the bypass", got)
	}
}

// When the configured resolvers are unreachable the query must fail rather than
// reach the OS resolver, and the failure must be observable on the wire as an
// attempt against the configured address.
func TestInternalDomainsUnreachableResolverDoesNotReachOSResolver(t *testing.T) {
	osFixture := startDNSFixture(t)
	useOSResolverFixture(t, osFixture)
	useDNSIntercept(t)

	// A loopback port nothing listens on: the dial fails fast and locally.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := pc.LocalAddr().String()
	_ = pc.Close()

	cfg := internalDomainsTestConfig()
	cfg.Service.LeakOnUpstreamFailure = func(v bool) *bool { return &v }(true)
	applyInternalDomains(cfg, []controld.SplitDNS{{Domain: "corp.example", Resolvers: []string{dead}}})
	p := newInternalDomainsProg(t, cfg)

	addr, err := net.ResolveUDPAddr("udp", "192.168.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(ctrld.LoggerCtx(context.Background(), p.logger.Load()), ctrld.ReqIdCtxKey{}, requestID())
	ufr := p.upstreamFor(ctx, "0", cfg.Listener["0"], addr, "", "host.corp.example")
	res := p.proxy(ctx, &proxyRequest{msg: newDnsMsgWithHostname("host.corp.example.", dns.TypeA), ufr: ufr})

	if got := osFixture.questions(); len(got) != 0 {
		t.Errorf("unreachable internal resolver leaked to the OS resolver: %v", got)
	}
	if res == nil || res.answer == nil || res.answer.Rcode != dns.RcodeServerFailure {
		t.Errorf("answer = %v, want SERVFAIL", res)
	}
}

// The API returns Internal Domains sorted bytewise by domain, which puts a
// parent suffix ahead of its children. Generation order is routing precedence,
// so the more specific suffix has to win regardless of API order.
func TestInternalDomainsOverlappingSuffixPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries []controld.SplitDNS
		want    map[string][]string
	}{
		{
			name: "parent os, child explicit",
			entries: []controld.SplitDNS{
				{Domain: "example.com"},
				{Domain: "z.example.com", Resolvers: []string{"10.0.0.2"}},
			},
			want: map[string][]string{
				"z.example.com":         {"upstream.internal_0"},
				"host.z.example.com":    {"upstream.internal_0"},
				"a.b.z.example.com":     {"upstream.internal_0"},
				"example.com":           {},
				"other.example.com":     {},
				"notz.example.com":      {},
				"z.example.com.evil.gg": {"upstream.0"},
				"example.org":           {"upstream.0"},
			},
		},
		{
			name: "parent explicit, child os",
			entries: []controld.SplitDNS{
				{Domain: "example.com", Resolvers: []string{"10.0.0.2"}},
				{Domain: "z.example.com"},
			},
			want: map[string][]string{
				"z.example.com":      {},
				"host.z.example.com": {},
				"example.com":        {"upstream.internal_0"},
				"other.example.com":  {"upstream.internal_0"},
				"example.org":        {"upstream.0"},
			},
		},
		{
			name: "three levels, API order",
			entries: []controld.SplitDNS{
				{Domain: "example.com", Resolvers: []string{"10.0.0.1"}},
				{Domain: "y.example.com"},
				{Domain: "x.y.example.com", Resolvers: []string{"10.0.0.3"}},
			},
			want: map[string][]string{
				"host.x.y.example.com": {"upstream.internal_0"},
				"x.y.example.com":      {"upstream.internal_0"},
				"other.y.example.com":  {},
				"y.example.com":        {},
				"other.example.com":    {"upstream.internal_1"},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := internalDomainsTestConfig()
			applyInternalDomains(cfg, tc.entries)
			p := newInternalDomainsProg(t, cfg)
			addr, err := net.ResolveUDPAddr("udp", "192.168.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			for domain, want := range tc.want {
				ufr := p.upstreamFor(context.Background(), "0", cfg.Listener["0"], addr, "", domain)
				if strings.Join(ufr.upstreams, ",") != strings.Join(want, ",") {
					t.Errorf("upstreamFor(%q) = %v, want %v", domain, ufr.upstreams, want)
				}
			}
		})
	}
}

// Ordering is a generation concern; it must not make an unchanged list look
// changed at refresh time.
func TestInternalDomainsOrderingIsRefreshStable(t *testing.T) {
	apiOrder := []controld.SplitDNS{
		{Domain: "example.com"},
		{Domain: "z.example.com", Resolvers: []string{"10.0.0.2"}},
	}
	if !internalDomainsEqual(apiOrder, orderInternalDomainsBySpecificity(apiOrder)) {
		t.Error("reordering for specificity must not read as a configuration change")
	}
	first, second := internalDomainsTestConfig(), internalDomainsTestConfig()
	applyInternalDomains(first, apiOrder)
	applyInternalDomains(second, orderInternalDomainsBySpecificity(apiOrder))
	if len(first.Listener["0"].Policy.Rules) != len(second.Listener["0"].Policy.Rules) {
		t.Error("generation must not depend on the order the API returned")
	}
}

// Generated Internal Domain upstreams carry the organization's private resolver
// addresses. The production setup path must not publish them above debug.
func TestInternalDomainsSetupKeepsResolverAddressesOutOfInfoLogs(t *testing.T) {
	buf := captureInternalDomainsLogs(t)
	const secret = "10.77.88.99"
	cfg := internalDomainsTestConfig()
	applyInternalDomains(cfg, []controld.SplitDNS{
		{Domain: "corp.example", Resolvers: []string{secret}},
	})
	// Drop the Control D upstream: setupUpstream would try to bootstrap it.
	delete(cfg.Upstream, "0")

	p := newInternalDomainsProg(t, cfg)
	before := len(buf.String())
	p.setupUpstream(cfg)
	out := buf.String()[before:]

	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" || strings.Contains(line, `"level":"debug"`) {
			continue
		}
		if strings.Contains(line, secret) {
			t.Errorf("resolver address disclosed above debug level: %s", line)
		}
	}
	if !strings.Contains(out, secret) {
		t.Errorf("expected the address at debug level for diagnosis, got: %s", out)
	}
}

// A transport error names the endpoint it could not reach. For an Internal
// Domain upstream that endpoint is private, so only a classification may appear
// at error level.
func TestInternalDomainsResolverFailureLogsNoAddress(t *testing.T) {
	buf := captureInternalDomainsLogs(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := pc.LocalAddr().String()
	_ = pc.Close()

	cfg := internalDomainsTestConfig()
	cfg.Service.LeakOnUpstreamFailure = func(v bool) *bool { return &v }(false)
	applyInternalDomains(cfg, []controld.SplitDNS{{Domain: "corp.example", Resolvers: []string{dead}}})
	p := newInternalDomainsProg(t, cfg)

	addr, err := net.ResolveUDPAddr("udp", "192.168.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(ctrld.LoggerCtx(context.Background(), p.logger.Load()), ctrld.ReqIdCtxKey{}, requestID())
	ufr := p.upstreamFor(ctx, "0", cfg.Listener["0"], addr, "", "host.corp.example")
	before := len(buf.String())
	p.proxy(ctx, &proxyRequest{msg: newDnsMsgWithHostname("host.corp.example.", dns.TypeA), ufr: ufr})
	out := buf.String()[before:]

	host, _, _ := net.SplitHostPort(dead)
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" || strings.Contains(line, `"level":"debug"`) {
			continue
		}
		if strings.Contains(line, dead) || strings.Contains(line, host+":") {
			t.Errorf("resolver address disclosed above debug level: %s", line)
		}
	}
	if !strings.Contains(out, `"failure":`) {
		t.Errorf("expected a classified failure at error level, got: %s", out)
	}
	if !strings.Contains(out, dead) {
		t.Error("private resolver address must remain available at debug")
	}

	// Master's transport-level diagnostic must stay at error for ordinary
	// legacy upstreams; only generated Internal Domain queries opt into privacy.
	before = len(buf.String())
	p.queryUpstream(ctx, &proxyRequest{msg: newDnsMsgWithHostname("public.example.", dns.TypeA)},
		"upstream.0", cfg.Upstream["internal_0"])
	ordinaryError := false
	for _, line := range strings.Split(buf.String()[before:], "\n") {
		if strings.Contains(line, `"level":"error"`) && strings.Contains(line, "Legacy request failed") && strings.Contains(line, dead) {
			ordinaryError = true
		}
	}
	if !ordinaryError {
		t.Error("ordinary legacy resolver lost its error-level transport diagnostic")
	}
}

// selfUninstallEligibility runs the production setup path and reports whether
// the REFUSED-triggered deletion check stays available.
func selfUninstallEligibility(t *testing.T, p *prog, cfg *ctrld.Config) bool {
	t.Helper()
	p.setupUpstream(cfg)
	return p.canSelfUninstall.Load()
}

// Generated Internal Domain resolvers are part of the managed configuration.
// Counting them as independent upstreams made an ordinary managed install look
// custom, which silently disabled the REFUSED-triggered deletion check.
func TestInternalDomainsKeepSelfUninstallEligibility(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries []controld.SplitDNS
		extra   map[string]*ctrld.UpstreamConfig
		want    bool
	}{
		{name: "no internal domains", want: true},
		{
			name:    "os mode",
			entries: []controld.SplitDNS{{Domain: "corp.example", Mode: controld.SplitDNSModeOS}},
			want:    true,
		},
		{
			name:    "explicit mode",
			entries: []controld.SplitDNS{{Domain: "corp.example", Mode: controld.SplitDNSModeResolvers, Resolvers: []string{"10.0.0.53"}}},
			want:    true,
		},
		{
			name: "several explicit domains",
			entries: []controld.SplitDNS{
				{Domain: "corp.example", Mode: controld.SplitDNSModeResolvers, Resolvers: []string{"10.0.0.53", "10.0.0.54"}},
				{Domain: "lab.example", Mode: controld.SplitDNSModeResolvers, Resolvers: []string{"10.0.0.55"}},
			},
			want: true,
		},
		{
			// A genuinely custom multi-upstream install keeps its safeguard.
			name:  "a real second upstream",
			extra: map[string]*ctrld.UpstreamConfig{"1": {Endpoint: "https://dns.example.net/x", Type: ctrld.ResolverTypeDOH, BootstrapIP: "192.0.2.1"}},
			want:  false,
		},
		{
			// Only the shape applyInternalDomains produces is discounted, so a
			// custom config cannot buy eligibility by naming an upstream
			// "internal_0".
			name:  "an upstream merely named like a generated one",
			extra: map[string]*ctrld.UpstreamConfig{"internal_0": {Name: "mine", Endpoint: "https://dns.example.net/x", Type: ctrld.ResolverTypeDOH, BootstrapIP: "192.0.2.1"}},
			want:  false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := internalDomainsTestConfig()
			applyInternalDomains(cfg, tc.entries)
			for k, uc := range tc.extra {
				cfg.Upstream[k] = uc
			}
			p := newInternalDomainsProg(t, cfg)
			if got := selfUninstallEligibility(t, p, cfg); got != tc.want {
				t.Errorf("canSelfUninstall = %v, want %v (upstreams: %d)", got, tc.want, len(cfg.Upstream))
			}
		})
	}
}

// Eligibility is recomputed on every setup, so a reload that adds a real second
// upstream withdraws it and one that removes Internal Domains keeps it. The old
// code only ever raised the flag, which made startup and refresh disagree.
func TestSelfUninstallEligibilityRecomputedAcrossReloads(t *testing.T) {
	explicit := []controld.SplitDNS{{Domain: "corp.example", Mode: controld.SplitDNSModeResolvers, Resolvers: []string{"10.0.0.53"}}}

	cfg := internalDomainsTestConfig()
	applyInternalDomains(cfg, explicit)
	p := newInternalDomainsProg(t, cfg)
	if !selfUninstallEligibility(t, p, cfg) {
		t.Fatal("fresh start with explicit Internal Domains must stay eligible")
	}

	// Reload: Internal Domains removed. Still a plain managed install.
	removed := internalDomainsTestConfig()
	if !selfUninstallEligibility(t, p, removed) {
		t.Error("removing Internal Domains must keep eligibility")
	}

	// Reload: a genuinely custom second upstream appears.
	custom := internalDomainsTestConfig()
	custom.Upstream["1"] = &ctrld.UpstreamConfig{Endpoint: "https://dns.example.net/x", Type: ctrld.ResolverTypeDOH, BootstrapIP: "192.0.2.1"}
	if selfUninstallEligibility(t, p, custom) {
		t.Error("a real second upstream must withdraw eligibility, not stay latched on")
	}

	// Reload: back to the managed config with Internal Domains.
	again := internalDomainsTestConfig()
	applyInternalDomains(again, explicit)
	if !selfUninstallEligibility(t, p, again) {
		t.Error("eligibility must come back with the managed config")
	}
}

// The visible consequence: with explicit Internal Domains configured, a REFUSED
// answer is still counted toward the deletion check instead of being ignored.
// Counting alone performs no uninstall; that stays gated on the API confirming
// the device is gone.
func TestInternalDomainsKeepRefusedQueryCounting(t *testing.T) {
	cfg := internalDomainsTestConfig()
	applyInternalDomains(cfg, []controld.SplitDNS{
		{Domain: "corp.example", Mode: controld.SplitDNSModeResolvers, Resolvers: []string{"10.0.0.53"}},
	})
	p := newInternalDomainsProg(t, cfg)
	p.setupUpstream(cfg)

	refused := new(dns.Msg)
	refused.SetRcode(newDnsMsgWithHostname("host.corp.example.", dns.TypeA), dns.RcodeRefused)
	p.doSelfUninstall(&proxyResponse{answer: refused, refused: false})

	p.selfUninstallMu.Lock()
	count, checking := p.refusedQueryCount, p.checkingSelfUninstall
	p.selfUninstallMu.Unlock()
	if count != 1 {
		t.Errorf("refusedQueryCount = %d, want 1", count)
	}
	if checking {
		t.Error("a single REFUSED answer must not start a device-status check")
	}
}

// logLinesAboveDebug returns the log lines emitted since mark that a support
// bundle reader would see at info level or above.
func logLinesAboveDebug(buf *syncBuffer, mark int) []string {
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(buf.String()[mark:]), "\n") {
		if line == "" || strings.Contains(line, `"level":"debug"`) {
			continue
		}
		out = append(out, line)
	}
	return out
}

// deadUDPAddr returns a loopback address with nothing listening, so a dial
// fails fast and locally with connection refused.
func deadUDPAddr(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()
	return addr
}

// blackholeUDPAddr returns a loopback address that accepts packets and never
// answers, so an exchange fails with a timeout rather than a refusal.
func blackholeUDPAddr(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc.LocalAddr().String()
}

// internalDomainsProbeConfig generates an explicit Internal Domain pointing at
// addr, with a short timeout so a blackholed probe fails quickly.
func internalDomainsProbeConfig(t *testing.T, addr string) *ctrld.Config {
	t.Helper()
	cfg := internalDomainsTestConfig()
	applyInternalDomains(cfg, []controld.SplitDNS{
		{Domain: "corp.example", Mode: controld.SplitDNSModeResolvers, Resolvers: []string{addr}},
	})
	uc := cfg.Upstream["internal_0"]
	if uc == nil {
		t.Fatal("no internal upstream generated")
	}
	uc.Timeout = 300
	uc.Init(ctrld.LoggerCtx(context.Background(), mainLog.Load()))
	return cfg
}

// The loop checker runs on a one-minute ticker and probes every upstream whose
// address is local, which every generated Internal Domain resolver is. No user
// query is involved, so without the privacy treatment it publishes the
// organization's resolver addresses on its own schedule.
func TestInternalDomainsLoopCheckHidesResolverAddress(t *testing.T) {
	buf := captureInternalDomainsLogs(t)
	for _, tc := range []struct {
		name string
		addr func(*testing.T) string
	}{
		{"connection refused", deadUDPAddr},
		{"timeout", blackholeUDPAddr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := tc.addr(t)
			host, _, _ := net.SplitHostPort(addr)
			cfg := internalDomainsProbeConfig(t, addr)
			p := newInternalDomainsProg(t, cfg)
			p.loop = make(map[string]bool)
			// Only the generated upstream is local, so it is the only one probed.
			delete(cfg.Upstream, "0")

			mark := len(buf.String())
			p.checkDnsLoop()
			above := logLinesAboveDebug(buf, mark)

			for _, line := range above {
				if strings.Contains(line, addr) || strings.Contains(line, host+":") {
					t.Errorf("loop check disclosed the resolver address: %s", line)
				}
			}
			if len(above) == 0 {
				t.Error("the failure must stay visible above debug")
			}
			var classified bool
			for _, line := range above {
				if strings.Contains(line, `"failure":`) {
					classified = true
				}
			}
			if !classified {
				t.Errorf("expected a classified failure, got: %v", above)
			}
			if !strings.Contains(buf.String()[mark:], addr) {
				t.Error("the address must remain at debug level for diagnosis")
			}
		})
	}
}

// Preventing an Internal Domain query from starting recovery does not keep its
// resolver out of recovery started for another reason: buildRecoveryUpstreams
// takes every non-OS upstream.
func TestInternalDomainsRecoveryCheckHidesResolverAddress(t *testing.T) {
	buf := captureInternalDomainsLogs(t)
	for _, tc := range []struct {
		name string
		addr func(*testing.T) string
	}{
		{"connection refused", deadUDPAddr},
		{"timeout", blackholeUDPAddr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := tc.addr(t)
			host, _, _ := net.SplitHostPort(addr)
			cfg := internalDomainsProbeConfig(t, addr)
			p := newInternalDomainsProg(t, cfg)

			upstreams := p.buildRecoveryUpstreams(RecoveryReasonNetworkChange)
			uc, selected := upstreams["upstream.internal_0"]
			if !selected {
				t.Fatalf("recovery upstreams = %v, want the Internal Domain resolver included", upstreams)
			}

			mark := len(buf.String())
			if err := p.checkUpstreamOnce("upstream.internal_0", uc); err == nil {
				t.Fatal("expected the probe to fail")
			}
			above := logLinesAboveDebug(buf, mark)

			for _, line := range above {
				if strings.Contains(line, addr) || strings.Contains(line, host+":") {
					t.Errorf("recovery check disclosed the resolver address: %s", line)
				}
			}
			var classified bool
			for _, line := range above {
				if strings.Contains(line, `"failure":`) {
					classified = true
				}
			}
			if !classified {
				t.Errorf("expected a classified failure above debug, got: %v", above)
			}
			if !strings.Contains(buf.String()[mark:], addr) {
				t.Error("the address must remain at debug level for diagnosis")
			}
		})
	}
}
