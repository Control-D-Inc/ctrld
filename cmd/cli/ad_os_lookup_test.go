package cli

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Control-D-Inc/ctrld"
)

// adLookupResolver records whether each resolve carried the LAN mark, which is
// what keeps osResolver off Control D's public resolver. Only the OS resolver
// answers, so an explicit upstream fails over to it.
type adLookupResolver struct {
	name string
	seen *[]adLookupResolve
}

type adLookupResolve struct {
	resolver string
	lan      bool
}

func (r adLookupResolver) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	lan, _ := ctx.Value(ctrld.LanQueryCtxKey{}).(bool)
	*r.seen = append(*r.seen, adLookupResolve{r.name, lan})
	if r.name != osUpstreamConfig.Name {
		return nil, errors.New("upstream unreachable")
	}
	answer := new(dns.Msg)
	answer.SetReply(msg)
	return answer, nil
}

func newAdLookupProg(t *testing.T, leak bool) (*prog, *[]adLookupResolve) {
	t.Helper()
	cfg := &ctrld.Config{Upstream: map[string]*ctrld.UpstreamConfig{
		"0": {Name: "explicit resolver", Type: ctrld.ResolverTypeLegacy, Endpoint: "192.0.2.53:53", Timeout: 100},
	}}
	cfg.Service.LeakOnUpstreamFailure = &leak
	withActiveDirectoryDomain(t, "corp.lab")
	p := &prog{cfg: cfg, um: newUpstreamMonitor(cfg, mainLog.Load())}
	p.logger.Store(mainLog.Load())
	p.recoveryCancel = func() {}
	p.um.after = func(time.Duration, func()) {}
	p.lanLoopGuard = newLoopGuard()
	p.ptrLoopGuard = newLoopGuard()
	t.Cleanup(func() { p.querySampler.closeExpired(time.Now().Add(querySampleWindow)) })

	var seen []adLookupResolve
	origNewResolver := newResolverFn
	t.Cleanup(func() { newResolverFn = origNewResolver })
	newResolverFn = func(_ context.Context, uc *ctrld.UpstreamConfig) (ctrld.Resolver, error) {
		return adLookupResolver{name: uc.Name, seen: &seen}, nil
	}
	return p, &seen
}

func adLookupQuery(p *prog, name string, ufr *upstreamForResult) *proxyResponse {
	msg := new(dns.Msg)
	qtype := dns.TypeA
	if strings.HasPrefix(name, "_") {
		qtype = dns.TypeSRV
	}
	msg.SetQuestion(name, qtype)
	ufr.srcAddr = "192.168.0.1:1234"
	return p.proxy(context.Background(), &proxyRequest{msg: msg, ufr: ufr})
}

func wantAdLookupResolves(t *testing.T, got []adLookupResolve, want ...adLookupResolve) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("resolves = %+v, want %+v", got, want)
	}
}

// Drive proxy() itself, so the test fails if a path stops marking the query.
func Test_proxyKeepsAdLookupsOffThePublicResolver(t *testing.T) {
	captureDebugMainLog(t)
	osName := osUpstreamConfig.Name
	for _, tc := range []struct {
		name  string
		qname string
		ufr   *upstreamForResult
		leak  bool
		want  []adLookupResolve
	}{
		{
			// The auto-added AD rule has no targets, so proxy() routes it to the OS resolver.
			name:  "auto-added AD rule",
			qname: "dc01.corp.lab.",
			ufr:   &upstreamForResult{matched: true},
			want:  []adLookupResolve{{osName, true}},
		},
		{
			name:  "DC locator SRV through an AD rule",
			qname: "_ldap._tcp.dc._msdcs.corp.lab.",
			ufr:   &upstreamForResult{matched: true},
			want:  []adLookupResolve{{osName, true}},
		},
		{
			name:  "OS rule for a public name keeps the public fallback",
			qname: "example.com.",
			ufr:   &upstreamForResult{matched: true},
			want:  []adLookupResolve{{osName, false}},
		},
		{
			name:  "explicit rule for an AD name falls back to the OS resolver",
			qname: "dc01.corp.lab.",
			ufr:   &upstreamForResult{matched: true, upstreams: []string{upstreamPrefix + "0"}},
			leak:  true,
			want:  []adLookupResolve{{"explicit resolver", false}, {osName, true}},
		},
		{
			name:  "explicit rule for a public name falls back with the public resolver",
			qname: "example.com.",
			ufr:   &upstreamForResult{matched: true, upstreams: []string{upstreamPrefix + "0"}},
			leak:  true,
			want:  []adLookupResolve{{"explicit resolver", false}, {osName, false}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, seen := newAdLookupProg(t, tc.leak)
			if res := adLookupQuery(p, tc.qname, tc.ufr); res == nil || res.answer == nil {
				t.Fatal("the proxy returned no answer")
			}
			wantAdLookupResolves(t, *seen, tc.want...)
		})
	}
}

// The DNS-intercept recovery bypass forwards queries before any rule handling.
func Test_proxyRecoveryBypassKeepsAdLookupsOffThePublicResolver(t *testing.T) {
	captureDebugMainLog(t)
	useDNSIntercept(t)
	osName := osUpstreamConfig.Name
	for _, tc := range []struct {
		qname string
		lan   bool
	}{{"dc01.corp.lab.", true}, {"example.com.", false}} {
		t.Run(tc.qname, func(t *testing.T) {
			p, seen := newAdLookupProg(t, false)
			p.recoveryBypass.Store(true)
			if res := adLookupQuery(p, tc.qname, &upstreamForResult{upstreams: []string{upstreamPrefix + "0"}}); res == nil || res.answer == nil {
				t.Fatal("the proxy returned no answer")
			}
			wantAdLookupResolves(t, *seen, adLookupResolve{osName, tc.lan})
		})
	}
}
