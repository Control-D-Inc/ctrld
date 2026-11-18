package cli

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/dnscache"
	"github.com/Control-D-Inc/ctrld/testhelper"
)

// withZPADNSEchoBypass sets the three gates that guard the built-in Zscaler
// DNS echo bypass: the macOS-only platform gate, Intercept Mode, and the
// hard-mode opt-out.
func withZPADNSEchoBypass(t *testing.T, onDarwin, intercept, hard bool) {
	t.Helper()
	oldBypass, oldIntercept, oldHard := zpaDNSEchoBypassEnabled, dnsIntercept, hardIntercept
	zpaDNSEchoBypassEnabled = onDarwin
	dnsIntercept = intercept
	hardIntercept = hard
	t.Cleanup(func() {
		zpaDNSEchoBypassEnabled = oldBypass
		dnsIntercept = oldIntercept
		hardIntercept = oldHard
	})
}

// listenerWithRules builds a listener whose policy carries only domain rules.
func listenerWithRules(rules ...ctrld.Rule) *ctrld.ListenerConfig {
	return &ctrld.ListenerConfig{
		IP:   "127.0.0.1",
		Port: 53,
		Policy: &ctrld.ListenerPolicyConfig{
			Name:  "Test Policy",
			Rules: rules,
		},
	}
}

// Test_prog_upstreamFor_ZPADNSEchoBypass pins the routing decision for issue
// 601: under macOS Intercept Mode the exact Zscaler health-check name — and
// nothing else — is routed like a Control D bypass rule, i.e. with an empty
// upstream list that proxy() then resolves through upstream.os.
func Test_prog_upstreamFor_ZPADNSEchoBypass(t *testing.T) {
	cfg := testhelper.SampleConfig(t)
	p := &prog{cfg: cfg}
	p.logger.Store(mainLog.Load())
	for _, nc := range p.cfg.Network {
		for _, cidr := range nc.Cidrs {
			_, ipNet, err := net.ParseCIDR(cidr)
			require.NoError(t, err)
			nc.IPNets = append(nc.IPNets, ipNet)
		}
	}

	// A listener whose policy routes the echo name to a specific non-OS
	// upstream. That is a deliberate route for this exact name, so it wins.
	lcWithEchoRule := listenerWithRules(ctrld.Rule{zpaDNSEchoDomain: []string{"upstream.2"}})
	lcWithZscalerWildcardRule := listenerWithRules(ctrld.Rule{"*.zscaler.com": []string{"upstream.2"}})

	// Empty targets are how a Control D profile's bypass list reaches ctrld
	// (cfg.Listener rules built from resolverConfig.Exclude). This is the
	// documented pre-fix workaround, so it must keep routing to the OS path AND
	// stay classified as the health check, or upgrading a machine that still
	// carries the workaround would lose the no-cache behavior.
	lcWithEchoBypassRule := listenerWithRules(ctrld.Rule{zpaDNSEchoDomain: []string{}})
	lcWithZscalerWildcardBypassRule := listenerWithRules(ctrld.Rule{"*.zscaler.com": []string{}})

	// network.0 targets, i.e. what an un-bypassed query from 192.168.0.1 gets.
	notBypassed := []string{"upstream.1", "upstream.0"}
	const (
		inNetwork0  = "192.168.0.1:0" // matches network.0, so listener.0's policy matches
		outOfPolicy = "10.0.0.1:0"    // matches no configured network
	)

	tests := []struct {
		name          string
		onDarwin      bool
		intercept     bool
		hard          bool
		lc            *ctrld.ListenerConfig
		defaultNum    string
		srcAddr       string
		domain        string
		wantUpstreams []string
		wantMatched   bool
		wantZPAEcho   bool
	}{
		{"exact echo name routes to the OS resolver path", true, true, false, p.cfg.Listener["0"], "0", inNetwork0, zpaDNSEchoDomain, nil, true, true},
		{"echo name is matched case-insensitively and with a trailing dot", true, true, false, p.cfg.Listener["0"], "0", inNetwork0, "DNSEchoTest.ZScaler.COM.", nil, true, true},
		{"echo name is bypassed on a listener with no policy", true, true, false, p.cfg.Listener["1"], "1", inNetwork0, zpaDNSEchoDomain, nil, false, true},

		// The bypass must not double as source authorization. serveDNS refuses a
		// query on a Restricted listener when matched is false, so an
		// unauthorized source must stay unmatched even for this name — while
		// still being routed to the OS resolver path if the listener does serve
		// it. See TestZPADNSEchoBypassDoesNotAuthorizeRestrictedListener.
		{"unauthorized source is still unmatched", true, true, false, p.cfg.Listener["0"], "0", outOfPolicy, zpaDNSEchoDomain, nil, false, true},

		// An explicit domain rule routing the name to a specific upstream
		// outranks the built-in route; network/MAC policy targets, which say
		// nothing about this name, do not.
		{"explicit domain rule for the name wins", true, true, false, lcWithEchoRule, "0", inNetwork0, zpaDNSEchoDomain, []string{"upstream.2"}, true, false},
		{"explicit wildcard rule covering the name wins", true, true, false, lcWithZscalerWildcardRule, "0", inNetwork0, zpaDNSEchoDomain, []string{"upstream.2"}, true, false},

		// An explicit rule that itself selects the OS path (empty targets, i.e.
		// the Control D bypass-list shape) keeps its own labels but is still the
		// health check, so proxy() keeps it out of the cache.
		{"existing exact bypass rule stays classified as the health check", true, true, false, lcWithEchoBypassRule, "0", inNetwork0, zpaDNSEchoDomain, []string{}, true, true},
		{"existing wildcard bypass rule stays classified as the health check", true, true, false, lcWithZscalerWildcardBypassRule, "0", inNetwork0, zpaDNSEchoDomain, []string{}, true, true},

		// Gating: the bypass exists only where the problem does.
		{"not bypassed off macOS", false, true, false, p.cfg.Listener["0"], "0", inNetwork0, zpaDNSEchoDomain, notBypassed, true, false},
		{"not bypassed outside Intercept Mode", true, false, false, p.cfg.Listener["0"], "0", inNetwork0, zpaDNSEchoDomain, notBypassed, true, false},
		{"not bypassed in hard intercept mode", true, true, true, p.cfg.Listener["0"], "0", inNetwork0, zpaDNSEchoDomain, notBypassed, true, false},

		// Scope: only the one exact name, so no neighbouring name loses filtering.
		{"subdomain of the echo name is not bypassed", true, true, false, p.cfg.Listener["0"], "0", inNetwork0, "foo." + zpaDNSEchoDomain, notBypassed, true, false},
		{"echo name as a prefix of another domain is not bypassed", true, true, false, p.cfg.Listener["0"], "0", inNetwork0, zpaDNSEchoDomain + ".evil.example", notBypassed, true, false},
		{"name that merely ends with the echo name is not bypassed", true, true, false, p.cfg.Listener["0"], "0", inNetwork0, "evil" + zpaDNSEchoDomain, notBypassed, true, false},
		{"parent Zscaler domain is not bypassed", true, true, false, p.cfg.Listener["0"], "0", inNetwork0, "zscaler.com", notBypassed, true, false},
		{"ordinary domain is not bypassed", true, true, false, p.cfg.Listener["0"], "0", inNetwork0, "example.com", notBypassed, true, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withZPADNSEchoBypass(t, tc.onDarwin, tc.intercept, tc.hard)
			addr, err := net.ResolveUDPAddr("udp", tc.srcAddr)
			require.NoError(t, err)
			ctx := context.WithValue(context.Background(), ctrld.ReqIdCtxKey{}, requestID())

			ufr := p.upstreamFor(ctx, tc.defaultNum, tc.lc, addr, "", tc.domain)

			assert.Equal(t, tc.wantUpstreams, ufr.upstreams)
			assert.Equal(t, tc.wantMatched, ufr.matched, "matched is the source-authorization bit")
			assert.Equal(t, tc.wantZPAEcho, ufr.zpaDNSEcho)
			if tc.wantZPAEcho {
				// An empty upstream list is the whole mechanism: it is what
				// proxy() turns into upstream.os. Guard the translation step
				// that makes that substitution fire.
				assert.Empty(t, p.upstreamConfigsFromUpstreamNumbers(ufr.upstreams))
				if tc.lc.Policy == nil || len(tc.lc.Policy.Rules) == 0 {
					// Only relabelled when the built-in route is the one that
					// made the decision; an operator's own matching rule keeps
					// its own labels.
					assert.Equal(t, zpaDNSEchoPolicyName, ufr.matchedPolicy)
					assert.Equal(t, zpaDNSEchoDomain, ufr.matchedRule)
				}
			}
		})
	}
}

// TestZPADNSEchoBypassDoesNotAuthorizeRestrictedListener pins the serveDNS
// consequence of keeping `matched` out of the bypass: a Restricted listener
// answers only sources that match its policy, and the built-in echo route must
// not become a hole in that for every macOS DNS-intercept instance.
func TestZPADNSEchoBypassDoesNotAuthorizeRestrictedListener(t *testing.T) {
	withZPADNSEchoBypass(t, true, true, false)

	cfg := testhelper.SampleConfig(t)
	p := &prog{cfg: cfg}
	p.logger.Store(mainLog.Load())
	for _, nc := range p.cfg.Network {
		for _, cidr := range nc.Cidrs {
			_, ipNet, err := net.ParseCIDR(cidr)
			require.NoError(t, err)
			nc.IPNets = append(nc.IPNets, ipNet)
		}
	}
	lc := p.cfg.Listener["0"]
	lc.Restricted = true

	ctx := context.WithValue(context.Background(), ctrld.ReqIdCtxKey{}, requestID())
	for _, tc := range []struct {
		name        string
		srcAddr     string
		wantRefused bool
	}{
		{"source outside every network policy is refused", "10.0.0.1:0", true},
		{"source inside network.0 is served", "192.168.0.1:0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, err := net.ResolveUDPAddr("udp", tc.srcAddr)
			require.NoError(t, err)
			ufr := p.upstreamFor(ctx, "0", lc, addr, "", zpaDNSEchoDomain)

			// The route itself is unconditional; only the authorization differs.
			require.True(t, ufr.zpaDNSEcho)
			// This is the exact condition serveDNS uses to answer REFUSED.
			assert.Equal(t, tc.wantRefused, !ufr.matched && lc.Restricted)
		})
	}
}

// osResolverStub stands in for the OS resolver during a proxy() test. It
// answers NOERROR for anything, and records what it was actually asked, so a
// test can tell an answer that came off the wire from one served locally.
type osResolverStub struct {
	addr string

	mu      sync.Mutex
	queries []string
}

// startOSResolverStub points osUpstreamConfig at a local DNS server for the
// duration of the test. It uses the legacy (plain UDP) resolver type because
// ResolverTypeOS resolves through process-wide state in the ctrld package that
// a test in this package cannot address.
func startOSResolverStub(t *testing.T) *osResolverStub {
	t.Helper()

	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)

	stub := &osResolverStub{addr: pc.LocalAddr().String()}
	srv := &dns.Server{PacketConn: pc, Net: "udp"}
	srv.Handler = dns.HandlerFunc(func(w dns.ResponseWriter, m *dns.Msg) {
		stub.mu.Lock()
		stub.queries = append(stub.queries, dns.TypeToString[m.Question[0].Qtype]+" "+m.Question[0].Name)
		stub.mu.Unlock()
		answer := new(dns.Msg)
		answer.SetReply(m)
		_ = w.WriteMsg(answer)
	})

	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the OS resolver stub to start")
	}

	old := osUpstreamConfig
	osUpstreamConfig = &ctrld.UpstreamConfig{
		Name:     "OS resolver",
		Type:     ctrld.ResolverTypeLegacy,
		Endpoint: stub.addr,
		Timeout:  2000,
	}
	t.Cleanup(func() {
		osUpstreamConfig = old
		_ = srv.Shutdown()
	})
	return stub
}

func (s *osResolverStub) received() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.queries...)
}

// TestZPADNSEchoBypassReachesOSResolverUncached is the regression test for the
// two ways this route could look correct while still leaving ZPA broken.
//
//  1. It must not be served from ctrld's response cache. Client Connector
//     enables Private Access only after it observes the echo answer arrive on
//     its own DNS path; an answer we serve locally is silence to it. The nasty
//     case is an entry cached while ZPA was disconnected, which would otherwise
//     outlive InitializeOsResolver() on reconnect and keep Private Access
//     disabled for the entry's whole TTL.
//  2. It must apply to every record type, not just A, matching the Control D
//     bypass folder the customer confirmed as a workaround.
//
// It runs against three listener shapes, because the profile bypass list the
// customer is using today arrives as a listener domain rule with empty targets
// (see cfg.Listener rules built from resolverConfig.Exclude). Such a rule
// routes to the OS path on its own, so it would silently keep the cache — a
// machine upgraded while still carrying the workaround must get the fix too.
//
// A pre-existing upstream.os entry with a distinguishable rcode is seeded
// before every query, so a locally served answer is detectable.
func TestZPADNSEchoBypassReachesOSResolverUncached(t *testing.T) {
	oldDNS64 := dns64NetworkClassFn
	dns64NetworkClassFn = func() (bool, bool, error) { return true, false, nil }
	t.Cleanup(func() { dns64NetworkClassFn = oldDNS64 })

	listeners := []struct {
		name  string
		rules []ctrld.Rule
	}{
		{"no-rule", nil},
		{"exact-bypass-rule", []ctrld.Rule{{zpaDNSEchoDomain: []string{}}}},
		{"wildcard-bypass-rule", []ctrld.Rule{{"*.zscaler.com": []string{}}}},
	}
	qtypes := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeTXT, dns.TypeHTTPS, dns.TypeMX}
	for _, lcCase := range listeners {
		for _, qtype := range qtypes {
			for _, bypass := range []bool{true, false} {
				name := lcCase.name + "/" + dns.TypeToString[qtype]
				if bypass {
					name += "/bypass"
				} else {
					name += "/no-bypass"
				}
				t.Run(name, func(t *testing.T) {
					withZPADNSEchoBypass(t, bypass, true, false)
					stub := startOSResolverStub(t)

					cfg := testhelper.SampleConfig(t)
					cfg.Service.LeakOnUpstreamFailure = func(v bool) *bool { return &v }(false)
					p := &prog{cfg: cfg, um: newUpstreamMonitor(cfg, mainLog.Load())}
					p.logger.Store(mainLog.Load())
					for _, nc := range p.cfg.Network {
						for _, cidr := range nc.Cidrs {
							_, ipNet, err := net.ParseCIDR(cidr)
							require.NoError(t, err)
							nc.IPNets = append(nc.IPNets, ipNet)
						}
					}
					cache, err := dnscache.NewLRUCache(64)
					require.NoError(t, err)
					p.cache = cache

					lc := p.cfg.Listener["0"]
					if lcCase.rules != nil {
						lc = listenerWithRules(lcCase.rules...)
					}

					msg := newDnsMsgWithHostname(zpaDNSEchoDomain+".", qtype)
					// Every candidate upstream has a fresh REFUSED answer
					// waiting. The stub answers NOERROR, so the rcode says
					// whether we went to the wire or were served from cache.
					seedCache := func() {
						for _, upstream := range []string{upstreamOS, "upstream.0", "upstream.1", "upstream.2"} {
							cached := new(dns.Msg)
							cached.SetRcode(msg, dns.RcodeRefused)
							p.cache.Add(dnscache.NewKey(msg, upstream), dnscache.NewValue(cached, time.Now().Add(time.Hour)))
						}
					}

					addr, err := net.ResolveUDPAddr("udp", "192.168.0.1:0")
					require.NoError(t, err)
					ctx := context.WithValue(context.Background(), ctrld.ReqIdCtxKey{}, requestID())

					// Query twice. The second pass is what a Client Connector
					// poll after a ZPA reconnect looks like: if the first answer
					// had been cached, this one would never reach the resolver.
					for pass := 1; pass <= 2; pass++ {
						seedCache()
						ufr := p.upstreamFor(ctx, "0", lc, addr, "", zpaDNSEchoDomain)
						assert.Equal(t, bypass, ufr.zpaDNSEcho)
						res := p.proxy(ctx, &proxyRequest{msg: msg, ufr: ufr})

						require.NotNil(t, res)
						require.NotNil(t, res.answer)
						if bypass {
							assert.False(t, res.cached, "pass %d: the echo query must not be answered from cache", pass)
							assert.Equal(t, dns.RcodeSuccess, res.answer.Rcode,
								"pass %d: %s echo query must be answered by the OS resolver", pass, dns.TypeToString[qtype])
						} else {
							assert.True(t, res.cached, "pass %d: an ordinary query still uses the cache", pass)
							assert.Equal(t, dns.RcodeRefused, res.answer.Rcode,
								"pass %d: %s echo query must not reach the OS resolver when the bypass is off", pass, dns.TypeToString[qtype])
						}
					}

					got := stub.received()
					want := dns.TypeToString[qtype] + " " + zpaDNSEchoDomain + "."
					if bypass {
						assert.Equal(t, []string{want, want}, got,
							"the OS resolver must see the echo query on every poll")
						// Write side: nothing may be stored under the OS
						// upstream either, or the next poll would be local.
						cached := p.cache.Get(dnscache.NewKey(msg, upstreamOS))
						require.NotNil(t, cached, "seeded entry disappeared")
						assert.Equal(t, dns.RcodeRefused, cached.Msg.Rcode,
							"the echo answer must not be written to the cache")
					} else {
						assert.Empty(t, got, "the OS resolver must not be queried when the bypass is off")
					}
				})
			}
		}
	}
}
