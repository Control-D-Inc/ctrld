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

func Test_wildcardMatches(t *testing.T) {
	tests := []struct {
		name     string
		wildcard string
		domain   string
		match    bool
	}{
		{"domain - prefix parent should not match", "*.example.com", "example.com", false},
		{"domain - prefix", "*.example.com", "anything.example.com", true},
		{"domain - prefix not match other s", "*.example.com", "other.org", false},
		{"domain - prefix not match s in name", "*.example.com", "eexample.com", false},
		{"domain - suffix", "suffix.*", "suffix.example.com", true},
		{"domain - suffix not match other", "suffix.*", "suffix1.example.com", false},
		{"domain - both", "suffix.*.example.com", "suffix.anything.example.com", true},
		{"domain - both not match", "suffix.*.example.com", "suffix1.suffix.example.com", false},
		{"domain - case-insensitive", "*.EXAMPLE.com", "anything.example.com", true},
		{"mac - prefix", "*:98:05:b4:2b", "d4:67:98:05:b4:2b", true},
		{"mac - prefix not match other s", "*:98:05:b4:2b", "0d:ba:54:09:94:2c", false},
		{"mac - prefix not match s in name", "*:98:05:b4:2b", "e4:67:97:05:b4:2b", false},
		{"mac - suffix", "d4:67:98:*", "d4:67:98:05:b4:2b", true},
		{"mac - suffix not match other", "d4:67:98:*", "d4:67:97:15:b4:2b", false},
		{"mac - both", "d4:67:98:*:b4:2b", "d4:67:98:05:b4:2b", true},
		{"mac - both not match", "d4:67:98:*:b4:2b", "d4:67:97:05:c4:2b", false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := wildcardMatches(tc.wildcard, tc.domain); got != tc.match {
				t.Errorf("unexpected result, wildcard: %s, domain: %s, want: %v, got: %v", tc.wildcard, tc.domain, tc.match, got)
			}
		})
	}
}

func Test_canonicalName(t *testing.T) {
	tests := []struct {
		name      string
		domain    string
		canonical string
	}{
		{"fqdn to canonical", "example.com.", "example.com"},
		{"already canonical", "example.com", "example.com"},
		{"case insensitive", "Example.Com.", "example.com"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := canonicalName(tc.domain); got != tc.canonical {
				t.Errorf("unexpected result, want: %s, got: %s", tc.canonical, got)
			}
		})
	}
}

func Test_prog_upstreamFor(t *testing.T) {
	cfg := testhelper.SampleConfig(t)
	cfg.Service.LeakOnUpstreamFailure = func(v bool) *bool { return &v }(false)
	p := &prog{cfg: cfg}
	p.um = newUpstreamMonitor(p.cfg)
	p.lanLoopGuard = newLoopGuard()
	p.ptrLoopGuard = newLoopGuard()
	for _, nc := range p.cfg.Network {
		for _, cidr := range nc.Cidrs {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				t.Fatal(err)
			}
			nc.IPNets = append(nc.IPNets, ipNet)
		}
	}

	tests := []struct {
		name               string
		ip                 string
		mac                string
		defaultUpstreamNum string
		lc                 *ctrld.ListenerConfig
		domain             string
		upstreams          []string
		matched            bool
		testLogMsg         string
	}{
		{"Policy map matches", "192.168.0.1:0", "", "0", p.cfg.Listener["0"], "abc.xyz", []string{"upstream.1", "upstream.0"}, true, ""},
		{"Policy split matches", "192.168.0.1:0", "", "0", p.cfg.Listener["0"], "abc.ru", []string{"upstream.1"}, true, ""},
		{"Policy map for other network matches", "192.168.1.2:0", "", "0", p.cfg.Listener["0"], "abc.xyz", []string{"upstream.0"}, true, ""},
		{"No policy map for listener", "192.168.1.2:0", "", "1", p.cfg.Listener["1"], "abc.ru", []string{"upstream.1"}, false, ""},
		{"unenforced loging", "192.168.1.2:0", "", "0", p.cfg.Listener["0"], "abc.ru", []string{"upstream.1"}, true, "My Policy, network.1 (unenforced), *.ru -> [upstream.1]"},
		{"Policy Macs matches upper", "192.168.0.1:0", "14:45:A0:67:83:0A", "0", p.cfg.Listener["0"], "abc.xyz", []string{"upstream.2"}, true, "14:45:a0:67:83:0a"},
		{"Policy Macs matches lower", "192.168.0.1:0", "14:54:4a:8e:08:2d", "0", p.cfg.Listener["0"], "abc.xyz", []string{"upstream.2"}, true, "14:54:4a:8e:08:2d"},
		{"Policy Macs matches case-insensitive", "192.168.0.1:0", "14:54:4A:8E:08:2D", "0", p.cfg.Listener["0"], "abc.xyz", []string{"upstream.2"}, true, "14:54:4a:8e:08:2d"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, network := range []string{"udp", "tcp"} {
				var (
					addr net.Addr
					err  error
				)
				switch network {
				case "udp":
					addr, err = net.ResolveUDPAddr(network, tc.ip)
				case "tcp":
					addr, err = net.ResolveTCPAddr(network, tc.ip)
				}
				require.NoError(t, err)
				require.NotNil(t, addr)
				ctx := context.WithValue(context.Background(), ctrld.ReqIdCtxKey{}, requestID())
				ufr := p.upstreamFor(ctx, tc.defaultUpstreamNum, tc.lc, addr, tc.mac, tc.domain)
				p.proxy(ctx, &proxyRequest{
					msg: newDnsMsgWithHostname("foo", dns.TypeA),
					ufr: ufr,
				})
				assert.Equal(t, tc.matched, ufr.matched)
				assert.Equal(t, tc.upstreams, ufr.upstreams)
				if tc.testLogMsg != "" {
					assert.Contains(t, logOutput.String(), tc.testLogMsg)
				}
			}
		})
	}
}

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
		{"existing exact bypass rule stays classified as the health check", true, true, false, lcWithEchoBypassRule, "0", inNetwork0, zpaDNSEchoDomain, nil, true, true},
		{"existing wildcard bypass rule stays classified as the health check", true, true, false, lcWithZscalerWildcardBypassRule, "0", inNetwork0, zpaDNSEchoDomain, nil, true, true},

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
					p := &prog{cfg: cfg, um: newUpstreamMonitor(cfg)}
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

func TestCache(t *testing.T) {
	cfg := testhelper.SampleConfig(t)
	prog := &prog{cfg: cfg}
	for _, nc := range prog.cfg.Network {
		for _, cidr := range nc.Cidrs {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				t.Fatal(err)
			}
			nc.IPNets = append(nc.IPNets, ipNet)
		}
	}
	cacher, err := dnscache.NewLRUCache(4096)
	require.NoError(t, err)
	prog.cache = cacher

	msg := new(dns.Msg)
	msg.SetQuestion("example.com", dns.TypeA)
	msg.MsgHdr.RecursionDesired = true
	answer1 := new(dns.Msg)
	answer1.SetRcode(msg, dns.RcodeSuccess)

	prog.cache.Add(dnscache.NewKey(msg, "upstream.1"), dnscache.NewValue(answer1, time.Now().Add(time.Minute)))
	answer2 := new(dns.Msg)
	answer2.SetRcode(msg, dns.RcodeRefused)
	prog.cache.Add(dnscache.NewKey(msg, "upstream.0"), dnscache.NewValue(answer2, time.Now().Add(time.Minute)))

	req1 := &proxyRequest{
		msg:            msg,
		ci:             nil,
		failoverRcodes: nil,
		ufr: &upstreamForResult{
			upstreams:      []string{"upstream.1"},
			matchedPolicy:  "",
			matchedNetwork: "",
			matchedRule:    "",
			matched:        false,
		},
	}
	req2 := &proxyRequest{
		msg:            msg,
		ci:             nil,
		failoverRcodes: nil,
		ufr: &upstreamForResult{
			upstreams:      []string{"upstream.0"},
			matchedPolicy:  "",
			matchedNetwork: "",
			matchedRule:    "",
			matched:        false,
		},
	}
	got1 := prog.proxy(context.Background(), req1)
	got2 := prog.proxy(context.Background(), req2)
	assert.NotSame(t, got1, got2)
	assert.Equal(t, answer1.Rcode, got1.answer.Rcode)
	assert.Equal(t, answer2.Rcode, got2.answer.Rcode)
}

func TestDNS64CacheLookup(t *testing.T) {
	cfg := testhelper.SampleConfig(t)
	p := &prog{cfg: cfg}
	cache, err := dnscache.NewLRUCache(16)
	require.NoError(t, err)
	p.cache = cache

	now := time.Now()
	prefix := dns64WellKnownPrefix
	req := mkAAAAReq("legacy.example")
	upstream := "upstream.0"
	empty := new(dns.Msg)
	empty.SetReply(req)
	synthesized := new(dns.Msg)
	synthesized.SetReply(req)
	synthesized.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("64:ff9b::c000:201")}}

	t.Run("fresh variant hit", func(t *testing.T) {
		p.cache.Purge()
		p.cache.Add(dns64CacheKey(req, upstream, prefix), dnscache.NewValue(synthesized, now.Add(time.Minute)))
		answer, stale, hit, dns64Hit, bypass := p.cachedResponse(req, upstream, prefix, true, now)
		if answer == nil || !answerHasAAAA(answer) || stale != nil || !hit || !dns64Hit || bypass {
			t.Fatalf("unexpected lookup result: answer=%v stale=%v hit=%v dns64Hit=%v bypass=%v", answer, stale, hit, dns64Hit, bypass)
		}
	})

	t.Run("fresh empty normal answer is retained as stale while bypassed", func(t *testing.T) {
		p.cache.Purge()
		p.cache.Add(dnscache.NewKey(req, upstream), dnscache.NewValue(empty, now.Add(time.Minute)))
		answer, stale, hit, dns64Hit, bypass := p.cachedResponse(req, upstream, prefix, true, now)
		if answer != nil || stale == nil || hit || dns64Hit || !bypass {
			t.Fatalf("unexpected lookup result: answer=%v stale=%v hit=%v dns64Hit=%v bypass=%v", answer, stale, hit, dns64Hit, bypass)
		}
	})

	t.Run("expired variant is preferred as stale", func(t *testing.T) {
		p.cache.Purge()
		p.cache.Add(dns64CacheKey(req, upstream, prefix), dnscache.NewValue(synthesized, now.Add(-time.Minute)))
		p.cache.Add(dnscache.NewKey(req, upstream), dnscache.NewValue(empty, now.Add(-time.Minute)))
		answer, stale, hit, dns64Hit, bypass := p.cachedResponse(req, upstream, prefix, true, now)
		if answer != nil || stale == nil || !answerHasAAAA(stale) || hit || dns64Hit || bypass {
			t.Fatalf("unexpected lookup result: answer=%v stale=%v hit=%v dns64Hit=%v bypass=%v", answer, stale, hit, dns64Hit, bypass)
		}
	})
}

func Test_ipAndMacFromMsg(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		wantIp  bool
		mac     string
		wantMac bool
	}{
		{"has ip v4 and mac", "1.2.3.4", true, "4c:20:b8:ab:87:1b", true},
		{"has ip v6 and mac", "2606:1a40:3::1", true, "4c:20:b8:ab:87:1b", true},
		{"no ip", "1.2.3.4", false, "4c:20:b8:ab:87:1b", false},
		{"no mac", "1.2.3.4", false, "4c:20:b8:ab:87:1b", false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatal("missing IP")
			}
			hw, err := net.ParseMAC(tc.mac)
			if err != nil {
				t.Fatal(err)
			}
			m := new(dns.Msg)
			m.SetQuestion("example.com.", dns.TypeA)
			o := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
			if tc.wantMac {
				ec1 := &dns.EDNS0_LOCAL{Code: EDNS0_OPTION_MAC, Data: hw}
				o.Option = append(o.Option, ec1)
			}
			if tc.wantIp {
				ec2 := &dns.EDNS0_SUBNET{Address: ip}
				o.Option = append(o.Option, ec2)
			}
			m.Extra = append(m.Extra, o)
			gotIP, gotMac := ipAndMacFromMsg(m)
			if tc.wantMac && gotMac != tc.mac {
				t.Errorf("mismatch, want: %q, got: %q", tc.mac, gotMac)
			}
			if !tc.wantMac && gotMac != "" {
				t.Errorf("unexpected mac: %q", gotMac)
			}
			if tc.wantIp && gotIP != tc.ip {
				t.Errorf("mismatch, want: %q, got: %q", tc.ip, gotIP)
			}
			if !tc.wantIp && gotIP != "" {
				t.Errorf("unexpected ip: %q", gotIP)
			}
		})
	}
}

func Test_remoteAddrFromMsg(t *testing.T) {
	loopbackIP := net.ParseIP("127.0.0.1")
	tests := []struct {
		name string
		addr net.Addr
		ci   *ctrld.ClientInfo
		want string
	}{
		{"tcp", &net.TCPAddr{IP: loopbackIP, Port: 12345}, &ctrld.ClientInfo{IP: "192.168.1.10"}, "192.168.1.10:12345"},
		{"udp", &net.UDPAddr{IP: loopbackIP, Port: 12345}, &ctrld.ClientInfo{IP: "192.168.1.11"}, "192.168.1.11:12345"},
		{"nil client info", &net.UDPAddr{IP: loopbackIP, Port: 12345}, nil, "127.0.0.1:12345"},
		{"empty ip", &net.UDPAddr{IP: loopbackIP, Port: 12345}, &ctrld.ClientInfo{}, "127.0.0.1:12345"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			addr := spoofRemoteAddr(tc.addr, tc.ci)
			if addr.String() != tc.want {
				t.Errorf("unexpected result, want: %q, got: %q", tc.want, addr.String())
			}
		})
	}
}

func Test_ipFromARPA(t *testing.T) {
	tests := []struct {
		IP   string
		ARPA string
	}{
		{"1.2.3.4", "4.3.2.1.in-addr.arpa."},
		{"245.110.36.114", "114.36.110.245.in-addr.arpa."},
		{"::ffff:12.34.56.78", "78.56.34.12.in-addr.arpa."},
		{"::1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa."},
		{"1::", "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.ip6.arpa."},
		{"1234:567::89a:bcde", "e.d.c.b.a.9.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.6.5.0.4.3.2.1.ip6.arpa."},
		{"1234:567:fefe:bcbc:adad:9e4a:89a:bcde", "e.d.c.b.a.9.8.0.a.4.e.9.d.a.d.a.c.b.c.b.e.f.e.f.7.6.5.0.4.3.2.1.ip6.arpa."},
		{"", "asd.in-addr.arpa."},
		{"", "asd.ip6.arpa."},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.IP, func(t *testing.T) {
			t.Parallel()
			if got := ipFromARPA(tc.ARPA); !got.Equal(net.ParseIP(tc.IP)) {
				t.Errorf("unexpected ip, want: %s, got: %s", tc.IP, got)
			}
		})
	}
}

func newDnsMsgWithClientIP(ip string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	o := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	o.Option = append(o.Option, &dns.EDNS0_SUBNET{Address: net.ParseIP(ip)})
	m.Extra = append(m.Extra, o)
	return m
}

func Test_stripClientSubnet(t *testing.T) {
	tests := []struct {
		name       string
		msg        *dns.Msg
		wantSubnet bool
	}{
		{"no edns0", new(dns.Msg), false},
		{"loopback IP v4", newDnsMsgWithClientIP("127.0.0.1"), false},
		{"loopback IP v6", newDnsMsgWithClientIP("::1"), false},
		{"private IP v4", newDnsMsgWithClientIP("192.168.1.123"), false},
		{"private IP v6", newDnsMsgWithClientIP("fd12:3456:789a:1::1"), false},
		{"public IP", newDnsMsgWithClientIP("1.1.1.1"), true},
		{"invalid IP", newDnsMsgWithClientIP(""), true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			stripClientSubnet(tc.msg)
			hasSubnet := false
			if opt := tc.msg.IsEdns0(); opt != nil {
				for _, s := range opt.Option {
					if _, ok := s.(*dns.EDNS0_SUBNET); ok {
						hasSubnet = true
					}
				}
			}
			if tc.wantSubnet != hasSubnet {
				t.Errorf("unexpected result, want: %v, got: %v", tc.wantSubnet, hasSubnet)
			}
		})
	}
}

func newDnsMsgWithHostname(hostname string, typ uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(hostname, typ)
	return m
}

func Test_isLanHostnameQuery(t *testing.T) {
	tests := []struct {
		name               string
		msg                *dns.Msg
		isLanHostnameQuery bool
	}{
		{"A", newDnsMsgWithHostname("foo", dns.TypeA), true},
		{"AAAA", newDnsMsgWithHostname("foo", dns.TypeAAAA), true},
		{"A not LAN", newDnsMsgWithHostname("example.com", dns.TypeA), false},
		{"AAAA not LAN", newDnsMsgWithHostname("example.com", dns.TypeAAAA), false},
		{"Not A or AAAA", newDnsMsgWithHostname("foo", dns.TypeTXT), false},
		{".domain", newDnsMsgWithHostname("foo.domain", dns.TypeA), true},
		{".lan", newDnsMsgWithHostname("foo.lan", dns.TypeA), true},
		{".local", newDnsMsgWithHostname("foo.local", dns.TypeA), true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isLanHostnameQuery(tc.msg); tc.isLanHostnameQuery != got {
				t.Errorf("unexpected result, want: %v, got: %v", tc.isLanHostnameQuery, got)
			}
		})
	}
}

func newDnsMsgPtr(ip string, t *testing.T) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	ptr, err := dns.ReverseAddr(ip)
	if err != nil {
		t.Fatal(err)
	}
	m.SetQuestion(ptr, dns.TypePTR)
	return m
}

func Test_isPrivatePtrLookup(t *testing.T) {
	tests := []struct {
		name               string
		msg                *dns.Msg
		isPrivatePtrLookup bool
	}{
		// RFC 1918 allocates 10.0.0.0/8, 172.16.0.0/12, and 192.168.0.0/16 as
		{"10.0.0.0/8", newDnsMsgPtr("10.0.0.123", t), true},
		{"172.16.0.0/12", newDnsMsgPtr("172.16.0.123", t), true},
		{"192.168.0.0/16", newDnsMsgPtr("192.168.1.123", t), true},
		{"CGNAT", newDnsMsgPtr("100.66.27.28", t), true},
		{"Loopback", newDnsMsgPtr("127.0.0.1", t), true},
		{"Link Local Unicast", newDnsMsgPtr("fe80::69f6:e16e:8bdb:433f", t), true},
		// RFC 7335 IPv4 Service Continuity Prefix (464XLAT/DS-Lite CLAT), see #552.
		{"464XLAT CLAT host", newDnsMsgPtr("192.0.0.2", t), true},
		{"Public IP", newDnsMsgPtr("8.8.8.8", t), false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isPrivatePtrLookup(tc.msg); tc.isPrivatePtrLookup != got {
				t.Errorf("unexpected result, want: %v, got: %v", tc.isPrivatePtrLookup, got)
			}
		})
	}
}

func Test_isSrvLanLookup(t *testing.T) {
	tests := []struct {
		name        string
		msg         *dns.Msg
		isSrvLookup bool
	}{
		{"SRV LAN", newDnsMsgWithHostname("foo", dns.TypeSRV), true},
		{"Not SRV", newDnsMsgWithHostname("foo", dns.TypeNone), false},
		{"Not SRV LAN", newDnsMsgWithHostname("controld.com", dns.TypeSRV), false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isSrvLanLookup(tc.msg); tc.isSrvLookup != got {
				t.Errorf("unexpected result, want: %v, got: %v", tc.isSrvLookup, got)
			}
		})
	}
}

func Test_isWanClient(t *testing.T) {
	tests := []struct {
		name        string
		addr        net.Addr
		isWanClient bool
	}{
		// RFC 1918 allocates 10.0.0.0/8, 172.16.0.0/12, and 192.168.0.0/16 as
		{"10.0.0.0/8", &net.UDPAddr{IP: net.ParseIP("10.0.0.123")}, false},
		{"172.16.0.0/12", &net.UDPAddr{IP: net.ParseIP("172.16.0.123")}, false},
		{"192.168.0.0/16", &net.UDPAddr{IP: net.ParseIP("192.168.1.123")}, false},
		{"CGNAT", &net.UDPAddr{IP: net.ParseIP("100.66.27.28")}, false},
		{"Loopback", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}, false},
		{"Link Local Unicast", &net.UDPAddr{IP: net.ParseIP("fe80::69f6:e16e:8bdb:433f")}, false},
		// RFC 7335 IPv4 Service Continuity Prefix (464XLAT/DS-Lite CLAT), see #552.
		{"464XLAT PLAT side", &net.UDPAddr{IP: net.ParseIP("192.0.0.1")}, false},
		{"464XLAT CLAT host", &net.UDPAddr{IP: net.ParseIP("192.0.0.2")}, false},
		// Outside the /29 but inside 192.0.0.0/24: still WAN (fix is scoped to /29).
		{"192.0.0.0/24 outside /29", &net.UDPAddr{IP: net.ParseIP("192.0.0.100")}, true},
		{"Public", &net.UDPAddr{IP: net.ParseIP("8.8.8.8")}, true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isWanClient(tc.addr); tc.isWanClient != got {
				t.Errorf("unexpected result, want: %v, got: %v", tc.isWanClient, got)
			}
		})
	}
}

func Test_prog_queryFromSelf(t *testing.T) {
	p := &prog{}
	require.NotPanics(t, func() {
		p.queryFromSelf("")
	})
	require.NotPanics(t, func() {
		p.queryFromSelf("foo")
	})
}

func Test_sameQuestion(t *testing.T) {
	mk := func(name string, qtype uint16) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion(name, qtype)
		return m
	}
	tests := []struct {
		name   string
		req    *dns.Msg
		answer *dns.Msg
		want   bool
	}{
		{"identical", mk("example.com.", dns.TypeA), mk("example.com.", dns.TypeA), true},
		{"case insensitive", mk("Example.COM.", dns.TypeA), mk("example.com.", dns.TypeA), true},
		{"different name", mk("victim.example.", dns.TypeA), mk("attacker.example.", dns.TypeA), false},
		{"different type", mk("example.com.", dns.TypeA), mk("example.com.", dns.TypeAAAA), false},
		{"nil req", nil, mk("example.com.", dns.TypeA), false},
		{"nil answer", mk("example.com.", dns.TypeA), nil, false},
		{"empty answer question", mk("example.com.", dns.TypeA), new(dns.Msg), false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := sameQuestion(tc.req, tc.answer); got != tc.want {
				t.Errorf("sameQuestion() = %v, want %v", got, tc.want)
			}
		})
	}
}
