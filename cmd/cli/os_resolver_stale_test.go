package cli

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Control-D-Inc/ctrld"
)

// A network change marks the OS resolver stale and reads the new network's
// nameservers before the re-bootstrap and the route lookup that follows it, so
// no query after the change meets the previous network's nameservers
// unmarked (#628).
func TestNetworkChangeReadsOSResolverBeforeReBootstrap(t *testing.T) {
	h := newNetworkEventsHarness(t, "en0", "en7")
	var events []string
	networkChangeReadOSResolverFn = func(*prog, context.Context) { events = append(events, "read") }
	networkChangeDefaultRouteIPFn = func(*prog) string {
		events = append(events, "route")
		return ""
	}
	before := orderTestState("", "", map[string][]string{"en0": nil}, map[string]bool{"en0": true})
	before.HaveV4 = false
	after := orderTestState("en7", "", map[string][]string{"en0": nil, "en7": {"192.0.2.30/24"}}, map[string]bool{"en0": true})

	h.handle(before, after, false)

	if want := []string{"read", "route"}; !slices.Equal(events, want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
}

// The read at a network change does not wait for the system to publish the
// nameservers, and keeps the OS resolver stale when it finds none.
func TestReadOSResolverOnNetworkChange(t *testing.T) {
	for _, tc := range []struct {
		name      string
		found     []string
		wantStale bool
	}{
		{"none yet", nil, true},
		{"found", []string{"[fd66:6:6::1]:53"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			captureDebugMainLog(t)
			oldQuick, oldFull := initializeOsResolverQuick, initializeOsResolver
			t.Cleanup(func() { initializeOsResolverQuick, initializeOsResolver = oldQuick, oldFull })
			var reasons []string
			initializeOsResolverQuick = func(_ context.Context, reason string) []string {
				reasons = append(reasons, reason)
				return tc.found
			}
			initializeOsResolver = func(context.Context, bool, string) []string {
				t.Fatal("the network-change read used the full read")
				return nil
			}
			p := &prog{}
			p.logger.Store(mainLog.Load())

			p.readOSResolverOnNetworkChange(context.Background())

			if want := []string{osResolverReasonNetworkChange}; !slices.Equal(reasons, want) {
				t.Fatalf("reads = %v, want %v", reasons, want)
			}
			if got := p.osResolverStale(); got != tc.wantStale {
				t.Fatalf("stale = %v, want %v", got, tc.wantStale)
			}
		})
	}
}

// The stale mark ends by itself, so a network whose nameservers are never read
// does not hold the lookup for good.
func TestOSResolverStaleExpires(t *testing.T) {
	now := time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)
	oldNow := networkEventsNowFn
	t.Cleanup(func() { networkEventsNowFn = oldNow })
	networkEventsNowFn = func() time.Time { return now }
	p := &prog{}
	p.markOSResolverStale()
	now = now.Add(osResolverStaleHold - time.Second)
	if !p.osResolverStale() {
		t.Fatal("not stale within the hold")
	}
	now = now.Add(time.Second)
	if p.osResolverStale() {
		t.Fatal("still stale after the hold")
	}
}

// staleTestResolver fails every upstream, and answers through the OS resolver
// only when osAnswers is set.
type staleTestResolver struct {
	os        bool
	osAnswers bool
}

func (r staleTestResolver) Resolve(_ context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if !r.os || !r.osAnswers {
		return nil, errors.New("network is unreachable")
	}
	answer := new(dns.Msg)
	answer.SetReply(msg)
	return answer, nil
}

// While the OS resolver holds nameservers read before the network change, a
// failed ipv4only.arpa AAAA lookup gets no answer, so the host retries it
// instead of ending its NAT64 prefix discovery on a SERVFAIL from the previous
// network's nameservers (#628). Every other failure still gets SERVFAIL.
func TestStaleOSResolverHoldsNAT64Discovery(t *testing.T) {
	for _, tc := range []struct {
		name      string
		qname     string
		qtype     uint16
		stale     bool
		osAnswers bool
		wantDrop  bool
		wantRcode int
	}{
		{"stale discovery", "ipv4only.arpa.", dns.TypeAAAA, true, false, true, 0},
		{"stale discovery, any case", "IPv4Only.Arpa.", dns.TypeAAAA, true, false, true, 0},
		{"fresh discovery", "ipv4only.arpa.", dns.TypeAAAA, false, false, false, dns.RcodeServerFailure},
		{"stale A lookup", "ipv4only.arpa.", dns.TypeA, true, false, false, dns.RcodeServerFailure},
		{"stale other name", "example.com.", dns.TypeAAAA, true, false, false, dns.RcodeServerFailure},
		{"stale discovery answered", "ipv4only.arpa.", dns.TypeAAAA, true, true, false, dns.RcodeSuccess},
	} {
		t.Run(tc.name, func(t *testing.T) {
			captureDebugMainLog(t)
			leak := true
			cfg := &ctrld.Config{Upstream: map[string]*ctrld.UpstreamConfig{
				"0": {Name: "control d", Type: ctrld.ResolverTypeDOH, Endpoint: "https://192.0.2.1/dns-query", Timeout: 100},
			}}
			cfg.Service.LeakOnUpstreamFailure = &leak
			p := &prog{cfg: cfg, um: newUpstreamMonitor(cfg, mainLog.Load())}
			p.logger.Store(mainLog.Load())
			p.um.after = func(time.Duration, func()) {}
			p.lanLoopGuard = newLoopGuard()
			p.ptrLoopGuard = newLoopGuard()
			t.Cleanup(func() { p.querySampler.closeExpired(time.Now().Add(querySampleWindow)) })
			oldResolver, oldRecovery := newResolverFn, queryRecoveryFn
			t.Cleanup(func() { newResolverFn, queryRecoveryFn = oldResolver, oldRecovery })
			newResolverFn = func(_ context.Context, uc *ctrld.UpstreamConfig) (ctrld.Resolver, error) {
				return staleTestResolver{os: uc.Name == osUpstreamConfig.Name, osAnswers: tc.osAnswers}, nil
			}
			queryRecoveryFn = func(*prog, RecoveryReason) {}
			if tc.stale {
				p.markOSResolverStale()
			}
			msg := new(dns.Msg)
			msg.SetQuestion(tc.qname, tc.qtype)

			res := p.proxy(context.Background(), &proxyRequest{msg: msg, ufr: &upstreamForResult{
				upstreams: []string{upstreamPrefix + "0"}, srcAddr: "127.0.0.1:5353",
			}})

			if res.drop != tc.wantDrop {
				t.Fatalf("drop = %v, want %v", res.drop, tc.wantDrop)
			}
			if tc.wantDrop {
				if res.answer != nil {
					t.Fatalf("dropped query has an answer: %v", res.answer)
				}
				return
			}
			if res.answer == nil || res.answer.Rcode != tc.wantRcode {
				t.Fatalf("answer = %v, want rcode %s", res.answer, dns.RcodeToString[tc.wantRcode])
			}
		})
	}
}
