package cli

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	ctrld "github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/dnscache"
)

func TestDNS64DNSSECCacheAndSynthesis(t *testing.T) {
	captureDebugMainLog(t)
	for _, do := range []bool{false, true} {
		for _, denialAD := range []bool{false, true} {
			for _, aAD := range []bool{false, true} {
				t.Run(fmt.Sprintf("DO=%v/denialAD=%v/A_AD=%v", do, denialAD, aAD), func(t *testing.T) {
					req := mkAAAAReq("dnssec.example.")
					req.SetEdns0(1232, do)
					denial := new(dns.Msg)
					denial.SetReply(req)
					denial.AuthenticatedData = denialAD
					cache, err := dnscache.NewLRUCache(10)
					if err != nil {
						t.Fatal(err)
					}
					p := &prog{cache: cache}
					p.dns64.active = true
					p.dns64.prefix = dns64WellKnownPrefix
					p.dns64.checkedAt = time.Now()
					calls := 0
					resolveA := func(q *dns.Msg) *dns.Msg {
						calls++
						if q.Question[0].Qtype != dns.TypeA {
							t.Fatal("not an A lookup")
						}
						a := new(dns.Msg)
						a.SetReply(q)
						a.AuthenticatedData = aAD
						a.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("198.51.100.7")}}
						return a
					}
					out, prefix := p.maybeDNS64(context.Background(), req, denial, resolveA)
					wantAD := do && denialAD && aAD
					if calls != 1 || !answerHasAAAA(out) || !prefix.IsValid() || out.AuthenticatedData != wantAD {
						t.Fatalf("cold: calls=%d AAAA=%v prefix=%v AD=%v wantAD=%v", calls, answerHasAAAA(out), prefix, out.AuthenticatedData, wantAD)
					}
					now := time.Now()
					for _, stale := range []bool{false, true} {
						expiry := now.Add(time.Minute)
						if stale {
							expiry = now.Add(-time.Minute)
						}
						cache.Add(dns64CacheKey(req, "upstream.0", prefix), dnscache.NewValue(out, expiry))
						answer, old, hit, variant, _ := p.cachedResponse(req, "upstream.0", prefix, true, now)
						got := answer
						if stale {
							got = old
						}
						if got == nil || !answerHasAAAA(got) || got.AuthenticatedData != wantAD || hit == stale || variant == stale {
							t.Fatalf("normal cache stale=%v: answer=%v old=%v hit=%v variant=%v", stale, answer, old, hit, variant)
						}
						cd := req.Copy()
						cd.CheckingDisabled = true
						answer, old, hit, variant, _ = p.cachedResponse(cd, "upstream.0", prefix, true, now)
						if answerHasAAAA(answer) || answerHasAAAA(old) || hit || variant {
							t.Errorf("CD cache stale=%v leaked synthesis: answer=%v old=%v hit=%v variant=%v", stale, answer, old, hit, variant)
						}
						cold, coldPrefix := p.maybeDNS64(context.Background(), cd, denial, resolveA)
						if cold != denial || coldPrefix.IsValid() || calls != 1 {
							t.Fatal("CD cold path performed synthesis")
						}
					}
					if denial.AuthenticatedData != denialAD {
						t.Fatal("mutated denial")
					}
				})
			}
		}
	}
}

func TestDNS64DNSSECOrdinaryCacheFallback(t *testing.T) {
	req := mkAAAAReq("dnssec.example.")
	req.CheckingDisabled = true
	req.SetEdns0(1232, true)
	ordinary := new(dns.Msg)
	ordinary.SetReply(req)
	cache, err := dnscache.NewLRUCache(10)
	if err != nil {
		t.Fatal(err)
	}
	p := &prog{cache: cache}
	now := time.Now()
	cache.Add(dnscache.NewKey(req, "upstream.0"), dnscache.NewValue(ordinary, now.Add(time.Minute)))
	answer, _, hit, variant, bypass := p.cachedResponse(req, "upstream.0", dns64WellKnownPrefix, true, now)
	if !hit || variant || bypass || answerHasAAAA(answer) {
		t.Fatalf("ordinary cache: hit=%v variant=%v bypass=%v answer=%v", hit, variant, bypass, answer)
	}
}

func TestRecoveryOSOnlyCandidatePool(t *testing.T) {
	for _, reason := range []RecoveryReason{RecoveryReasonNetworkChange, RecoveryReasonRegularFailure} {
		p := &prog{cfg: &ctrld.Config{Upstream: map[string]*ctrld.UpstreamConfig{"0": {Type: ctrld.ResolverTypeOS}, "nil": nil}}}
		pool := p.buildRecoveryUpstreams(reason)
		if len(pool) != 1 || pool[upstreamOS] != osUpstreamConfig {
			t.Errorf("reason=%v: OS-only recovery candidates=%v", reason, pool)
		}
	}
}

func TestDNS64DNSSECCacheDOIsolation(t *testing.T) {
	for _, do := range []bool{false, true} {
		req := mkAAAAReq("dnssec.example.")
		req.SetEdns0(1232, do)
		response := new(dns.Msg)
		response.SetReply(req)
		response.AuthenticatedData = do
		response.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("64:ff9b::c633:6407")}}
		cache, err := dnscache.NewLRUCache(10)
		if err != nil {
			t.Fatal(err)
		}
		p := &prog{cache: cache}
		now := time.Now()
		other := req.Copy()
		other.IsEdns0().SetDo(!do)
		for _, expiry := range []time.Time{now.Add(time.Minute), now.Add(-time.Minute)} {
			cache.Add(dns64CacheKey(req, "upstream.0", dns64WellKnownPrefix), dnscache.NewValue(response, expiry))
			answer, stale, hit, variant, _ := p.cachedResponse(other, "upstream.0", dns64WellKnownPrefix, true, now)
			if answer != nil || stale != nil || hit || variant {
				t.Fatalf("DO=%v result reused for DO=%v: answer=%v stale=%v", do, !do, answer, stale)
			}
		}
	}
}
