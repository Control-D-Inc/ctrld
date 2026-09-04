package cli

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"tailscale.com/net/netmon"

	"github.com/Control-D-Inc/ctrld/internal/dnscache"
)

func mkAAAAReq(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeAAAA)
	return m
}

func mkNetAddr(cidr string) net.Addr {
	ip, n, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	n.IP = ip
	return n
}

func TestDNS64NetworkClass(t *testing.T) {
	tests := []struct {
		name              string
		defaultRouteAddrs []net.Addr
		allAddrs          []net.Addr
		wantV4            bool
		wantCLAT          bool
	}{
		{"dual stack", []net.Addr{mkNetAddr("10.0.11.61/23"), mkNetAddr("2605:8d80::1/64")}, []net.Addr{mkNetAddr("10.0.11.61/23"), mkNetAddr("2605:8d80::1/64")}, true, false},
		{"virtual rfc1918 does not imply ipv4 connectivity", []net.Addr{mkNetAddr("2605:8d80::1/64")}, []net.Addr{mkNetAddr("2605:8d80::1/64"), mkNetAddr("192.168.65.1/24")}, false, false},
		{"464xlat tether (customer case)", []net.Addr{mkNetAddr("2605:8d80:6b41:122::1/64")}, []net.Addr{mkNetAddr("192.0.0.2/32"), mkNetAddr("2605:8d80:6b41:122::1/64")}, false, true},
		{"v6 only no clat (dns64 network)", []net.Addr{mkNetAddr("2001:db8::1/64")}, []net.Addr{mkNetAddr("2001:db8::1/64")}, false, false},
		{"loopback only", []net.Addr{mkNetAddr("127.0.0.1/8"), mkNetAddr("::1/128")}, []net.Addr{mkNetAddr("127.0.0.1/8"), mkNetAddr("::1/128")}, false, false},
		{"link local v4 ignored", []net.Addr{mkNetAddr("169.254.10.1/16"), mkNetAddr("2001:db8::1/64")}, []net.Addr{mkNetAddr("169.254.10.1/16"), mkNetAddr("2001:db8::1/64")}, false, false},
		{"clat plus real v4", []net.Addr{mkNetAddr("10.0.0.5/24")}, []net.Addr{mkNetAddr("192.0.0.2/32"), mkNetAddr("10.0.0.5/24")}, true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v4, clat := dns64NetworkClass(tc.defaultRouteAddrs, tc.allAddrs)
			if v4 != tc.wantV4 || clat != tc.wantCLAT {
				t.Errorf("dns64NetworkClass() = (v4=%v, clat=%v), want (v4=%v, clat=%v)", v4, clat, tc.wantV4, tc.wantCLAT)
			}
		})
	}
}

func TestNAT64PrefixFromAnswer(t *testing.T) {
	mkAnswer := func(v6 string) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion(dns64WellKnownName, dns.TypeAAAA)
		r := new(dns.Msg)
		r.SetReply(m)
		if v6 != "" {
			r.Answer = append(r.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: dns64WellKnownName, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
				AAAA: net.ParseIP(v6),
			})
		}
		return r
	}
	tests := []struct {
		name       string
		answer     *dns.Msg
		wantPrefix string
		wantOK     bool
	}{
		{"well-known prefix + 192.0.0.170", mkAnswer("64:ff9b::c000:aa"), "64:ff9b::/96", true},
		{"well-known prefix + 192.0.0.171", mkAnswer("64:ff9b::c000:ab"), "64:ff9b::/96", true},
		{"carrier-specific prefix", mkAnswer("2001:db8:64::c000:aa"), "2001:db8:64::/96", true},
		{"non-dns64 answer (real aaaa)", mkAnswer("2001:db8::1"), "", false},
		{"empty answer", mkAnswer(""), "", false},
		{"nil answer", nil, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, ok := nat64PrefixFromAnswer(tc.answer)
			if ok != tc.wantOK {
				t.Fatalf("nat64PrefixFromAnswer() ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && p != netip.MustParsePrefix(tc.wantPrefix) {
				t.Errorf("nat64PrefixFromAnswer() = %s, want %s", p, tc.wantPrefix)
			}
		})
	}
}

func TestSynthesizeAAAAFromA(t *testing.T) {
	req := mkAAAAReq("legacy.example.com")
	aReq := req.Copy()
	aReq.Question[0].Qtype = dns.TypeA
	aAns := new(dns.Msg)
	aAns.SetReply(aReq)
	aAns.Answer = []dns.RR{
		&dns.CNAME{Hdr: dns.RR_Header{Name: "legacy.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "cdn.example.net."},
		&dns.A{Hdr: dns.RR_Header{Name: "cdn.example.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("198.51.100.7")},
	}
	prefix := netip.MustParsePrefix("64:ff9b::/96")

	out := synthesizeAAAAFromA(req, aAns, prefix)
	if out == nil {
		t.Fatal("synthesizeAAAAFromA returned nil")
	}
	var gotAAAA *dns.AAAA
	var gotCNAME *dns.CNAME
	for _, rr := range out.Answer {
		switch v := rr.(type) {
		case *dns.AAAA:
			gotAAAA = v
		case *dns.CNAME:
			gotCNAME = v
		case *dns.A:
			t.Error("synthesized answer still contains an A record")
		}
	}
	if gotCNAME == nil {
		t.Error("CNAME chain record not preserved")
	}
	if gotAAAA == nil {
		t.Fatal("no synthesized AAAA record")
	}
	want := net.ParseIP("64:ff9b::c633:6407") // 198.51.100.7 embedded
	if !gotAAAA.AAAA.Equal(want) {
		t.Errorf("synthesized AAAA = %s, want %s", gotAAAA.AAAA, want)
	}
	if gotAAAA.Hdr.Ttl != 60 {
		t.Errorf("TTL not preserved: got %d", gotAAAA.Hdr.Ttl)
	}
	if out.Question[0].Qtype != dns.TypeAAAA {
		t.Errorf("reply question type = %d, want AAAA", out.Question[0].Qtype)
	}
}

func TestSynthesizeAAAAFromAIPv4Eligibility(t *testing.T) {
	req := mkAAAAReq("blocked.example")
	tests := []struct {
		name   string
		prefix netip.Prefix
		ip     string
		want   bool
	}{
		{"unspecified with well-known prefix", dns64WellKnownPrefix, "0.0.0.0", false},
		{"loopback with well-known prefix", dns64WellKnownPrefix, "127.0.0.1", false},
		{"link-local with well-known prefix", dns64WellKnownPrefix, "169.254.1.1", false},
		{"private with well-known prefix", dns64WellKnownPrefix, "10.0.0.1", false},
		{"private with network-specific prefix", netip.MustParsePrefix("2001:db8:64::/96"), "10.0.0.1", true},
		{"unspecified with network-specific prefix", netip.MustParsePrefix("2001:db8:64::/96"), "0.0.0.0", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			aReq := req.Copy()
			aReq.Question[0].Qtype = dns.TypeA
			aAns := new(dns.Msg)
			aAns.SetReply(aReq)
			aAns.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP(tc.ip)}}
			if got := answerHasAAAA(synthesizeAAAAFromA(req, aAns, tc.prefix)); got != tc.want {
				t.Fatalf("answerHasAAAA() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDNS64Eligible(t *testing.T) {
	emptyReply := func(req *dns.Msg, rcode int) *dns.Msg {
		r := new(dns.Msg)
		r.SetReply(req)
		r.Rcode = rcode
		return r
	}
	aaaaReq := mkAAAAReq("x.example.")
	cdReq := aaaaReq.Copy()
	cdReq.CheckingDisabled = true
	withAAAA := emptyReply(aaaaReq, dns.RcodeSuccess)
	withAAAA.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: "x.example.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET}, AAAA: net.ParseIP("2001:db8::1")}}
	aReq := new(dns.Msg)
	aReq.SetQuestion("x.example.", dns.TypeA)

	tests := []struct {
		name   string
		req    *dns.Msg
		answer *dns.Msg
		want   bool
	}{
		{"AAAA empty NOERROR -> eligible", aaaaReq, emptyReply(aaaaReq, dns.RcodeSuccess), true},
		{"AAAA with records -> not eligible", aaaaReq, withAAAA, false},
		{"CD query is not synthesized", cdReq, emptyReply(cdReq, dns.RcodeSuccess), false},
		{"NXDOMAIN never synthesized", aaaaReq, emptyReply(aaaaReq, dns.RcodeNameError), false},
		{"SERVFAIL never synthesized", aaaaReq, emptyReply(aaaaReq, dns.RcodeServerFailure), false},
		{"A query not eligible", aReq, emptyReply(aReq, dns.RcodeSuccess), false},
		{"nil answer", aaaaReq, nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := dns64Eligible(tc.req, tc.answer); got != tc.want {
				t.Errorf("dns64Eligible() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDNS64ActiveGating(t *testing.T) {
	cases := []struct {
		name    string
		hasV4   bool
		hasCLAT bool
		prefix  string
		want    bool
	}{
		{"dual stack, prefix known", true, false, "64:ff9b::/96", false},
		{"clat network, prefix known", false, true, "64:ff9b::/96", false},
		{"v6-only no clat, prefix known", false, false, "64:ff9b::/96", true},
		{"v6-only no clat, no prefix yet", false, false, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			old := dns64NetworkClassFn
			dns64NetworkClassFn = func() (bool, bool, error) { return tc.hasV4, tc.hasCLAT, nil }
			t.Cleanup(func() { dns64NetworkClassFn = old })

			p := &prog{}
			p.dns64.discovering = true // block background discovery in tests
			if tc.prefix != "" {
				p.dns64.prefix = netip.MustParsePrefix(tc.prefix)
			}
			if got := p.dns64Active(); got != tc.want {
				t.Errorf("dns64Active() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestStoreDiscoveredNAT64PrefixActivatesImmediately(t *testing.T) {
	p := &prog{}
	p.dns64.generation = 4
	p.dns64.checkedAt = time.Now()
	prefix := netip.MustParsePrefix("64:ff9b::/96")
	if !p.storeDiscoveredNAT64Prefix(4, prefix) {
		t.Fatal("current discovery result was rejected")
	}
	if !p.dns64.active || p.dns64.prefix != prefix || p.dns64.checkedAt.IsZero() {
		t.Fatalf("discovery did not immediately activate DNS64: active=%v prefix=%s checkedAt=%s", p.dns64.active, p.dns64.prefix, p.dns64.checkedAt)
	}
	if p.storeDiscoveredNAT64Prefix(3, netip.MustParsePrefix("2001:db8:64::/96")) {
		t.Fatal("stale discovery result was accepted")
	}
	if p.dns64.prefix != prefix {
		t.Fatalf("stale discovery replaced prefix: %s", p.dns64.prefix)
	}
}

func TestDNS64NetworkChangeInvalidatesPrefix(t *testing.T) {
	p := &prog{}
	p.dns64.prefix = netip.MustParsePrefix("64:ff9b::/96")
	p.dns64.active = true
	p.dns64.checkedAt = time.Now()
	p.dns64.discovering = true

	delta := &netmon.ChangeDelta{
		Old: &netmon.State{DefaultRouteInterface: "en0", HaveV6: true, InterfaceIPs: map[string][]netip.Prefix{"en0": {netip.MustParsePrefix("2001:db8:1::1/64")}}},
		New: &netmon.State{DefaultRouteInterface: "en0", HaveV6: true, InterfaceIPs: map[string][]netip.Prefix{"en0": {netip.MustParsePrefix("2001:db8:2::1/64")}}},
	}
	p.handleDNS64NetworkChange(delta, false)
	if p.dns64.active || p.dns64.prefix.IsValid() || !p.dns64.checkedAt.IsZero() || p.dns64.discovering {
		t.Fatalf("network change did not invalidate DNS64 state: active=%v prefix=%s checkedAt=%s discovering=%v", p.dns64.active, p.dns64.prefix, p.dns64.checkedAt, p.dns64.discovering)
	}
	if p.dns64.generation != 1 {
		t.Fatalf("generation = %d, want 1", p.dns64.generation)
	}
}

func TestDNS64CacheKeyPartitionsByPrefix(t *testing.T) {
	req := mkAAAAReq("legacy.example")
	normal := dnscache.NewKey(req, "upstream.0")
	wellKnown := dns64CacheKey(req, "upstream.0", netip.MustParsePrefix("64:ff9b::/96"))
	carrier := dns64CacheKey(req, "upstream.0", netip.MustParsePrefix("2001:db8:64::/96"))
	if normal == wellKnown || wellKnown == carrier {
		t.Fatalf("normal and per-prefix synthesized cache keys must be distinct: normal=%+v well-known=%+v carrier=%+v", normal, wellKnown, carrier)
	}
	cache, err := dnscache.NewLRUCache(4)
	if err != nil {
		t.Fatal(err)
	}
	answer := new(dns.Msg)
	answer.SetReply(req)
	cache.Add(wellKnown, dnscache.NewValue(answer, time.Now().Add(time.Minute)))
	if cache.Get(wellKnown) == nil || cache.Get(normal) != nil || cache.Get(carrier) != nil {
		t.Fatal("synthesized cache entry crossed the normal or carrier-prefix partition")
	}
}

func TestMaybeDNS64EndToEnd(t *testing.T) {
	old := dns64NetworkClassFn
	dns64NetworkClassFn = func() (bool, bool, error) { return false, false, nil }
	t.Cleanup(func() { dns64NetworkClassFn = old })

	p := &prog{}
	p.dns64.discovering = true
	p.dns64.prefix = netip.MustParsePrefix("64:ff9b::/96")

	req := mkAAAAReq("legacy.example.com")
	empty := new(dns.Msg)
	empty.SetReply(req)

	resolveA := func(aReq *dns.Msg) *dns.Msg {
		if aReq.Question[0].Qtype != dns.TypeA {
			t.Fatalf("resolveA called with qtype %d", aReq.Question[0].Qtype)
		}
		r := new(dns.Msg)
		r.SetReply(aReq)
		r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: aReq.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP("203.0.113.9")}}
		return r
	}
	out, usedPrefix := p.maybeDNS64(t.Context(), req, empty, resolveA)
	if !answerHasAAAA(out) {
		t.Fatal("expected synthesized AAAA answer")
	}
	if usedPrefix != p.dns64.prefix {
		t.Fatalf("used prefix = %s, want %s", usedPrefix, p.dns64.prefix)
	}

	blocked := new(dns.Msg)
	blocked.SetReply(req)
	blocked.Rcode = dns.RcodeNameError
	if got, _ := p.maybeDNS64(t.Context(), req, blocked, resolveA); got != blocked {
		t.Error("NXDOMAIN answer must pass through unsynthesized")
	}

	blockedA := func(aReq *dns.Msg) *dns.Msg {
		r := new(dns.Msg)
		r.SetReply(aReq)
		r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: aReq.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.IPv4zero}}
		return r
	}
	if got, prefix := p.maybeDNS64(t.Context(), req, empty, blockedA); got != empty || prefix != p.dns64.prefix {
		t.Error("NODATA plus 0.0.0.0 block answer must pass through unsynthesized and be cacheable for the current prefix")
	}
}

func TestMaybeDNS64DropsStaleInFlightPrefix(t *testing.T) {
	p := &prog{}
	p.dns64.active = true
	p.dns64.checkedAt = time.Now()
	p.dns64.prefix = netip.MustParsePrefix("64:ff9b::/96")
	req := mkAAAAReq("legacy.example")
	empty := new(dns.Msg)
	empty.SetReply(req)

	got, prefix := p.maybeDNS64(t.Context(), req, empty, func(aReq *dns.Msg) *dns.Msg {
		p.resetDNS64State()
		r := new(dns.Msg)
		r.SetReply(aReq)
		r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: aReq.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP("203.0.113.9")}}
		return r
	})
	if got != empty || prefix.IsValid() {
		t.Fatal("in-flight synthesis used a prefix invalidated by a network change")
	}
}
