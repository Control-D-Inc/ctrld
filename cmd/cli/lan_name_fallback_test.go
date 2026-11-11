package cli

import (
	"context"
	"encoding/binary"

	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Control-D-Inc/ctrld"
)

var lanTestAdapter = lanFallbackAdapter{
	ifIndex:   7,
	prefix:    netip.MustParsePrefix("192.168.77.125/24"),
	netbios:   true,
	multicast: true,
	suffixes:  []string{"lan"},
}

func TestLanFallbackTargetFor(t *testing.T) {
	adapters := []lanFallbackAdapter{lanTestAdapter}
	for _, tc := range []struct {
		qname string
		want  lanFallbackTarget
		ok    bool
	}{
		// What the lab saw: Windows appends the connection suffix first.
		{"qa-nbonly.lan.", lanFallbackTarget{netbios: "QA-NBONLY", mdns: "qa-nbonly.local"}, true},
		{"QA-NBONLY.", lanFallbackTarget{netbios: "QA-NBONLY", mdns: "qa-nbonly.local"}, true},
		{"qa-mdnsonly.local.", lanFallbackTarget{mdns: "qa-mdnsonly.local"}, true},
		// 16+ characters cannot be a NetBIOS name; mDNS still applies.
		{"a-very-long-hostname.lan.", lanFallbackTarget{mdns: "a-very-long-hostname.local"}, true},
		// A suffix the adapter does not use means a real DNS name.
		{"printer.domain.", lanFallbackTarget{}, false},
		{"host.example.com.", lanFallbackTarget{}, false},
		// Two labels under the adapter suffix is a DNS name, not a host label.
		{"a.b.lan.", lanFallbackTarget{}, false},
		{"a.b.local.", lanFallbackTarget{}, false},
		{"bad*name.", lanFallbackTarget{}, false},
		{"-dash.", lanFallbackTarget{}, false},
		{".", lanFallbackTarget{}, false},
	} {
		got, ok := lanFallbackTargetFor(tc.qname, adapters)
		if ok != tc.ok || got != tc.want {
			t.Errorf("%q: got %+v %v, want %+v %v", tc.qname, got, ok, tc.want, tc.ok)
		}
	}
}

func TestLanFallbackAdapterBroadcastAndOnLink(t *testing.T) {
	if got := lanTestAdapter.broadcast(); got != netip.MustParseAddr("192.168.77.255") {
		t.Fatalf("broadcast = %s", got)
	}
	if !lanTestAdapter.onLink(netip.MustParseAddr("192.168.77.1")) {
		t.Error("on-link responder rejected")
	}
	if lanTestAdapter.onLink(netip.MustParseAddr("203.0.113.9")) {
		t.Error("off-link responder accepted")
	}
}

type fakeLanPlatform struct {
	adapters  []lanFallbackAdapter
	mdnsOn    bool
	nbAddr    netip.Addr
	mdnsAddr  netip.Addr
	delay     time.Duration
	nbCalls   atomic.Int32
	mdnsCalls atomic.Int32
}

func (f *fakeLanPlatform) platform() lanFallbackPlatform {
	answer := func(calls *atomic.Int32, addr netip.Addr) func(context.Context, lanFallbackAdapter, string) (netip.Addr, error) {
		return func(ctx context.Context, _ lanFallbackAdapter, _ string) (netip.Addr, error) {
			calls.Add(1)
			select {
			case <-time.After(f.delay):
			case <-ctx.Done():
				return netip.Addr{}, ctx.Err()
			}
			if !addr.IsValid() {
				<-ctx.Done()
				return netip.Addr{}, ctx.Err()
			}
			return addr, nil
		}
	}
	return lanFallbackPlatform{
		adapters:    func() []lanFallbackAdapter { return f.adapters },
		mdnsEnabled: func() bool { return f.mdnsOn },
		nbns:        answer(&f.nbCalls, f.nbAddr),
		mdns:        answer(&f.mdnsCalls, f.mdnsAddr),
	}
}

func newTestFallback(f *fakeLanPlatform) *lanNameFallback {
	fb := newLanNameFallback(f.platform())
	fb.timeout = 200 * time.Millisecond
	return fb
}

// The fallback follows what Windows has enabled: an adapter with NetBIOS off
// is never broadcast on, and mDNS off means no mDNS query.
func TestLanFallbackFollowsOSSettings(t *testing.T) {
	ip := netip.MustParseAddr("192.168.77.1")
	for _, tc := range []struct {
		name      string
		netbios   bool
		mdnsOn    bool
		multicast bool
		qname     string
		wantProto string
		wantNB    int32
		wantMDNS  int32
	}{
		{"netbios on", true, false, true, "qa-nbonly.lan.", "NetBIOS", 1, 0},
		{"netbios off on the adapter", false, false, true, "qa-nbonly.lan.", "", 0, 0},
		{"mdns on", false, true, true, "qa-mdnsonly.local.", "mDNS", 0, 1},
		{"mdns off by policy", true, false, true, "qa-mdnsonly.local.", "", 0, 0},
		{"adapter without multicast", false, true, false, "qa-mdnsonly.local.", "", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := lanTestAdapter
			a.netbios, a.multicast = tc.netbios, tc.multicast
			f := &fakeLanPlatform{adapters: []lanFallbackAdapter{a}, mdnsOn: tc.mdnsOn, nbAddr: ip, mdnsAddr: ip}
			addr, proto, ok := newTestFallback(f).resolve(context.Background(), tc.qname)
			if proto != tc.wantProto || ok != (tc.wantProto != "") || (ok && addr != ip) {
				t.Fatalf("got %s %q %v, want %q", addr, proto, ok, tc.wantProto)
			}
			if f.nbCalls.Load() != tc.wantNB || f.mdnsCalls.Load() != tc.wantMDNS {
				t.Fatalf("calls nbns=%d mdns=%d, want %d/%d", f.nbCalls.Load(), f.mdnsCalls.Load(), tc.wantNB, tc.wantMDNS)
			}
		})
	}
}

// An answer from outside the adapter's subnet is not a LAN host.
func TestLanFallbackRejectsOffLinkAnswer(t *testing.T) {
	f := &fakeLanPlatform{adapters: []lanFallbackAdapter{lanTestAdapter}, nbAddr: netip.MustParseAddr("203.0.113.9")}
	if _, _, ok := newTestFallback(f).resolve(context.Background(), "qa-nbonly.lan."); ok {
		t.Fatal("off-link answer accepted")
	}
}

// A/AAAA pairs and DNS Client retries for one name share one lookup, and a
// miss is remembered so it is not broadcast again at once.
func TestLanFallbackCollapsesAndRemembersMisses(t *testing.T) {
	f := &fakeLanPlatform{adapters: []lanFallbackAdapter{lanTestAdapter}, mdnsOn: true}
	fb := newTestFallback(f)
	now := time.Now()
	fb.now = func() time.Time { return now }
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, ok := fb.resolve(context.Background(), "nobody.lan."); ok {
				t.Error("miss resolved")
			}
		}()
	}
	wg.Wait()
	if n := f.nbCalls.Load(); n != 1 {
		t.Fatalf("nbns calls = %d, want 1", n)
	}
	start := time.Now()
	fb.resolve(context.Background(), "NOBODY.")
	if f.nbCalls.Load() != 1 || time.Since(start) > 50*time.Millisecond {
		t.Fatal("a remembered miss was looked up again")
	}
	now = now.Add(lanFallbackMissTTL)
	fb.resolve(context.Background(), "nobody.lan.")
	if f.nbCalls.Load() != 2 {
		t.Fatal("an expired miss was not looked up again")
	}
}

// The lookup is bounded even when the caller's context never ends.
func TestLanFallbackIsBounded(t *testing.T) {
	f := &fakeLanPlatform{adapters: []lanFallbackAdapter{lanTestAdapter}, mdnsOn: true}
	start := time.Now()
	newTestFallback(f).resolve(context.Background(), "nobody.lan.")
	if d := time.Since(start); d > time.Second {
		t.Fatalf("lookup took %s", d)
	}
}

func TestLanFallbackAnswer(t *testing.T) {
	ip := netip.MustParseAddr("192.168.77.1")
	a := new(dns.Msg).SetQuestion("qa-nbonly.lan.", dns.TypeA)
	got := lanFallbackAnswer(a, ip)
	if got.Rcode != dns.RcodeSuccess || len(got.Answer) != 1 || got.Answer[0].(*dns.A).A.String() != "192.168.77.1" ||
		got.Answer[0].Header().Name != "qa-nbonly.lan." || got.Answer[0].Header().Ttl != lanFallbackAnswerTTL {
		t.Fatalf("A answer = %v", got)
	}
	aaaa := new(dns.Msg).SetQuestion("qa-nbonly.lan.", dns.TypeAAAA)
	if got := lanFallbackAnswer(aaaa, ip); got.Rcode != dns.RcodeSuccess || len(got.Answer) != 0 {
		t.Fatalf("AAAA must be NODATA, got %v", got)
	}
}

// nbnsResponder answers one NetBIOS name query the way a Windows or Samba
// host does, on a real UDP socket.
func nbnsResponder(t *testing.T, name string, ip netip.Addr) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := buf[:n]
			id := binary.BigEndian.Uint16(q)
			if string(q[12:12+34]) != string(nbnsQueryPacket(id, name)[12:12+34]) {
				continue
			}
			resp := make([]byte, 12)
			binary.BigEndian.PutUint16(resp[0:], id)
			binary.BigEndian.PutUint16(resp[2:], 0x8500)
			binary.BigEndian.PutUint16(resp[6:], 1)
			resp = append(resp, q[12:12+34]...)
			resp = binary.BigEndian.AppendUint16(resp, 0x20)
			resp = binary.BigEndian.AppendUint16(resp, 1)
			resp = binary.BigEndian.AppendUint32(resp, 300)
			resp = binary.BigEndian.AppendUint16(resp, 6)
			resp = binary.BigEndian.AppendUint16(resp, 0)
			a4 := ip.As4()
			resp = append(resp, a4[:]...)
			pc.WriteTo(resp, src)
		}
	}()
	return netip.MustParseAddrPort(pc.LocalAddr().String())
}

func TestNBNSExchange(t *testing.T) {
	want := netip.MustParseAddr("192.168.77.1")
	target := nbnsResponder(t, "QA-NBONLY", want)
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	any := func(netip.Addr) bool { return true }
	got, err := nbnsExchange(ctx, pc, target, "QA-NBONLY", any)
	if err != nil || got != want {
		t.Fatalf("got %s %v", got, err)
	}
	// Nobody answers another name: the exchange ends at the deadline.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel2()
	if _, err := nbnsExchange(ctx2, pc, target, "OTHER", any); err == nil {
		t.Fatal("unknown name resolved")
	}
	// A responder the caller does not accept is ignored.
	ctx3, cancel3 := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel3()
	if _, err := nbnsExchange(ctx3, pc, target, "QA-NBONLY", func(netip.Addr) bool { return false }); err == nil {
		t.Fatal("rejected responder accepted")
	}
}

func TestParseNBNSResponseRejectsNegative(t *testing.T) {
	q := nbnsQueryPacket(42, "HOST")
	neg := append([]byte(nil), q...)
	binary.BigEndian.PutUint16(neg[2:], 0x8503) // NXDOMAIN-style name error
	if _, err := parseNBNSResponse(neg, 42, "HOST"); err == nil {
		t.Fatal("negative response accepted")
	}
	if _, err := parseNBNSResponse(q, 42, "HOST"); err == nil {
		t.Fatal("query accepted as response")
	}
}

func TestMDNSExchange(t *testing.T) {
	want := netip.MustParseAddr("192.168.77.1")
	srv, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, src, err := srv.ReadFrom(buf)
			if err != nil {
				return
			}
			q := new(dns.Msg)
			if q.Unpack(buf[:n]) != nil || len(q.Question) != 1 || q.Question[0].Name != "qa-mdnsonly.local." {
				continue
			}
			// A legacy unicast reply (RFC 6762 6.7): same ID, question echoed.
			r := new(dns.Msg).SetReply(q)
			r.Authoritative = true
			r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "qa-mdnsonly.local.", Rrtype: dns.TypeA, Class: dns.ClassINET | 0x8000, Ttl: 10}, A: want.AsSlice()}}
			b, _ := r.Pack()
			srv.WriteTo(b, src)
		}
	}()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := mdnsExchange(ctx, pc, netip.MustParseAddrPort(srv.LocalAddr().String()), "qa-mdnsonly.local", func(netip.Addr) bool { return true })
	if err != nil || got != want {
		t.Fatalf("got %s %v", got, err)
	}
}

// lanProxyResolver plays the LAN resolver: NXDOMAIN for everything.
type lanProxyResolver struct{ calls *atomic.Int32 }

func (r lanProxyResolver) Resolve(_ context.Context, msg *dns.Msg) (*dns.Msg, error) {
	r.calls.Add(1)
	m := new(dns.Msg)
	m.SetRcode(msg, dns.RcodeNameError)
	return m, nil
}

func newLanFallbackProg(t *testing.T, intercept bool, fb *lanNameFallback) (*prog, *atomic.Int32) {
	t.Helper()
	cfg := &ctrld.Config{Upstream: map[string]*ctrld.UpstreamConfig{}}
	p := &prog{cfg: cfg, um: newUpstreamMonitor(cfg)}
	p.um.after = func(time.Duration, func()) {}
	p.lanLoopGuard = newLoopGuard()
	p.ptrLoopGuard = newLoopGuard()
	p.lanFallback = fb
	t.Cleanup(func() { p.querySampler.closeExpired(time.Now().Add(querySampleWindow)) })
	prev := dnsIntercept
	dnsIntercept = intercept
	t.Cleanup(func() { dnsIntercept = prev })
	var calls atomic.Int32
	origNewResolver, origRecovery := newResolverFn, queryRecoveryFn
	t.Cleanup(func() { newResolverFn, queryRecoveryFn = origNewResolver, origRecovery })
	newResolverFn = func(*ctrld.UpstreamConfig) (ctrld.Resolver, error) { return lanProxyResolver{&calls}, nil }
	queryRecoveryFn = func(*prog, RecoveryReason) {}
	return p, &calls
}

func lanProxyQuery(p *prog, name string, qtype uint16) *dns.Msg {
	msg := new(dns.Msg).SetQuestion(name, qtype)
	return p.proxy(context.Background(), &proxyRequest{msg: msg, ufr: &upstreamForResult{srcAddr: "192.168.77.125:1234"}}).answer
}

// Drive proxy() itself: in Intercept mode, an OS-resolver NXDOMAIN for a LAN
// name becomes the NetBIOS answer; everything else keeps today's answer.
func TestProxyLanNameFallback(t *testing.T) {
	captureDebugMainLog(t)
	ip := netip.MustParseAddr("192.168.77.1")
	f := &fakeLanPlatform{adapters: []lanFallbackAdapter{lanTestAdapter}, nbAddr: ip}

	p, _ := newLanFallbackProg(t, true, newTestFallback(f))
	got := lanProxyQuery(p, "qa-nbonly.lan.", dns.TypeA)
	if got == nil || got.Rcode != dns.RcodeSuccess || len(got.Answer) != 1 || got.Answer[0].(*dns.A).A.String() != "192.168.77.1" {
		t.Fatalf("intercept: got %v", got)
	}
	if got := lanProxyQuery(p, "qa-nbonly.lan.", dns.TypeAAAA); got == nil || got.Rcode != dns.RcodeSuccess || len(got.Answer) != 0 {
		t.Fatalf("intercept AAAA must be NODATA: %v", got)
	}
	// A public-looking name never takes the fallback.
	before := f.nbCalls.Load()
	if got := lanProxyQuery(p, "nope.example.com.", dns.TypeA); got != nil && got.Rcode == dns.RcodeSuccess {
		t.Fatalf("public name answered: %v", got)
	}
	if f.nbCalls.Load() != before {
		t.Fatal("public name was broadcast")
	}

	// Standard mode: Windows still does its own fallback, ctrld does not.
	f2 := &fakeLanPlatform{adapters: []lanFallbackAdapter{lanTestAdapter}, nbAddr: ip}
	p2, _ := newLanFallbackProg(t, false, newTestFallback(f2))
	if got := lanProxyQuery(p2, "qa-nbonly.lan.", dns.TypeA); got == nil || got.Rcode != dns.RcodeNameError {
		t.Fatalf("standard mode must keep NXDOMAIN: %v", got)
	}
	if f2.nbCalls.Load() != 0 {
		t.Fatal("standard mode broadcast")
	}

	// Nobody answers: the NXDOMAIN stands.
	f3 := &fakeLanPlatform{adapters: []lanFallbackAdapter{lanTestAdapter}}
	p3, _ := newLanFallbackProg(t, true, newTestFallback(f3))
	if got := lanProxyQuery(p3, "nobody.lan.", dns.TypeA); got == nil || got.Rcode != dns.RcodeNameError {
		t.Fatalf("miss must keep NXDOMAIN: %v", got)
	}
}
