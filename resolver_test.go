package ctrld

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func Test_osResolver_Resolve(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		defer cancel()
		resolver := newResolverWithNameserver([]string{"127.0.0.127:5353"})
		m := new(dns.Msg)
		m.SetQuestion("controld.com.", dns.TypeA)
		m.RecursionDesired = true
		_, _ = resolver.Resolve(context.Background(), m)
	}()

	select {
	case <-time.After(10 * time.Second):
		t.Error("os resolver hangs")
	case <-ctx.Done():
	}
}

func Test_osResolver_ResolveLanHostname(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reqId := "req-id"
	ctx = context.WithValue(ctx, ReqIdCtxKey{}, reqId)
	ctx = LanQueryCtx(ctx)

	go func(ctx context.Context) {
		defer cancel()
		id, ok := ctx.Value(ReqIdCtxKey{}).(string)
		if !ok || id != reqId {
			t.Error("missing request id")
			return
		}
		lan, ok := ctx.Value(LanQueryCtxKey{}).(bool)
		if !ok || !lan {
			t.Error("not a LAN query")
			return
		}
		resolver := newResolverWithNameserver([]string{"76.76.2.0:53"})
		m := new(dns.Msg)
		m.SetQuestion("controld.com.", dns.TypeA)
		m.RecursionDesired = true
		_, err := resolver.Resolve(ctx, m)
		if err == nil {
			t.Error("os resolver succeeded unexpectedly")
			return
		}
	}(ctx)

	select {
	case <-time.After(10 * time.Second):
		t.Error("os resolver hangs")
	case <-ctx.Done():
	}
}

func Test_osResolver_ResolveWithNonSuccessAnswer(t *testing.T) {
	// Set up a LAN nameserver that returns a success response.
	lanPC, err := net.ListenPacket("udp", "127.0.0.1:0") // 127.0.0.1 is considered LAN (loopback)
	if err != nil {
		t.Fatalf("failed to listen on LAN address: %v", err)
	}
	lanServer, lanAddr, err := runLocalPacketConnTestServer(t, lanPC, successHandler())
	if err != nil {
		t.Fatalf("failed to run LAN test server: %v", err)
	}
	defer lanServer.Shutdown()

	// Set up two public nameservers that return non-success responses.
	publicHandlers := []dns.Handler{
		nonSuccessHandlerWithRcode(dns.RcodeRefused),
		nonSuccessHandlerWithRcode(dns.RcodeNameError),
	}
	var publicNS []string
	var publicServers []*dns.Server
	for _, handler := range publicHandlers {
		pc, err := net.ListenPacket("udp", ":0")
		if err != nil {
			t.Fatalf("failed to listen on public address: %v", err)
		}
		s, addr, err := runLocalPacketConnTestServer(t, pc, handler)
		if err != nil {
			t.Fatalf("failed to run public test server: %v", err)
		}
		publicNS = append(publicNS, addr)
		publicServers = append(publicServers, s)
	}
	defer func() {
		for _, s := range publicServers {
			s.Shutdown()
		}
	}()

	// We now create an osResolver which has both a LAN and public nameserver.
	nss := []string{lanAddr}
	nss = append(nss, publicNS...)
	resolver := newResolverWithNameserver(nss)

	msg := new(dns.Msg)
	msg.SetQuestion(".", dns.TypeNS)
	answer, err := resolver.Resolve(context.Background(), msg)
	if err != nil {
		t.Fatal(err)
	}

	// Since a LAN nameserver is available and returns a success answer, we expect RcodeSuccess.
	if answer.Rcode != dns.RcodeSuccess {
		t.Errorf("expected a success answer from LAN nameserver (RcodeSuccess) but got: %s", dns.RcodeToString[answer.Rcode])
	}
}

func Test_osResolver_InitializationRace(t *testing.T) {
	var wg sync.WaitGroup
	n := 10
	wg.Add(n)
	for range n {
		go func() {
			defer wg.Done()
			InitializeOsResolver(false)
		}()
	}
	wg.Wait()
}

func Test_osResolver_Singleflight(t *testing.T) {
	lanPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on LAN address: %v", err)
	}
	call := &atomic.Int64{}
	lanServer, lanAddr, err := runLocalPacketConnTestServer(t, lanPC, countHandler(call))
	if err != nil {
		t.Fatalf("failed to run LAN test server: %v", err)
	}
	defer lanServer.Shutdown()

	or := newResolverWithNameserver([]string{lanAddr})
	domain := "controld.com"
	n := 10
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
			m.RecursionDesired = true
			_, err := or.Resolve(context.Background(), m)
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()

	// All above queries should only make 1 call to server.
	if call.Load() != 1 {
		t.Fatalf("expected 1 result from singleflight lookup, got %d", call)
	}
}

func Test_osResolver_HotCache(t *testing.T) {
	lanPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on LAN address: %v", err)
	}
	call := &atomic.Int64{}
	lanServer, lanAddr, err := runLocalPacketConnTestServer(t, lanPC, countHandler(call))
	if err != nil {
		t.Fatalf("failed to run LAN test server: %v", err)
	}
	defer lanServer.Shutdown()

	or := newResolverWithNameserver([]string{lanAddr})
	domain := "controld.com"
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.RecursionDesired = true

	// Make 2 repeated queries to server, should hit hot cache.
	for i := 0; i < 2; i++ {
		if _, err := or.Resolve(context.Background(), m.Copy()); err != nil {
			t.Fatal(err)
		}
	}
	if call.Load() != 1 {
		t.Fatalf("cache not hit, server was called: %d", call.Load())
	}

	timeoutChan := make(chan struct{})
	time.AfterFunc(5*time.Second, func() {
		close(timeoutChan)
	})

	for {
		select {
		case <-timeoutChan:
			t.Fatal("timed out waiting for cache cleaned")
		default:
			count := 0
			or.cache.Range(func(key, value interface{}) bool {
				count++
				return true
			})
			if count != 0 {
				t.Logf("hot cache is not empty: %d elements", count)
				continue
			}
		}
		break
	}

	if _, err := or.Resolve(context.Background(), m.Copy()); err != nil {
		t.Fatal(err)
	}
	if call.Load() != 2 {
		t.Fatal("cache hit unexpectedly")
	}
}

func Test_Edns0_CacheReply(t *testing.T) {
	lanPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on LAN address: %v", err)
	}
	call := &atomic.Int64{}
	lanServer, lanAddr, err := runLocalPacketConnTestServer(t, lanPC, countHandler(call))
	if err != nil {
		t.Fatalf("failed to run LAN test server: %v", err)
	}
	defer lanServer.Shutdown()

	or := newResolverWithNameserver([]string{lanAddr})
	domain := "controld.com"
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.RecursionDesired = true

	do := func() *dns.Msg {
		msg := m.Copy()
		msg.SetEdns0(4096, true)
		cookieOption := new(dns.EDNS0_COOKIE)
		cookieOption.Code = dns.EDNS0COOKIE
		cookieOption.Cookie = generateEdns0ClientCookie()
		msg.IsEdns0().Option = append(msg.IsEdns0().Option, cookieOption)

		answer, err := or.Resolve(context.Background(), msg)
		if err != nil {
			t.Fatal(err)
		}
		return answer
	}
	answer1 := do()
	answer2 := do()
	// Ensure the cache was hit, so we can check that edns0 cookie must be modified.
	if call.Load() != 1 {
		t.Fatalf("cache not hit, server was called: %d", call.Load())
	}
	cookie1 := getEdns0Cookie(answer1.IsEdns0())
	cookie2 := getEdns0Cookie(answer2.IsEdns0())
	if cookie1 == nil || cookie2 == nil {
		t.Fatalf("unexpected nil cookie value (cookie1: %v, cookie2: %v)", cookie1, cookie2)
	}
	if cookie1.Cookie == cookie2.Cookie {
		t.Fatalf("edns0 cookie is not modified: %v", cookie1)
	}
}

// https://github.com/Control-D-Inc/ctrld/issues/255
func Test_legacyResolverWithBigExtraSection(t *testing.T) {
	lanPC, err := net.ListenPacket("udp", "127.0.0.1:0") // 127.0.0.1 is considered LAN (loopback)
	if err != nil {
		t.Fatalf("failed to listen on LAN address: %v", err)
	}
	lanServer, lanAddr, err := runLocalPacketConnTestServer(t, lanPC, bigExtraSectionHandler())
	if err != nil {
		t.Fatalf("failed to run LAN test server: %v", err)
	}
	defer lanServer.Shutdown()

	uc := &UpstreamConfig{
		Name:     "Legacy",
		Type:     ResolverTypeLegacy,
		Endpoint: lanAddr,
	}
	uc.Init()
	r, err := NewResolver(uc)
	if err != nil {
		t.Fatal(err)
	}

	_, err = r.Resolve(context.Background(), uc.VerifyMsg())
	if err != nil {
		t.Fatal(err)
	}
}

func Test_upstreamTypeFromEndpoint(t *testing.T) {
	tests := []struct {
		name         string
		endpoint     string
		resolverType string
	}{
		{"doh", "https://freedns.controld.com/p2", ResolverTypeDOH},
		{"doq", "quic://p2.freedns.controld.com", ResolverTypeDOQ},
		{"dot", "p2.freedns.controld.com", ResolverTypeDOT},
		{"legacy", "8.8.8.8:53", ResolverTypeLegacy},
		{"legacy ipv6", "[2404:6800:4005:809::200e]:53", ResolverTypeLegacy},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if rt := ResolverTypeFromEndpoint(tc.endpoint); rt != tc.resolverType {
				t.Errorf("mismatch, want: %s, got: %s", tc.resolverType, rt)
			}
		})
	}
}

func runLocalPacketConnTestServer(t *testing.T, pc net.PacketConn, handler dns.Handler, opts ...func(*dns.Server)) (*dns.Server, string, error) {
	t.Helper()

	server := &dns.Server{
		PacketConn:   pc,
		ReadTimeout:  time.Hour,
		WriteTimeout: time.Hour,
		Handler:      handler,
	}

	waitLock := sync.Mutex{}
	waitLock.Lock()
	server.NotifyStartedFunc = waitLock.Unlock

	for _, opt := range opts {
		opt(server)
	}

	addr, closer := pc.LocalAddr().String(), pc
	go func() {
		if err := server.ActivateAndServe(); err != nil {
			t.Error(err)
		}
		closer.Close()
	}()

	waitLock.Lock()
	return server, addr, nil
}

func successHandler() dns.HandlerFunc {
	return func(w dns.ResponseWriter, msg *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(msg, dns.RcodeSuccess)
		w.WriteMsg(m)
	}
}

func nonSuccessHandlerWithRcode(rcode int) dns.HandlerFunc {
	return func(w dns.ResponseWriter, msg *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(msg, rcode)
		w.WriteMsg(m)
	}
}

func countHandler(call *atomic.Int64) dns.HandlerFunc {
	return func(w dns.ResponseWriter, msg *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(msg, dns.RcodeSuccess)
		if cookie := getEdns0Cookie(msg.IsEdns0()); cookie != nil {
			if m.IsEdns0() == nil {
				m.SetEdns0(4096, false)
			}
			cookieOption := new(dns.EDNS0_COOKIE)
			cookieOption.Code = dns.EDNS0COOKIE
			cookieOption.Cookie = generateEdns0ServerCookie(cookie.Cookie)
			m.IsEdns0().Option = append(m.IsEdns0().Option, cookieOption)
		}
		w.WriteMsg(m)
		call.Add(1)
	}
}

func mustRR(s string) dns.RR {
	r, err := dns.NewRR(s)
	if err != nil {
		panic(err)
	}
	return r
}

func bigExtraSectionHandler() dns.HandlerFunc {
	return func(w dns.ResponseWriter, msg *dns.Msg) {
		m := &dns.Msg{
			Answer: []dns.RR{
				mustRR(".			7149	IN	NS	m.root-servers.net."),
				mustRR(".			7149	IN	NS	c.root-servers.net."),
				mustRR(".			7149	IN	NS	e.root-servers.net."),
				mustRR(".			7149	IN	NS	j.root-servers.net."),
				mustRR(".			7149	IN	NS	g.root-servers.net."),
				mustRR(".			7149	IN	NS	k.root-servers.net."),
				mustRR(".			7149	IN	NS	l.root-servers.net."),
				mustRR(".			7149	IN	NS	d.root-servers.net."),
				mustRR(".			7149	IN	NS	h.root-servers.net."),
				mustRR(".			7149	IN	NS	b.root-servers.net."),
				mustRR(".			7149	IN	NS	a.root-servers.net."),
				mustRR(".			7149	IN	NS	f.root-servers.net."),
				mustRR(".			7149	IN	NS	i.root-servers.net."),
			},
			Extra: []dns.RR{
				mustRR("m.root-servers.net.	656	IN	A	202.12.27.33"),
				mustRR("m.root-servers.net.	656	IN	AAAA	2001:dc3::35"),
				mustRR("c.root-servers.net.	656	IN	A	192.33.4.12"),
				mustRR("c.root-servers.net.	656	IN	AAAA	2001:500:2::c"),
				mustRR("e.root-servers.net.	656	IN	A	192.203.230.10"),
				mustRR("e.root-servers.net.	656	IN	AAAA	2001:500:a8::e"),
				mustRR("j.root-servers.net.	656	IN	A	192.58.128.30"),
				mustRR("j.root-servers.net.	656	IN	AAAA	2001:503:c27::2:30"),
				mustRR("g.root-servers.net.	656	IN	A	192.112.36.4"),
				mustRR("g.root-servers.net.	656	IN	AAAA	2001:500:12::d0d"),
				mustRR("k.root-servers.net.	656	IN	A	193.0.14.129"),
				mustRR("k.root-servers.net.	656	IN	AAAA	2001:7fd::1"),
				mustRR("l.root-servers.net.	656	IN	A	199.7.83.42"),
				mustRR("l.root-servers.net.	656	IN	AAAA	2001:500:9f::42"),
				mustRR("d.root-servers.net.	656	IN	A	199.7.91.13"),
				mustRR("d.root-servers.net.	656	IN	AAAA	2001:500:2d::d"),
				mustRR("h.root-servers.net.	656	IN	A	198.97.190.53"),
				mustRR("h.root-servers.net.	656	IN	AAAA	2001:500:1::53"),
				mustRR("b.root-servers.net.	656	IN	A	170.247.170.2"),
				mustRR("b.root-servers.net.	656	IN	AAAA	2801:1b8:10::b"),
				mustRR("a.root-servers.net.	656	IN	A	198.41.0.4"),
				mustRR("a.root-servers.net.	656	IN	AAAA	2001:503:ba3e::2:30"),
				mustRR("f.root-servers.net.	656	IN	A	192.5.5.241"),
				mustRR("f.root-servers.net.	656	IN	AAAA	2001:500:2f::f"),
				mustRR("i.root-servers.net.	656	IN	A	192.36.148.17"),
				mustRR("i.root-servers.net.	656	IN	AAAA	2001:7fe::53"),
			},
		}

		m.Compress = true
		m.SetReply(msg)
		w.WriteMsg(m)
	}
}

func generateEdns0ClientCookie() string {
	cookie := make([]byte, 8)
	if _, err := rand.Read(cookie); err != nil {
		panic(err)
	}
	return hex.EncodeToString(cookie)
}

func generateEdns0ServerCookie(clientCookie string) string {
	cookie := make([]byte, 32)
	if _, err := rand.Read(cookie); err != nil {
		panic(err)
	}
	return clientCookie + hex.EncodeToString(cookie)
}
