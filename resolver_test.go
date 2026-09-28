package ctrld

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
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

func Test_customDNSExchangeWith_RetriesUnboundOnUnreachableSource(t *testing.T) {
	tests := []struct {
		name    string
		boundIP net.IP
		server  string
		errno   syscall.Errno
	}{
		{"ipv4 network unreachable", net.ParseIP("192.0.2.10"), "192.0.2.53:53", syscall.ENETUNREACH},
		{"ipv4 host unreachable", net.ParseIP("192.0.2.10"), "192.0.2.53:53", syscall.EHOSTUNREACH},
		{"ipv6 network unreachable", net.ParseIP("2001:db8::10"), "[2001:db8::53]:53", syscall.ENETUNREACH},
		{"ipv6 host unreachable", net.ParseIP("2001:db8::10"), "[2001:db8::53]:53", syscall.EHOSTUNREACH},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := new(dns.Msg)
			msg.SetQuestion("internal.example.", dns.TypeA)
			var localIPs []net.IP
			var servers []string
			exchange := func(_ context.Context, msg *dns.Msg, server string, localIP net.IP) (*dns.Msg, time.Duration, error) {
				localIPs = append(localIPs, append(net.IP(nil), localIP...))
				servers = append(servers, server)
				if localIP != nil {
					return nil, 0, &net.OpError{Op: "write", Net: "udp", Err: &os.SyscallError{Syscall: "write", Err: tt.errno}}
				}
				answer := new(dns.Msg)
				answer.SetReply(msg)
				return answer, time.Millisecond, nil
			}

			answer, _, err := customDNSExchangeWith(context.Background(), msg, tt.server, tt.boundIP, true, exchange)
			if err != nil {
				t.Fatal(err)
			}
			if answer == nil {
				t.Fatal("expected answer from route-selected retry")
			}
			if len(localIPs) != 2 {
				t.Fatalf("exchange calls: got %d, want 2", len(localIPs))
			}
			if !localIPs[0].Equal(tt.boundIP) {
				t.Fatalf("first source: got %v, want %v", localIPs[0], tt.boundIP)
			}
			if localIPs[1] != nil {
				t.Fatalf("retry source: got %v, want route-selected nil", localIPs[1])
			}
			if len(servers) != 2 || servers[0] != tt.server || servers[1] != tt.server {
				t.Fatalf("exchange servers: got %v, want two attempts to %s", servers, tt.server)
			}
		})
	}
}

func Test_customDNSExchangeWith_PreservesReachableBoundSource(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("internal.example.", dns.TypeA)
	boundIP := net.ParseIP("192.0.2.10")
	calls := 0
	exchange := func(_ context.Context, msg *dns.Msg, _ string, localIP net.IP) (*dns.Msg, time.Duration, error) {
		calls++
		if !localIP.Equal(boundIP) {
			t.Fatalf("source: got %v, want %v", localIP, boundIP)
		}
		answer := new(dns.Msg)
		answer.SetReply(msg)
		return answer, time.Millisecond, nil
	}

	answer, _, err := customDNSExchangeWith(context.Background(), msg, "192.0.2.53:53", boundIP, true, exchange)
	if err != nil {
		t.Fatal(err)
	}
	if answer == nil {
		t.Fatal("expected answer from bound exchange")
	}
	if calls != 1 {
		t.Fatalf("exchange calls: got %d, want 1", calls)
	}
}

func Test_customDNSExchangeWith_DoesNotRetryOtherFailures(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("internal.example.", dns.TypeA)
	calls := 0
	exchange := func(_ context.Context, _ *dns.Msg, _ string, _ net.IP) (*dns.Msg, time.Duration, error) {
		calls++
		return nil, 0, context.DeadlineExceeded
	}

	_, _, err := customDNSExchangeWith(context.Background(), msg, "192.0.2.53:53", net.ParseIP("192.0.2.10"), true, exchange)
	if err == nil {
		t.Fatal("expected exchange failure")
	}
	if calls != 1 {
		t.Fatalf("exchange calls: got %d, want 1", calls)
	}
}

func Test_customDNSExchangeWith_DoesNotRetryWithoutBoundSource(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("internal.example.", dns.TypeA)
	calls := 0
	exchange := func(_ context.Context, _ *dns.Msg, _ string, _ net.IP) (*dns.Msg, time.Duration, error) {
		calls++
		return nil, 0, &net.OpError{Op: "write", Net: "udp", Err: syscall.EHOSTUNREACH}
	}

	_, _, err := customDNSExchangeWith(context.Background(), msg, "192.0.2.53:53", nil, true, exchange)
	if err == nil {
		t.Fatal("expected exchange failure")
	}
	if calls != 1 {
		t.Fatalf("exchange calls: got %d, want 1", calls)
	}
}

func Test_customDNSExchangeWith_DoesNotRetryCanceledContext(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("internal.example.", dns.TypeA)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	exchange := func(_ context.Context, _ *dns.Msg, _ string, _ net.IP) (*dns.Msg, time.Duration, error) {
		calls++
		return nil, 0, &net.OpError{Op: "write", Net: "udp", Err: syscall.EHOSTUNREACH}
	}

	_, _, err := customDNSExchangeWith(ctx, msg, "192.0.2.53:53", net.ParseIP("192.0.2.10"), true, exchange)
	if err == nil {
		t.Fatal("expected exchange failure")
	}
	if calls != 1 {
		t.Fatalf("exchange calls: got %d, want 1", calls)
	}
}

func Test_customDNSExchangeWith_ReturnsUnboundRetryFailure(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("internal.example.", dns.TypeA)
	retryErr := errors.New("route-selected exchange failed")
	calls := 0
	exchange := func(_ context.Context, _ *dns.Msg, _ string, localIP net.IP) (*dns.Msg, time.Duration, error) {
		calls++
		if localIP != nil {
			return nil, 0, &net.OpError{Op: "write", Net: "udp", Err: syscall.EHOSTUNREACH}
		}
		return nil, 0, retryErr
	}

	_, _, err := customDNSExchangeWith(context.Background(), msg, "192.0.2.53:53", net.ParseIP("192.0.2.10"), true, exchange)
	if !errors.Is(err, retryErr) {
		t.Fatalf("exchange error: got %v, want retry error %v", err, retryErr)
	}
	if calls != 2 {
		t.Fatalf("exchange calls: got %d, want 2", calls)
	}
}

func Test_customDNSExchangeWith_DoesNotRetryReadSideUnreachable(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("internal.example.", dns.TypeA)
	calls := 0
	exchange := func(_ context.Context, _ *dns.Msg, _ string, _ net.IP) (*dns.Msg, time.Duration, error) {
		calls++
		return nil, 0, &net.OpError{Op: "read", Net: "udp", Err: syscall.EHOSTUNREACH}
	}

	_, _, err := customDNSExchangeWith(context.Background(), msg, "192.0.2.53:53", net.ParseIP("192.0.2.10"), true, exchange)
	if err == nil {
		t.Fatal("expected exchange failure")
	}
	if calls != 1 {
		t.Fatalf("exchange calls: got %d, want 1", calls)
	}
}

func Test_osResolver_ResolveUsesRouteSelectedFallbackForLANServer(t *testing.T) {
	const server = "10.0.0.53:53"
	boundIP := net.ParseIP("192.0.2.10")
	resolver := newResolverWithNameserver([]string{server})
	resolver.localIP = func(string) net.IP { return boundIP }

	var localIPs []net.IP
	var servers []string
	resolver.exchangeDNS = func(_ context.Context, msg *dns.Msg, gotServer string, localIP net.IP) (*dns.Msg, time.Duration, error) {
		servers = append(servers, gotServer)
		localIPs = append(localIPs, append(net.IP(nil), localIP...))
		if localIP != nil {
			return nil, 0, &net.OpError{Op: "write", Net: "udp", Err: syscall.EHOSTUNREACH}
		}
		answer := new(dns.Msg)
		answer.SetReply(msg)
		return answer, time.Millisecond, nil
	}

	msg := new(dns.Msg)
	msg.SetQuestion("internal.example.", dns.TypeA)
	answer, err := resolver.Resolve(context.Background(), msg)
	if err != nil {
		t.Fatal(err)
	}
	if answer == nil {
		t.Fatal("expected answer from route-selected retry")
	}
	if len(localIPs) != 2 || !localIPs[0].Equal(boundIP) || localIPs[1] != nil {
		t.Fatalf("exchange sources: got %v, want [%v <nil>]", localIPs, boundIP)
	}
	if len(servers) != 2 || servers[0] != server || servers[1] != server {
		t.Fatalf("exchange servers: got %v, want two attempts to %s", servers, server)
	}
}

// A VPN-pushed public DNS address is categorized as public by IP, but it is
// still a system-selected resolver and must get the same route-compatible retry.
func Test_osResolver_ResolveUsesRouteSelectedFallbackForPublicVPNServer(t *testing.T) {
	const server = "192.0.2.53:53"
	boundIP := net.ParseIP("198.51.100.10")
	resolver := newResolverWithNameserver([]string{server})
	resolver.localIP = func(string) net.IP { return boundIP }

	var localIPs []net.IP
	resolver.exchangeDNS = func(_ context.Context, msg *dns.Msg, _ string, localIP net.IP) (*dns.Msg, time.Duration, error) {
		localIPs = append(localIPs, append(net.IP(nil), localIP...))
		if localIP != nil {
			return nil, 0, &net.OpError{Op: "write", Net: "udp", Err: syscall.EHOSTUNREACH}
		}
		answer := new(dns.Msg)
		answer.SetReply(msg)
		return answer, time.Millisecond, nil
	}

	msg := new(dns.Msg)
	msg.SetQuestion("internal.example.", dns.TypeA)
	answer, err := resolver.Resolve(context.Background(), msg)
	if err != nil {
		t.Fatal(err)
	}
	if answer == nil {
		t.Fatal("expected answer from route-selected retry")
	}
	if len(localIPs) != 2 || !localIPs[0].Equal(boundIP) || localIPs[1] != nil {
		t.Fatalf("exchange sources: got %v, want [%v <nil>]", localIPs, boundIP)
	}
}

func Test_osResolver_ResolveDoesNotRetrySyntheticControlDFallbackUnbound(t *testing.T) {
	resolver := newResolverWithNameserver([]string{controldPublicDnsWithPort})
	resolver.localIP = func(string) net.IP { return net.ParseIP("198.51.100.10") }
	calls := 0
	resolver.exchangeDNS = func(_ context.Context, _ *dns.Msg, _ string, _ net.IP) (*dns.Msg, time.Duration, error) {
		calls++
		return nil, 0, &net.OpError{Op: "write", Net: "udp", Err: syscall.EHOSTUNREACH}
	}

	msg := new(dns.Msg)
	msg.SetQuestion("internal.example.", dns.TypeA)
	_, err := resolver.Resolve(context.Background(), msg)
	if err == nil {
		t.Fatal("expected exchange failure")
	}
	if calls != 1 {
		t.Fatalf("exchange calls: got %d, want one bound synthetic fallback attempt", calls)
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

func TestOSResolverNameserverSetsKeepsSyntheticFallbackOutOfSystemDiscovery(t *testing.T) {
	system := []string{"fe80::1"}
	effective, discovered, skip := osResolverNameserverSets(system, false)
	if skip {
		t.Fatal("non-empty discovery unexpectedly skipped resolver replacement")
	}

	if len(discovered) != 1 || discovered[0] != system[0] {
		t.Fatalf("discovered nameservers = %v, want raw system list %v", discovered, system)
	}
	if len(effective) != 2 || effective[0] != "[fe80::1]:53" || effective[1] != controldPublicDnsWithPort {
		t.Fatalf("effective nameservers = %v, want IPv6 system resolver plus synthetic fallback", effective)
	}
}

func TestOSResolverNameserverSetsHonorsEmptyGuard(t *testing.T) {
	effective, discovered, skip := osResolverNameserverSets(nil, true)
	if len(effective) != 0 || len(discovered) != 0 {
		t.Fatalf("guarded empty discovery returned effective=%v discovered=%v", effective, discovered)
	}
	if !skip {
		t.Fatal("guarded empty discovery did not return the skip decision")
	}
}

func Test_osResolver_InitializationRace(t *testing.T) {
	var wg sync.WaitGroup
	n := 10
	wg.Add(n)
	for range n {
		go func() {
			defer wg.Done()
			InitializeOsResolver(LoggerCtx(context.Background(), nil), false)
		}()
	}
	wg.Wait()
}

func Test_osResolver_Singleflight(t *testing.T) {
	lanPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on LAN address: %v", err)
	}
	defer lanPC.Close()

	call := &atomic.Int64{}
	lanServer, lanAddr, err := runLocalPacketConnTestServer(t, lanPC, countHandler(call))
	if err != nil {
		t.Fatalf("failed to run LAN test server: %v", err)
	}
	defer lanServer.Shutdown()

	or := newResolverWithNameserver([]string{lanAddr})
	domain := "controld.com"
	n := 10

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	errs := make(chan error, n)

	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
			m.RecursionDesired = true
			_, err := or.Resolve(ctx, m)
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)

	// Collect any errors that occurred
	for err := range errs {
		t.Errorf("resolver error: %v", err)
	}

	// All above queries should only make 1 call to server.
	if got := call.Load(); got != 1 {
		t.Fatalf("expected 1 result from singleflight lookup, got %d", got)
	}
}

func Test_osResolver_HotCache(t *testing.T) {
	const (
		testIterations    = 2
		cacheCheckTimeout = 5 * time.Second
		pollInterval      = 10 * time.Millisecond
	)

	// Setup test server
	lanPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on LAN address: %v", err)
	}
	defer lanPC.Close()

	call := &atomic.Int64{}
	lanServer, lanAddr, err := runLocalPacketConnTestServer(t, lanPC, countHandler(call))
	if err != nil {
		t.Fatalf("failed to run LAN test server: %v", err)
	}
	defer lanServer.Shutdown()

	// Initialize resolver
	or := newResolverWithNameserver([]string{lanAddr})
	domain := "controld.com"
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.RecursionDesired = true

	// Setup context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Make repeated queries to server, should hit hot cache
	for i := 0; i < testIterations; i++ {
		resp, err := or.Resolve(ctx, m.Copy())
		if err != nil {
			t.Fatal(err)
		}
		// Verify response content
		if resp.Rcode != dns.RcodeSuccess {
			t.Errorf("expected success response, got %v", resp.Rcode)
		}
	}

	if call.Load() != 1 {
		t.Fatalf("cache not hit, server was called: %d", call.Load())
	}

	// Wait for cache to be cleaned
	timeoutChan := make(chan struct{})
	time.AfterFunc(cacheCheckTimeout, func() {
		close(timeoutChan)
	})

	// Check cache with proper polling interval
waitLoop:
	for {
		select {
		case <-timeoutChan:
			t.Fatal("timed out waiting for cache cleaned")
		case <-time.After(pollInterval):
			count := 0
			or.cache.Range(func(key, value interface{}) bool {
				count++
				return true
			})
			if count == 0 {
				break waitLoop
			}
			t.Logf("hot cache is not empty: %d elements", count)
		}
	}

	// Verify cache miss after cleanup
	resp, err := or.Resolve(ctx, m.Copy())
	if err != nil {
		t.Fatal(err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("expected success response after cache cleanup, got %v", resp.Rcode)
	}
	if call.Load() != 2 {
		t.Fatal("cache hit unexpectedly")
	}
}

func Test_Edns0_CacheReply(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	lanPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on LAN address: %v", err)
	}
	defer lanPC.Close()

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

	do := func() (*dns.Msg, error) {
		msg := m.Copy()
		msg.SetEdns0(4096, true)
		cookieOption := new(dns.EDNS0_COOKIE)
		cookieOption.Code = dns.EDNS0COOKIE
		cookieOption.Cookie = generateEdns0ClientCookie()
		msg.IsEdns0().Option = append(msg.IsEdns0().Option, cookieOption)
		return or.Resolve(ctx, msg)
	}

	answer1, err := do()
	if err != nil {
		t.Fatalf("first resolve failed: %v", err)
	}

	answer2, err := do()
	if err != nil {
		t.Fatalf("second resolve failed: %v", err)
	}

	// Ensure the cache was hit
	if got := call.Load(); got != 1 {
		t.Fatalf("expected 1 server call, got: %d", got)
	}

	cookie1 := getEdns0Cookie(answer1.IsEdns0())
	cookie2 := getEdns0Cookie(answer2.IsEdns0())

	if cookie1 == nil || cookie2 == nil {
		t.Fatalf("unexpected nil cookie (cookie1: %v, cookie2: %v)", cookie1, cookie2)
	}

	if cookie1.Cookie == cookie2.Cookie {
		t.Fatalf("edns0 cookie was not modified (cookie: %v)", cookie1.Cookie)
	}

	// Validate response code
	if answer1.Rcode != dns.RcodeSuccess || answer2.Rcode != dns.RcodeSuccess {
		t.Errorf("expected success response code, got: %v, %v", answer1.Rcode, answer2.Rcode)
	}
}

// ecsAnswerHandler returns a distinct A record per EDNS Client Subnet, so a test can
// prove one subnet never receives another subnet's cached record. It counts upstream
// calls to confirm the hot cache/singleflight is partitioned by ECS rather than shared.
func ecsAnswerHandler(call *atomic.Int64) dns.HandlerFunc {
	return func(w dns.ResponseWriter, msg *dns.Msg) {
		call.Add(1)
		a := "203.0.113.1" // no/other subnet
		if opt := msg.IsEdns0(); opt != nil {
			for _, o := range opt.Option {
				if e, ok := o.(*dns.EDNS0_SUBNET); ok {
					switch {
					case e.Address.Equal(net.ParseIP("2001:db8:1::")):
						a = "192.0.2.1"
					case e.Address.Equal(net.ParseIP("2001:db8:2::")):
						a = "198.51.100.1"
					}
				}
			}
		}
		m := new(dns.Msg)
		m.SetReply(msg)
		rr, _ := dns.NewRR(msg.Question[0].Name + " 300 IN A " + a)
		m.Answer = []dns.RR{rr}
		w.WriteMsg(m)
	}
}

// Test_osResolver_HotCache_ECSPartition is the real cache-path regression test for #564 on
// the osResolver hot cache / singleflight path: the upstream returns a different A record
// per subnet, and a client in subnet B must never be served subnet A's hot-cached record.
func Test_osResolver_HotCache_ECSPartition(t *testing.T) {
	lanPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on LAN address: %v", err)
	}
	call := &atomic.Int64{}
	lanServer, lanAddr, err := runLocalPacketConnTestServer(t, lanPC, ecsAnswerHandler(call))
	if err != nil {
		t.Fatalf("failed to run LAN test server: %v", err)
	}
	defer lanServer.Shutdown()

	or := newResolverWithNameserver([]string{lanAddr})
	query := func(subnet string) string {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn("controld.com"), dns.TypeA)
		m.RecursionDesired = true
		m.SetEdns0(4096, true)
		m.IsEdns0().Option = append(m.IsEdns0().Option, &dns.EDNS0_SUBNET{
			Code:          dns.EDNS0SUBNET,
			Family:        2,
			SourceNetmask: 64,
			Address:       net.ParseIP(subnet),
		})
		answer, err := or.Resolve(context.Background(), m)
		if err != nil {
			t.Fatal(err)
		}
		for _, rr := range answer.Answer {
			if a, ok := rr.(*dns.A); ok {
				return a.A.String()
			}
		}
		return ""
	}

	// Subnet A populates the hot cache; a repeat hits it (upstream called once).
	if got := query("2001:db8:1::"); got != "192.0.2.1" {
		t.Fatalf("subnet A: got %q, want 192.0.2.1", got)
	}
	if got := query("2001:db8:1::"); got != "192.0.2.1" {
		t.Fatalf("subnet A repeat: got %q, want 192.0.2.1", got)
	}
	if call.Load() != 1 {
		t.Fatalf("subnet A repeat did not hit the hot cache: %d upstream calls", call.Load())
	}

	// Subnet B must get ITS OWN record, not subnet A's hot-cached one, and this
	// requires a fresh upstream call (the cache is partitioned, not shared).
	if got := query("2001:db8:2::"); got != "198.51.100.1" {
		t.Fatalf("subnet B was served the wrong record %q (want 198.51.100.1); hot cache is not ECS-partitioned", got)
	}
	if call.Load() != 2 {
		t.Fatalf("subnet B unexpectedly served from subnet A's cache: %d upstream calls, want 2", call.Load())
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
	ctx := context.Background()
	uc.Init(ctx)
	r, err := NewResolver(ctx, uc)
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
		// Count the call before writing the reply. The client returns as soon
		// as it receives the response, so a caller that reads this counter right
		// after Resolve returns would race an increment done after WriteMsg and
		// could observe a stale zero.
		call.Add(1)
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

// syncLogBuffer collects the log lines that any goroutine writes.
type syncLogBuffer struct {
	mu sync.Mutex
	sb strings.Builder
}

func (b *syncLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sb.Write(p)
}

func (b *syncLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sb.String()
}

// captureProxyLog returns a context whose logger writes one JSON object for
// each line into the returned buffer, at debug level. The resolver code logs
// through the logger of its context.
func captureProxyLog(t *testing.T) (context.Context, *syncLogBuffer) {
	t.Helper()
	buf := &syncLogBuffer{}
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "time"
	encoderConfig.LevelKey = "level"
	encoderConfig.EncodeLevel = zapcore.LowercaseLevelEncoder
	encoderConfig.MessageKey = "message"
	core := zapcore.NewCore(zapcore.NewJSONEncoder(encoderConfig), zapcore.AddSync(buf), zapcore.DebugLevel)
	return LoggerCtx(context.Background(), &Logger{Logger: zap.New(core)}), buf
}

// logEventsWithPrefix returns the log events whose message starts with prefix.
func logEventsWithPrefix(t *testing.T, logs, prefix string) []map[string]any {
	t.Helper()
	var events []map[string]any
	for _, line := range strings.Split(logs, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		event := map[string]any{}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("log line is not JSON: %q: %v", line, err)
		}
		message, _ := event["message"].(string)
		if !strings.HasPrefix(message, prefix) {
			continue
		}
		events = append(events, event)
	}
	return events
}

// wantLogField fails the test when an event misses a field or holds another value.
func wantLogField(t *testing.T, event map[string]any, field string, want any) {
	t.Helper()
	got, ok := event[field]
	if !ok {
		t.Fatalf("log event has no field %q: %v", field, event)
	}
	if got != want {
		t.Fatalf("log event field %q = %v, want %v", field, got, want)
	}
}

// wantLogStrings fails the test when a list field does not hold want.
func wantLogStrings(t *testing.T, event map[string]any, field string, want []string) {
	t.Helper()
	values, ok := event[field].([]any)
	if !ok {
		t.Fatalf("log event field %q is not a list: %v", field, event[field])
	}
	got := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok {
			t.Fatalf("log event field %q holds a value that is not a string: %v", field, value)
		}
		got = append(got, text)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("log event field %q = %v, want %v", field, got, want)
	}
}

// stubNameservers answers each system nameserver read from lists, in order.
// The last list answers every read after it.
func stubNameservers(t *testing.T, lists ...[]string) {
	t.Helper()
	previous := NameserversFn
	reads := 0
	NameserversFn = func(context.Context) []string {
		list := lists[min(reads, len(lists)-1)]
		reads++
		return slices.Clone(list)
	}
	t.Cleanup(func() { NameserversFn = previous })
}

// resetOsResolverLog clears the change-only state, so one test does not see
// the nameserver reads of another.
func resetOsResolverLog(t *testing.T) {
	t.Helper()
	reset := func() {
		osResolverLog.mu.Lock()
		defer osResolverLog.mu.Unlock()
		osResolverLog.system = nameserverReads{}
		osResolverLog.final = nameserverReads{}
		osResolverLog.reason = osResolverReasonUnspecified
	}
	reset()
	t.Cleanup(reset)
}

// keepOsResolver puts back the OS resolver that the process had before the test.
func keepOsResolver(t *testing.T) {
	t.Helper()
	resolverMutex.Lock()
	previous := or
	resolverMutex.Unlock()
	t.Cleanup(func() {
		resolverMutex.Lock()
		storeOsResolver(previous)
		resolverMutex.Unlock()
	})
}

// TestOsResolverNameserversReadsWithoutTheResolverLock covers a log header
// render during a resolver initialization. That initialization holds
// resolverMutex across a scutil read of several seconds, and the header must
// not wait for it.
func TestOsResolverNameserversReadsWithoutTheResolverLock(t *testing.T) {
	keepOsResolver(t)
	resolverMutex.Lock()
	storeOsResolver(newResolverWithNameserver([]string{"192.0.2.1:53"}))

	read := make(chan []string, 1)
	go func() { read <- OsResolverNameservers() }()

	select {
	case nameservers := <-read:
		resolverMutex.Unlock()
		if want := []string{"192.0.2.1:53"}; !slices.Equal(nameservers, want) {
			t.Fatalf("nameservers = %v, want %v", nameservers, want)
		}
	case <-time.After(5 * time.Second):
		resolverMutex.Unlock()
		t.Fatal("OsResolverNameservers waited for resolverMutex")
	}
}

func TestJournalMarksTheEventAndKeepsItsLevel(t *testing.T) {
	ctx, logs := captureProxyLog(t)

	Journal(LoggerFromCtx(ctx).Info()).Msg("Journal test event")

	events := logEventsWithPrefix(t, logs.String(), "Journal test event")
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1: %s", len(events), logs.String())
	}
	wantLogField(t, events[0], JournalField, true)
	wantLogField(t, events[0], "level", "info")
}

func TestOsResolverNameserverReadsLogOnChange(t *testing.T) {
	ctx, logs := captureProxyLog(t)
	resetOsResolverLog(t)
	keepOsResolver(t)
	first := []string{"192.0.2.1", "192.0.2.2"}
	second := []string{"192.0.2.3"}
	stubNameservers(t, first, first, second)

	for range 3 {
		InitializeOsResolverWithReason(ctx, false, "transition")
	}

	systemReads := logEventsWithPrefix(t, logs.String(), "Got system nameservers")
	if len(systemReads) != 2 {
		t.Fatalf("got %d system nameserver lines, want 2: %s", len(systemReads), logs.String())
	}
	wantLogField(t, systemReads[0], "repeats", float64(0))
	wantLogField(t, systemReads[1], "repeats", float64(1))
	wantLogField(t, systemReads[1], "message", "Got system nameservers: [192.0.2.3]")

	finalReads := logEventsWithPrefix(t, logs.String(), "Final available nameservers")
	if len(finalReads) != 2 {
		t.Fatalf("got %d final nameserver lines, want 2: %s", len(finalReads), logs.String())
	}
	wantLogField(t, finalReads[1], "repeats", float64(1))

	changes := logEventsWithPrefix(t, logs.String(), "OS resolver set changed")
	if len(changes) != 2 {
		t.Fatalf("got %d resolver change events, want one for each changed list: %s", len(changes), logs.String())
	}
	last := changes[1]
	wantLogStrings(t, last, "before", first)
	wantLogStrings(t, last, "after", second)
	wantLogField(t, last, JournalField, true)
	wantLogField(t, last, "level", "info")
	wantLogField(t, last, "reason", "transition")
	if _, ok := last["default_route"]; !ok {
		t.Fatalf("resolver change event has no default_route field: %v", last)
	}
	wantSource := map[string]string{"darwin": "scutil", "windows": "dhcp", "linux": "resolv.conf"}[runtime.GOOS]
	if wantSource != "" {
		wantLogField(t, last, "source", wantSource)
	}
}

func TestInitializeOsResolverReportsTheUnspecifiedReason(t *testing.T) {
	ctx, logs := captureProxyLog(t)
	resetOsResolverLog(t)
	keepOsResolver(t)
	stubNameservers(t, []string{"192.0.2.10"})

	InitializeOsResolver(ctx, false)

	changes := logEventsWithPrefix(t, logs.String(), "OS resolver set changed")
	if len(changes) != 1 {
		t.Fatalf("got %d resolver change events, want 1: %s", len(changes), logs.String())
	}
	wantLogField(t, changes[0], "reason", "unspecified")
	wantLogStrings(t, changes[0], "after", []string{"192.0.2.10"})
}

// TestOsResolverQueryFailureLogsAtDebug guards the level of the per-query
// failure line. The journal keeps every error line, and a broken network
// fails every query, so this line must not be an error.
func TestOsResolverQueryFailureLogsAtDebug(t *testing.T) {
	ctx, logs := captureProxyLog(t)
	resolver := newResolverWithNameserver([]string{"127.0.0.1:1"})
	resolver.exchangeDNS = func(_ context.Context, _ *dns.Msg, _ string, _ net.IP) (*dns.Msg, time.Duration, error) {
		return nil, 0, errors.New("dial udp: connection refused")
	}
	msg := new(dns.Msg)
	msg.SetQuestion("private.example.", dns.TypeA)

	if _, err := resolver.Resolve(ctx, msg); err == nil {
		t.Fatal("expected the query to fail")
	}

	events := logEventsWithPrefix(t, logs.String(), "OS resolver query failed")
	if len(events) == 0 {
		t.Fatalf("no failure line: %s", logs.String())
	}
	for _, event := range events {
		if event["level"] != "debug" {
			t.Fatalf("failure line at level %v, want debug: %v", event["level"], event)
		}
	}
}
