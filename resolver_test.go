package ctrld

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func Test_osResolver_Resolve(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		defer cancel()
		resolver := &osResolver{}
		resolver.publicServers.Store(&[]string{"127.0.0.127:5353"})
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
		resolver := &osResolver{}
		resolver.publicServers.Store(&[]string{"76.76.2.0:53"})
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
	resolver := &osResolver{}
	// Explicitly store the LAN nameserver.
	resolver.lanServers.Store(&[]string{lanAddr})
	// And store the public nameservers.
	resolver.publicServers.Store(&publicNS)

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
