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
		resolver.publicServer.Store(&[]string{"127.0.0.127:5353"})
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

func Test_osResolver_ResolveWithNonSuccessAnswer(t *testing.T) {
	ns := make([]string, 0, 2)
	servers := make([]*dns.Server, 0, 2)
	successHandler := dns.HandlerFunc(func(w dns.ResponseWriter, msg *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(msg, dns.RcodeSuccess)
		w.WriteMsg(m)
	})
	nonSuccessHandlerWithRcode := func(rcode int) dns.HandlerFunc {
		return dns.HandlerFunc(func(w dns.ResponseWriter, msg *dns.Msg) {
			m := new(dns.Msg)
			m.SetRcode(msg, rcode)
			w.WriteMsg(m)
		})
	}

	handlers := []dns.Handler{
		nonSuccessHandlerWithRcode(dns.RcodeRefused),
		nonSuccessHandlerWithRcode(dns.RcodeNameError),
		successHandler,
	}
	for i := range handlers {
		pc, err := net.ListenPacket("udp", ":0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		s, addr, err := runLocalPacketConnTestServer(t, pc, handlers[i])
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		ns = append(ns, addr)
		servers = append(servers, s)
	}
	defer func() {
		for _, server := range servers {
			server.Shutdown()
		}
	}()
	resolver := &osResolver{}
	resolver.publicServer.Store(&ns)
	msg := new(dns.Msg)
	msg.SetQuestion(".", dns.TypeNS)
	answer, err := resolver.Resolve(context.Background(), msg)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Rcode != dns.RcodeSuccess {
		t.Errorf("unexpected return code: %s", dns.RcodeToString[answer.Rcode])
	}
}

func Test_osResolver_InitializationRace(t *testing.T) {
	var wg sync.WaitGroup
	n := 10
	wg.Add(n)
	for range n {
		go func() {
			defer wg.Done()
			InitializeOsResolver()
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
