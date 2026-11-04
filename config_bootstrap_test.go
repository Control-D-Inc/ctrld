package ctrld

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// useBootstrapLookup replaces the bootstrap lookup. system answers lookups
// through the system nameservers, controlD lookups through the Control D
// bootstrap server; the test changes them through the returned pointers.
func useBootstrapLookup(t *testing.T, system, controlD []string) (*[]string, *[]string) {
	t.Helper()
	sys, cd := append([]string{}, system...), append([]string{}, controlD...)
	old := bootstrapLookupFn
	bootstrapLookupFn = func(_ context.Context, domain string, timeout int, nss []string) []string {
		if slices.Equal(nss, []string{net.JoinHostPort(PremiumDNSBoostrapIP, "53")}) {
			return append([]string{}, cd...)
		}
		return append([]string{}, sys...)
	}
	t.Cleanup(func() { bootstrapLookupFn = old })
	return &sys, &cd
}

// useIPv6 pins whether the host has IPv6. HasIPv6 probes once per process, so
// the probe runs first and the pinned value replaces its result.
func useIPv6(t *testing.T, available bool) {
	t.Helper()
	old := HasIPv6(context.Background())
	SetIPv6Available(available)
	t.Cleanup(func() { SetIPv6Available(old) })
}

func newBootstrapTestUpstream(typ, endpoint, ipStack string) *UpstreamConfig {
	uc := &UpstreamConfig{Type: typ, Endpoint: endpoint, Timeout: 1000}
	uc.Init(context.Background())
	uc.IPStack = ipStack
	return uc
}

// Bootstrap results must cover the address families the ip_stack needs (#624).
// A partial lookup is filled in from the Control D direct-IP table and the
// Control D bootstrap server; what is still missing marks the upstream for a
// new lookup instead of becoming a permanently empty transport. An IPv4-only
// host never needs IPv6.
func TestSetupBootstrapIPCompletesPerStack(t *testing.T) {
	const (
		cdEndpoint    = "https://dns.controld.com/abcdef"
		otherEndpoint = "https://dns.example.com/dns-query"
		v4, v6        = "192.0.2.10", "2001:db8::10"
	)
	for _, tc := range []struct {
		name           string
		endpoint       string
		ipStack        string
		ipv6           bool
		system, cdBoot []string
		want4, want6   []string
		wantIncomplete bool
	}{
		{name: "Control D split, AAAA only", endpoint: cdEndpoint, ipStack: IpStackSplit, ipv6: true,
			system: []string{"2606:1a40::99"}, want4: []string{PremiumDNSBoostrapIP}, want6: []string{"2606:1a40::99"}},
		{name: "Control D split, A only", endpoint: cdEndpoint, ipStack: IpStackSplit, ipv6: true,
			system: []string{"76.76.2.99"}, want4: []string{"76.76.2.99"}, want6: []string{PremiumDNSBoostrapIPv6}},
		{name: "Control D split, A only, IPv4-only host", endpoint: cdEndpoint, ipStack: IpStackSplit, ipv6: false,
			system: []string{"76.76.2.99"}, want4: []string{"76.76.2.99"}},
		{name: "Control D split, complete", endpoint: cdEndpoint, ipStack: IpStackSplit, ipv6: true,
			system: []string{"2606:1a40::99", "76.76.2.99"}, want4: []string{"76.76.2.99"}, want6: []string{"2606:1a40::99"}},
		{name: "other v4, AAAA only", endpoint: otherEndpoint, ipStack: IpStackV4, ipv6: true,
			system: []string{v6}, want6: []string{v6}, wantIncomplete: true},
		{name: "other v6, A only", endpoint: otherEndpoint, ipStack: IpStackV6, ipv6: true,
			system: []string{v4}, want4: []string{v4}, wantIncomplete: true},
		{name: "other v4, complete", endpoint: otherEndpoint, ipStack: IpStackV4, ipv6: true,
			system: []string{v4}, want4: []string{v4}},
		{name: "other both, AAAA only", endpoint: otherEndpoint, ipStack: IpStackBoth, ipv6: true,
			system: []string{v6}, want6: []string{v6}},
		{name: "other split, AAAA only, bootstrap server has A", endpoint: otherEndpoint, ipStack: IpStackSplit, ipv6: true,
			system: []string{v6}, cdBoot: []string{v4}, want4: []string{v4}, want6: []string{v6}},
		{name: "other split, AAAA only, nowhere has A", endpoint: otherEndpoint, ipStack: IpStackSplit, ipv6: true,
			system: []string{v6}, want6: []string{v6}, wantIncomplete: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			useIPv6(t, tc.ipv6)
			useBootstrapLookup(t, tc.system, tc.cdBoot)
			uc := newBootstrapTestUpstream(ResolverTypeDOH, tc.endpoint, tc.ipStack)
			uc.SetupBootstrapIP(context.Background())
			if !slices.Equal(uc.bootstrapIPs4, tc.want4) || !slices.Equal(uc.bootstrapIPs6, tc.want6) {
				t.Fatalf("bootstrap IPs = v4 %v, v6 %v; want v4 %v, v6 %v", uc.bootstrapIPs4, uc.bootstrapIPs6, tc.want4, tc.want6)
			}
			if got := uc.bootstrapIncomplete.Load(); got != tc.wantIncomplete {
				t.Fatalf("bootstrapIncomplete = %v, want %v", got, tc.wantIncomplete)
			}
		})
	}
}

// After a partial lookup, the transport recovers once the missing family can
// be resolved again, without a restart: a re-bootstrap looks it up instead of
// rebuilding the transport from the same incomplete lists. Until then a split
// transport borrows the other family rather than staying empty.
func TestReBootstrapRefreshesMissingFamily(t *testing.T) {
	const v4, v6 = "192.0.2.10", "2001:db8::10"
	for _, tc := range []struct {
		name          string
		ipStack       string
		wantInterimA4 []string // addresses A queries dial before recovery
	}{
		{name: "v4", ipStack: IpStackV4, wantInterimA4: nil},
		{name: "split", ipStack: IpStackSplit, wantInterimA4: []string{v6}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			useIPv6(t, true)
			system, _ := useBootstrapLookup(t, []string{v6}, nil)
			uc := newBootstrapTestUpstream(ResolverTypeDOT, "dot.example.com:853", tc.ipStack)
			t.Cleanup(uc.CloseTransports)
			uc.SetupBootstrapIP(context.Background())
			if !uc.bootstrapIncomplete.Load() {
				t.Fatal("an AAAA-only result was accepted as complete")
			}
			if got := uc.dotTransport(context.Background(), dns.TypeA).addrs; !slices.Equal(got, tc.wantInterimA4) {
				t.Fatalf("A-query addresses before recovery = %v, want %v", got, tc.wantInterimA4)
			}

			// DNS is still broken: a re-bootstrap keeps what it has.
			uc.ReBootstrap(context.Background())
			if got := uc.dotTransport(context.Background(), dns.TypeA).addrs; !slices.Equal(got, tc.wantInterimA4) {
				t.Fatalf("A-query addresses while DNS is down = %v, want %v", got, tc.wantInterimA4)
			}

			// DNS is back: the next re-bootstrap picks up the missing family.
			*system = []string{v6, v4}
			uc.ReBootstrap(context.Background())
			if got := uc.dotTransport(context.Background(), dns.TypeA).addrs; !slices.Equal(got, []string{v4}) {
				t.Fatalf("A-query addresses after recovery = %v, want [%s]", got, v4)
			}
			if uc.bootstrapIncomplete.Load() {
				t.Fatal("still incomplete after the missing family was found")
			}
		})
	}
}

// A complete result is not looked up again on every re-bootstrap.
func TestReBootstrapKeepsCompleteResult(t *testing.T) {
	useIPv6(t, true)
	lookups := 0
	old := bootstrapLookupFn
	bootstrapLookupFn = func(context.Context, string, int, []string) []string {
		lookups++
		return []string{"192.0.2.10", "2001:db8::10"}
	}
	t.Cleanup(func() { bootstrapLookupFn = old })
	uc := newBootstrapTestUpstream(ResolverTypeDOT, "dot.example.com:853", IpStackSplit)
	t.Cleanup(uc.CloseTransports)
	uc.SetupBootstrapIP(context.Background())
	before := lookups
	uc.ReBootstrap(context.Background())
	_ = uc.dotTransport(context.Background(), dns.TypeA)
	if lookups != before {
		t.Fatalf("a complete result was looked up again: %d lookups", lookups-before)
	}
}

// useDirectIPs replaces the Control D direct-IP table.
func useDirectIPs(t *testing.T, ips ...string) {
	t.Helper()
	old := controlDDirectIPsFn
	controlDDirectIPsFn = func(string) []string { return append([]string{}, ips...) }
	t.Cleanup(func() { controlDDirectIPsFn = old })
}

// listenLocal listens on ip:port, or on a free port when port is "0", and
// returns the port. It skips the test when ip is not available here.
func listenLocal(t *testing.T, ip, port string) string {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(ip, port))
	if err != nil {
		t.Skipf("cannot listen on %s: %v", ip, err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
}

func dialDOH(t *testing.T, transport *http.Transport, port string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := transport.DialContext(ctx, "tcp", net.JoinHostPort("dns.controld.com", port))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	return host, nil
}

// The DoH direct-IP fallback adds the Control D direct IPs as a backup for
// when the bootstrap addresses are empty or all fail. It never replaces a
// working list, so it is not pinned until restart, and it only dials the
// families the ip_stack dials.
func TestFallbackToDirectIPIsABackup(t *testing.T) {
	t.Run("v6 upstream keeps dialing its IPv6 list after the fallback", func(t *testing.T) {
		port := listenLocal(t, "::1", "0")
		useDirectIPs(t, "127.0.0.1")
		uc := newBootstrapTestUpstream(ResolverTypeDOH, "https://dns.controld.com/abcdef", IpStackV6)
		transport := uc.newDOHTransport(context.Background(), []string{"::1"})
		t.Cleanup(transport.CloseIdleConnections)
		if !uc.FallbackToDirectIP(context.Background()) {
			t.Fatal("FallbackToDirectIP did not fire for a Control D upstream")
		}
		if got, err := dialDOH(t, transport, port); err != nil || got != "::1" {
			t.Fatalf("dialed %q (err %v), want the bootstrap address ::1", got, err)
		}
		if uc.u.Host != "dns.controld.com" {
			t.Fatalf("request host = %q, want the domain kept for TLS", uc.u.Host)
		}
	})

	t.Run("v6 upstream with no addresses only gets IPv6 direct IPs", func(t *testing.T) {
		port := listenLocal(t, "::1", "0")
		useDirectIPs(t, "127.0.0.1", "::1")
		uc := newBootstrapTestUpstream(ResolverTypeDOH, "https://dns.controld.com/abcdef", IpStackV6)
		transport := uc.newDOHTransport(context.Background(), nil)
		t.Cleanup(transport.CloseIdleConnections)
		uc.FallbackToDirectIP(context.Background())
		if got := uc.directFallbackIPs(); !slices.Equal(got, []string{"::1"}) {
			t.Fatalf("direct IPs for a v6 upstream = %v, want only [::1]", got)
		}
		if got, err := dialDOH(t, transport, port); err != nil || got != "::1" {
			t.Fatalf("dialed %q (err %v), want the IPv6 direct IP ::1", got, err)
		}
	})

	t.Run("direct IPs only after the list fails, and the list wins again once reachable", func(t *testing.T) {
		port := listenLocal(t, "127.0.0.1", "0") // the direct IP
		useDirectIPs(t, "127.0.0.1")
		uc := newBootstrapTestUpstream(ResolverTypeDOH, "https://dns.controld.com/abcdef", IpStackSplit)
		transport := uc.newDOHTransport(context.Background(), []string{"::1"}) // nothing listens there yet
		t.Cleanup(transport.CloseIdleConnections)

		if _, err := dialDOH(t, transport, port); err == nil {
			t.Fatal("a failed list was retried on the direct IPs before the fallback fired")
		}
		uc.FallbackToDirectIP(context.Background())
		if got, err := dialDOH(t, transport, port); err != nil || got != "127.0.0.1" {
			t.Fatalf("dialed %q (err %v), want the direct IP after the list failed", got, err)
		}

		// The bootstrap address is reachable again: it is dialed, not the direct IP.
		listenLocal(t, "::1", port)
		if got, err := dialDOH(t, transport, port); err != nil || got != "::1" {
			t.Fatalf("dialed %q (err %v), want the recovered bootstrap address ::1", got, err)
		}
	})
	t.Run("doh3 dials the direct IPs after the list fails", func(t *testing.T) {
		cert := generateTestCertificate(t)
		ln, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
			Certificates: []tls.Certificate{cert.tlsCert},
			NextProtos:   []string{http3.NextProtoH3},
			MinVersion:   tls.VersionTLS13,
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				if _, err := ln.Accept(context.Background()); err != nil {
					return
				}
			}
		}()
		port := strconv.Itoa(ln.Addr().(*net.UDPAddr).Port)
		useDirectIPs(t, "127.0.0.1")
		uc := newBootstrapTestUpstream(ResolverTypeDOH3, "https://dns.controld.com/abcdef", IpStackV4)
		rt := uc.newDOH3Transport(context.Background(), nil).(*http3.Transport)
		t.Cleanup(func() { _ = rt.Close() })

		pool := x509.NewCertPool()
		pool.AddCert(cert.cert)
		tlsCfg := &tls.Config{RootCAs: pool, ServerName: "localhost", NextProtos: []string{http3.NextProtoH3}, MinVersion: tls.VersionTLS13}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		addr := net.JoinHostPort("dns.controld.com", port)

		if _, err := rt.Dial(ctx, addr, tlsCfg, nil); err == nil {
			t.Fatal("dial with no addresses succeeded before the fallback")
		}
		uc.FallbackToDirectIP(context.Background())
		conn, err := rt.Dial(ctx, addr, tlsCfg, nil)
		if err != nil {
			t.Fatalf("doh3 dial after the fallback: %v", err)
		}
		defer conn.CloseWithError(0, "")
		if host, _, _ := net.SplitHostPort(conn.RemoteAddr().String()); host != "127.0.0.1" {
			t.Fatalf("doh3 dialed %q, want the direct IP 127.0.0.1", host)
		}
	})
}

// DoT verifies the server as the upstream domain on every dial path, including
// the empty-address path that dials the endpoint: tls.Client fails every
// handshake without ServerName, and verification must stay on.
func TestDOTClientPoolServerName(t *testing.T) {
	uc := newBootstrapTestUpstream(ResolverTypeDOT, "dot.example.com:853", IpStackBoth)
	p := newDOTClientPool(context.Background(), uc, nil)
	t.Cleanup(p.Close)
	if p.tlsConfig.ServerName != "dot.example.com" {
		t.Fatalf("ServerName = %q, want the upstream domain", p.tlsConfig.ServerName)
	}
	if p.tlsConfig.InsecureSkipVerify {
		t.Fatal("certificate verification is disabled")
	}
}
