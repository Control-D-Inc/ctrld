package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Control-D-Inc/ctrld"
)

// tailscaleDNSConfigFixture is a reduced LocalAPI dns-config response with
// Split DNS zones, App Connector routes, a connector IP literal and the root.
// tail.example is a Split DNS zone on a tailnet resolver, which pf passes only
// in non-exit mode. lan.example and pub.example use resolvers off the tunnel,
// and mixed.example has one of each; pf would redirect those back to ctrld.
const tailscaleDNSConfigFixture = `{
	"Resolvers": [],
	"Routes": {
		"corp.example.":                [],
		"tail.example":                 [{"Addr": "100.64.0.2"}],
		"lan.example":                  [{"Addr": "192.168.1.2"}],
		"pub.example":                  [{"Addr": "8.8.8.8"}],
		"v6.example":                   [{"Addr": "fd7a:115c:a1e0::2"}],
		"mixed.example":                [{"Addr": "100.64.0.2"}, {"Addr": "10.0.0.2"}],
		"doh.example":                  [{"Addr": "https://dns.example/dns-query"}],
		"backend.example.de":           [{"Addr": "http://100.95.61.111:34024/dns-query"}],
		"cd.backend.example.co.jp":     [{"Addr": "http://100.94.53.33:34880/dns-query"}],
		"Queue.RMQ4.Example.com":       [{"Addr": "http://100.94.53.33:34880/dns-query"}],
		"*.wild.example":               [{"Addr": "http://100.1.2.3:1/dns-query"}],
		"46.30.138.82":                 [{"Addr": "http://100.123.219.98:49667/dns-query"}],
		"2001:db8::1":                  [{"Addr": "http://100.123.219.98:49667/dns-query"}],
		".":                            [{"Addr": "1.1.1.1"}],
		"":                             []
	},
	"Domains": ["tailnet.ts.net"]
}`

func TestParseTailscaleRoutes(t *testing.T) {
	got, err := parseTailscaleRoutes([]byte(tailscaleDNSConfigFixture))
	if err != nil {
		t.Fatal(err)
	}
	want := []tailscaleRoute{
		{Domain: "backend.example.de"},
		{Domain: "cd.backend.example.co.jp"},
		{Domain: "corp.example"},
		{Domain: "doh.example"},
		{Domain: "queue.rmq4.example.com"},
		{Domain: "tail.example", NeedsPassthrough: true},
		{Domain: "wild.example"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("parseTailscaleRoutes() = %v, want %v", got, want)
	}

	if _, err := parseTailscaleRoutes([]byte("not json")); err == nil {
		t.Fatal("expected an error for an undecodable body")
	}
}

func TestClassifyTailscaleResolver(t *testing.T) {
	for addr, want := range map[string]tailscaleResolverPath{
		"http://100.95.61.111:34024/dns-query": tailscaleResolverLoopFree,
		"https://dns.example/dns-query":        tailscaleResolverLoopFree,
		"100.64.0.2:5353":                      tailscaleResolverLoopFree,
		"100.64.0.2":                           tailscaleResolverViaPassthrough,
		"100.64.0.2:53":                        tailscaleResolverViaPassthrough,
		"http://100.64.0.2:53/dns-query":       tailscaleResolverViaPassthrough,
		"10.0.0.2":                             tailscaleResolverLoops,
		"8.8.8.8":                              tailscaleResolverLoops,
		"fd7a:115c:a1e0::2":                    tailscaleResolverLoops,
		"[2001:db8::1]:53":                     tailscaleResolverLoops,
		"http://dns.example:53/":               tailscaleResolverLoops,
		"tls://dns.example":                    tailscaleResolverLoops,
		"":                                     tailscaleResolverLoops,
	} {
		if got := classifyTailscaleResolver(addr); got != want {
			t.Errorf("classifyTailscaleResolver(%q) = %d, want %d", addr, got, want)
		}
	}
}

func TestParseTailscaleRoutesCapsAndLogsTruncation(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"Routes":{`)
	for i := 0; i < maxTailscaleRoutes+5; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"r%05d.example":[]`, i)
	}
	b.WriteString(`}}`)
	logs := captureMainLog(t)

	got, err := parseTailscaleRoutes([]byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != maxTailscaleRoutes {
		t.Fatalf("kept %d routes, want %d", len(got), maxTailscaleRoutes)
	}
	if want := fmt.Sprintf("has %d routes; keeping the first %d", maxTailscaleRoutes+5, maxTailscaleRoutes); !strings.Contains(logs.String(), want) {
		t.Fatalf("log does not report the truncation %q: %s", want, logs.String())
	}
}

func TestWithTailscaleRouteDomainsOnlyExtendsTailscaleResolver(t *testing.T) {
	configs := []ctrld.VPNDNSConfig{
		{InterfaceName: "utun4", Servers: []string{"100.100.100.100", "fd7a:115c:a1e0::53"}, Domains: []string{"tailnet.ts.net", "corp.example"}},
		{InterfaceName: "en0", Servers: []string{"192.168.1.1"}, Domains: []string{"lan"}},
	}
	got, added := withTailscaleRouteDomains(configs, []tailscaleRoute{{Domain: "corp.example"}, {Domain: "backend.example.de"}})

	if !added["backend.example.de"] || added["corp.example"] {
		t.Fatalf("added = %v, want only backend.example.de", added)
	}
	if want := []string{"tailnet.ts.net", "corp.example", "backend.example.de"}; !slices.Equal(got[0].Domains, want) {
		t.Fatalf("tailscale domains = %v, want %v", got[0].Domains, want)
	}
	if want := []string{"lan"}; !slices.Equal(got[1].Domains, want) {
		t.Fatalf("non-tailscale domains changed: %v", got[1].Domains)
	}
	if want := []string{"tailnet.ts.net", "corp.example"}; !slices.Equal(configs[0].Domains, want) {
		t.Fatalf("input configs were mutated: %v", configs[0].Domains)
	}
}

func TestVPNDNSRefreshRoutesTailscaleRoutesToQuad100(t *testing.T) {
	m := newVPNDNSManager(&mainLog, nil)
	m.discoverVPNDNS = func(context.Context) []ctrld.VPNDNSConfig {
		return []ctrld.VPNDNSConfig{
			{InterfaceName: "utun4", Servers: []string{"100.100.100.100"}, Domains: []string{"tailnet.ts.net", "lan"}},
			{InterfaceName: "en0", Servers: []string{"192.168.1.248"}, Domains: []string{"lan"}},
		}
	}
	m.discoverTailscaleRoutes = func(context.Context) ([]tailscaleRoute, error) {
		return parseTailscaleRoutes([]byte(tailscaleDNSConfigFixture))
	}

	m.Refresh(context.Background(), true)

	for _, name := range []string{"host.corp.example.", "backend.example.de.", "x.cd.backend.example.co.jp.", "host.tail.example."} {
		if got := m.UpstreamForDomain(name); !slices.Equal(got, []string{"100.100.100.100"}) {
			t.Errorf("UpstreamForDomain(%q) = %v, want quad-100", name, got)
		}
	}
	for _, name := range []string{"example.de.", "other.example.com.", "46.30.138.82.", "host.lan.example.", "host.pub.example.", "host.v6.example.", "host.mixed.example."} {
		if got := m.UpstreamForDomain(name); got != nil {
			t.Errorf("UpstreamForDomain(%q) = %v, want no route", name, got)
		}
	}
	for _, ex := range m.CurrentExemptions() {
		if ex.Server != "100.100.100.100" && ex.Server != "192.168.1.248" {
			t.Errorf("unexpected exemption %+v", ex)
		}
	}
}

func TestVPNDNSRefreshSkipsTailscaleLookupWithoutQuad100(t *testing.T) {
	m := newVPNDNSManager(&mainLog, nil)
	m.discoverVPNDNS = func(context.Context) []ctrld.VPNDNSConfig {
		return []ctrld.VPNDNSConfig{{InterfaceName: "utun5", Servers: []string{"10.8.0.1"}, Domains: []string{"corp.example"}}}
	}
	var calls atomic.Int32
	m.discoverTailscaleRoutes = func(context.Context) ([]tailscaleRoute, error) {
		calls.Add(1)
		return []tailscaleRoute{{Domain: "should.not.appear"}}, nil
	}

	m.Refresh(context.Background(), true)

	if calls.Load() != 0 {
		t.Fatalf("Tailscale LocalAPI queried %d times without a Tailscale resolver", calls.Load())
	}
	if got := m.UpstreamForDomain("x.should.not.appear."); got != nil {
		t.Fatalf("unexpected route %v", got)
	}
}

func TestVPNDNSRefreshKeepsOSRoutesWhenTailscaleUnavailable(t *testing.T) {
	m := newVPNDNSManager(&mainLog, nil)
	m.discoverVPNDNS = func(context.Context) []ctrld.VPNDNSConfig {
		return []ctrld.VPNDNSConfig{{InterfaceName: "utun4", Servers: []string{"100.100.100.100"}, Domains: []string{"tailnet.ts.net"}}}
	}
	m.discoverTailscaleRoutes = func(context.Context) ([]tailscaleRoute, error) {
		return nil, errTailscaleLocalAPIUnavailable
	}
	stubTailscaleRetryDelays(t, time.Hour)
	defer m.Close()

	m.Refresh(context.Background(), true)

	if got := m.Routes(); len(got) != 1 || !slices.Equal(got["tailnet.ts.net"], []string{"100.100.100.100"}) {
		t.Fatalf("routes = %v, want only the OS-discovered tailnet route", got)
	}
}

func TestVPNDNSRefreshPicksUpTailscaleRouteEdits(t *testing.T) {
	m := newVPNDNSManager(&mainLog, nil)
	m.discoverVPNDNS = func(context.Context) []ctrld.VPNDNSConfig {
		return []ctrld.VPNDNSConfig{{InterfaceName: "utun4", Servers: []string{"100.100.100.100"}, Domains: []string{"tailnet.ts.net"}}}
	}
	routes := []tailscaleRoute{{Domain: "corp.example"}}
	m.discoverTailscaleRoutes = func(context.Context) ([]tailscaleRoute, error) {
		return slices.Clone(routes), nil
	}

	m.Refresh(context.Background(), true)
	// A Tailscale reconnect is a tunnel change, which runs a refresh.
	routes = []tailscaleRoute{{Domain: "new.connector.example"}}
	m.Refresh(context.Background(), true)

	if got := m.UpstreamForDomain("api.new.connector.example."); !slices.Equal(got, []string{"100.100.100.100"}) {
		t.Fatalf("new connector route = %v, want quad-100", got)
	}
	if got := m.UpstreamForDomain("host.corp.example."); got != nil {
		t.Fatalf("removed route still present: %v", got)
	}
}

func TestParseMacOSSameUserProofs(t *testing.T) {
	const good = "/Users/u/Library/Group Containers/W5364U7YZB.io.tailscale.ipn.macos/sameuserproof-49152-abcdef0123"
	out := []byte("p123\ncIPNExtension\nn/private/var/folders/x\nn" + good + "\n" +
		// A process whose name only starts with IPNExtension: lsof -c matches it.
		"p200\ncIPNExtensionEvil\nn" + good + "\n" +
		// The right name, but the proof file is outside a group container.
		"p300\ncIPNExtension\nn/tmp/x.tailscale.ipn.macos/sameuserproof-8080-spoof\n" +
		"n/Users/u/Library/Group Containers/io.tailscale.ipn.macos/sameuserproof-notaport-tok\n" +
		"n/Users/u/Library/Group Containers/io.tailscale.ipn.macos/sameuserproof-49152-\n" +
		"n/Users/u/Library/Group Containers/io.tailscale.ipn.macos/nested/sameuserproof-1-tok\n")
	got := parseMacOSSameUserProofs(out)
	want := []macOSSameUserProof{{pid: 123, port: 49152, token: "abcdef0123"}}
	if !slices.Equal(got, want) {
		t.Fatalf("parseMacOSSameUserProofs() = %+v, want %+v", got, want)
	}
}

func TestVPNDNSRefreshSkipsPassthroughRoutesInExitMode(t *testing.T) {
	for _, tc := range []struct {
		name     string
		exitMode bool
		wantTail bool
	}{
		{name: "split", exitMode: false, wantTail: true},
		{name: "exit node", exitMode: true, wantTail: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newVPNDNSManager(&mainLog, nil)
			m.discoverVPNDNS = func(context.Context) []ctrld.VPNDNSConfig {
				return []ctrld.VPNDNSConfig{{InterfaceName: "utun4", Servers: []string{"100.100.100.100"}, Domains: []string{"tailnet.ts.net"}, IsExitMode: tc.exitMode}}
			}
			m.discoverTailscaleRoutes = func(context.Context) ([]tailscaleRoute, error) {
				return parseTailscaleRoutes([]byte(tailscaleDNSConfigFixture))
			}

			m.Refresh(context.Background(), true)

			// A peerAPI DoH connector never crosses pf's port-53 redirect.
			if got := m.UpstreamForDomain("api.backend.example.de."); !slices.Equal(got, []string{"100.100.100.100"}) {
				t.Fatalf("connector route = %v, want quad-100", got)
			}
			got := m.UpstreamForDomain("host.tail.example.")
			if tc.wantTail && !slices.Equal(got, []string{"100.100.100.100"}) {
				t.Fatalf("tailnet Split DNS route = %v, want quad-100", got)
			}
			if !tc.wantTail && got != nil {
				t.Fatalf("tailnet Split DNS route = %v in exit mode, want none (pf has no passthrough)", got)
			}
		})
	}
}

func TestVPNDNSRefreshKeepsLastTailscaleRoutesAndRetries(t *testing.T) {
	stubTailscaleRetryDelays(t, 10*time.Millisecond, 10*time.Millisecond)
	m := newVPNDNSManager(&mainLog, nil)
	defer m.Close()
	m.discoverVPNDNS = func(context.Context) []ctrld.VPNDNSConfig {
		return []ctrld.VPNDNSConfig{{InterfaceName: "utun4", Servers: []string{"100.100.100.100"}, Domains: []string{"tailnet.ts.net"}}}
	}
	var mu sync.Mutex
	results := []error{nil, errors.New("503 no netmap"), nil}
	served := []tailscaleRoute{{Domain: "old.example"}}
	var calls atomic.Int32
	m.discoverTailscaleRoutes = func(context.Context) ([]tailscaleRoute, error) {
		mu.Lock()
		defer mu.Unlock()
		i := int(calls.Add(1)) - 1
		if i < len(results) && results[i] != nil {
			return nil, results[i]
		}
		return slices.Clone(served), nil
	}

	m.Refresh(context.Background(), true)
	mu.Lock()
	served = []tailscaleRoute{{Domain: "new.example"}}
	mu.Unlock()
	// This refresh fails: the last good routes stay.
	m.Refresh(context.Background(), true)
	if got := m.UpstreamForDomain("host.old.example."); !slices.Equal(got, []string{"100.100.100.100"}) {
		t.Fatalf("last good route = %v after a failed read, want quad-100", got)
	}

	// The retry reads again and replaces the set.
	deadline := time.Now().Add(5 * time.Second)
	for m.UpstreamForDomain("host.new.example.") == nil {
		if time.Now().After(deadline) {
			t.Fatalf("retry did not refresh the routes; %d LocalAPI calls", calls.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := m.UpstreamForDomain("host.old.example."); got != nil {
		t.Fatalf("replaced route still present: %v", got)
	}
	// A successful read stops the retries.
	time.Sleep(50 * time.Millisecond)
	if got := calls.Load(); got != 3 {
		t.Fatalf("LocalAPI calls = %d, want 3 (no retry after success)", got)
	}
}

func TestVPNDNSTailscaleRetriesAreBounded(t *testing.T) {
	stubTailscaleRetryDelays(t, time.Millisecond, time.Millisecond, time.Millisecond)
	m := newVPNDNSManager(&mainLog, nil)
	defer m.Close()
	m.discoverVPNDNS = func(context.Context) []ctrld.VPNDNSConfig {
		return []ctrld.VPNDNSConfig{{InterfaceName: "utun4", Servers: []string{"100.100.100.100"}}}
	}
	var calls atomic.Int32
	m.discoverTailscaleRoutes = func(context.Context) ([]tailscaleRoute, error) {
		calls.Add(1)
		return nil, errTailscaleLocalAPIUnavailable
	}

	m.Refresh(context.Background(), true)
	time.Sleep(200 * time.Millisecond)

	// One read on the refresh, then one per retry delay, then nothing.
	if got := calls.Load(); got != 4 {
		t.Fatalf("LocalAPI calls = %d, want 4", got)
	}
}

func TestVPNDNSTailscaleRoutesDroppedWithoutQuad100(t *testing.T) {
	m := newVPNDNSManager(&mainLog, nil)
	withTS := true
	m.discoverVPNDNS = func(context.Context) []ctrld.VPNDNSConfig {
		if withTS {
			return []ctrld.VPNDNSConfig{{InterfaceName: "utun4", Servers: []string{"100.100.100.100"}}}
		}
		return nil
	}
	m.discoverTailscaleRoutes = func(context.Context) ([]tailscaleRoute, error) {
		return []tailscaleRoute{{Domain: "old.example"}}, nil
	}
	m.Refresh(context.Background(), true)
	withTS = false
	m.Refresh(context.Background(), false)
	if m.tailscale.last != nil {
		t.Fatalf("last Tailscale routes kept without quad-100: %v", m.tailscale.last)
	}
}

func TestRetryVPNDNSRefreshUsesNetworkActivityGate(t *testing.T) {
	m := newVPNDNSManager(&mainLog, nil)
	var calls atomic.Int32
	m.discoverVPNDNS = func(context.Context) []ctrld.VPNDNSConfig {
		calls.Add(1)
		return nil
	}
	p := &prog{vpnDNS: m}
	retry := p.retryVPNDNSRefresh(m)

	retry()
	if got := calls.Load(); got != 1 {
		t.Fatalf("refreshes = %d for the live manager, want 1", got)
	}

	p.vpnDNS = newVPNDNSManager(&mainLog, nil)
	retry()
	if got := calls.Load(); got != 1 {
		t.Fatalf("retry of a replaced manager refreshed it (%d refreshes)", got)
	}

	p.vpnDNS = m
	p.closeNetMonitor()
	retry()
	if got := calls.Load(); got != 1 {
		t.Fatalf("retry refreshed after shutdown (%d refreshes)", got)
	}
}

func stubTailscaleRetryDelays(t *testing.T, delays ...time.Duration) {
	t.Helper()
	old := tailscaleRouteRetryDelays
	tailscaleRouteRetryDelays = delays
	t.Cleanup(func() { tailscaleRouteRetryDelays = old })
}

func TestDiscoverTailscaleRoutesFromLocalAPI(t *testing.T) {
	const token = "s3cret-token"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != tailscaleDNSConfigPath || r.Host != tailscaleLocalAPIHost {
			http.NotFound(w, r)
			return
		}
		if _, pass, ok := r.BasicAuth(); !ok || pass != token {
			http.Error(w, "auth required", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(tailscaleDNSConfigFixture))
	}))
	defer srv.Close()
	dial := func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", srv.Listener.Addr().String())
	}

	got, err := discoverTailscaleRoutesFrom(context.Background(), []tailscaleLocalAPIEndpoint{
		{name: "stale", dial: func(context.Context) (net.Conn, error) { return nil, errors.New("connection refused") }},
		{name: "wrong-token", dial: dial, token: "nope"},
		{name: "good", dial: dial, token: token},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(got, tailscaleRoute{Domain: "corp.example"}) || !slices.Contains(got, tailscaleRoute{Domain: "backend.example.de"}) {
		t.Fatalf("routes = %v", got)
	}

	_, err = discoverTailscaleRoutesFrom(context.Background(), []tailscaleLocalAPIEndpoint{{name: "wrong-token", dial: dial, token: "nope"}})
	if err == nil {
		t.Fatal("expected an error for a rejected token")
	}
	if strings.Contains(err.Error(), "nope") || strings.Contains(err.Error(), token) {
		t.Fatalf("error leaks the token: %v", err)
	}

	if _, err := discoverTailscaleRoutesFrom(context.Background(), nil); !errors.Is(err, errTailscaleLocalAPIUnavailable) {
		t.Fatalf("err = %v, want errTailscaleLocalAPIUnavailable", err)
	}
}
