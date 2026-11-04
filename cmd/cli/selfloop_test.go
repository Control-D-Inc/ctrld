package cli

import (
	"context"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
)

// countingSemaphore is the production semaphore with a high-water mark, so a
// test can see how many listener slots one lookup holds at once.
type countingSemaphore struct {
	ready chan struct{}
	held  atomic.Int32
	peak  atomic.Int32
}

func (c *countingSemaphore) acquire() {
	c.ready <- struct{}{}
	n := c.held.Add(1)
	for {
		p := c.peak.Load()
		if n <= p || c.peak.CompareAndSwap(p, n) {
			return
		}
	}
}

func (c *countingSemaphore) release() {
	c.held.Add(-1)
	<-c.ready
}

// startSelfLoopListener runs the production listener on a free loopback port.
// The Internal Domain's resolver is that same listener, which is what a broken
// intercept exemption amounts to: every query ctrld sends to the resolver is
// delivered back to its own listener.
func startSelfLoopListener(t *testing.T, mode string) (*prog, string, *countingSemaphore, *dnsFixture) {
	return startSelfLoopListenerVia(t, mode, nil)
}

// startSelfLoopListenerVia is startSelfLoopListener with the Internal
// Domain's resolver set to resolverFor(listenAddr) instead of the listener.
func startSelfLoopListenerVia(t *testing.T, mode string, resolverFor func(listenAddr string) string) (*prog, string, *countingSemaphore, *dnsFixture) {
	t.Helper()
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.LocalAddr().(*net.UDPAddr).Port
	_ = ln.Close()
	listenAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	resolver := listenAddr
	if resolverFor != nil {
		resolver = resolverFor(listenAddr)
	}

	network := startRcodeDNSFixture(t, dns.RcodeNameError, false)
	useOSResolverFixture(t, network)

	cfg := internalDomainsTestConfig()
	cfg.Listener["0"].IP = "127.0.0.1"
	cfg.Listener["0"].Port = port
	applyInternalDomains(cfg, []controld.SplitDNS{{Domain: "corp.example", Mode: mode, Resolvers: []string{resolver}}})
	// Keep the test inside the Internal Domain path: the generated upstream's
	// timeout is what a looping query would otherwise wait for.
	for _, uc := range cfg.Upstream {
		if isGeneratedInternalDomainUpstream(uc) {
			uc.Timeout = 3000
		}
	}
	for _, uc := range cfg.Upstream {
		uc.Init(context.Background())
	}

	p := newInternalDomainsProg(t, cfg)
	// What the loop check at startup leaves behind: every LAN upstream is
	// managed and not looping.
	p.loop = make(map[string]bool)
	for _, uc := range cfg.Upstream {
		if canBeLocalUpstream(uc.Domain) {
			p.loop[uc.UID()] = false
		}
	}
	p.stopCh = make(chan struct{})
	p.runAbortCh = make(chan struct{})
	p.started = make(chan struct{}, 2)
	p.health = newQueryHealth()
	p.appCallback = &AppCallback{HostName: func() string { return "test" }, LanIp: func() string { return "127.0.0.1" }, MacAddress: func() string { return "" }}
	sema := &countingSemaphore{ready: make(chan struct{}, defaultSemaphoreCap)}
	p.sema = sema
	p.netMonitorClosed = true // no API fetch from the query path

	done := make(chan error, 1)
	go func() { done <- p.serveDNS(context.Background(), "0") }()
	for i := 0; i < 2; i++ {
		select {
		case <-p.started:
		case err := <-done:
			t.Fatalf("listener did not start: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("listener did not start")
		}
	}
	t.Cleanup(func() {
		close(p.stopCh)
		<-done
	})
	return p, listenAddr, sema, network
}

// captureSelfLoopLog points mainLog at a fresh JSON logger for the test,
// stubs the host context, and returns the log sink. The shared logOutput cannot be used: another test in the
// binary can swap mainLog for a console logger (Windows CI shows this), and
// the report is asserted field by field.
func captureSelfLoopLog(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	prev := mainLog.Load()
	mainLog.Store(newTestJSONLogger(buf))
	// The real host reads take seconds on a macOS runner; these tests assert
	// the report, and host_context_test.go covers the parsers.
	stub := func(e *ctrld.LogEvent) { e.Str("host_context", "stub") }
	prevContext := selfLoopHostContextFn.Swap(&stub)
	t.Cleanup(func() {
		selfLoopHostContextFn.Store(prevContext)
		// Let a report goroutine finish before the logger goes back.
		time.Sleep(50 * time.Millisecond)
		mainLog.Store(prev)
	})
	return buf
}

func selfLoopEvents(t *testing.T, out string) []map[string]any {
	t.Helper()
	var events []map[string]any
	for _, line := range strings.Split(out, "\n") {
		var e map[string]any
		if json.Unmarshal([]byte(line), &e) != nil {
			continue
		}
		if msg, _ := e["message"].(string); strings.HasPrefix(msg, "DNS self loop:") {
			events = append(events, e)
		}
	}
	return events
}

// A query that ctrld forwards to its own listener ends at once, holds one
// listener slot, falls back to the network, and is reported once.
func TestSelfLoopEndsAtFirstReturn(t *testing.T) {
	runSelfLoopBurst(t, nil)
}

// A network extension that takes over ctrld's socket re-sends the query from
// a socket of its own. The copy that reaches the listener keeps the DNS
// message but not ctrld's source port, which is what the customer log shows
// (copies from ports ctrld never sent from). This relay does the same.
func TestSelfLoopEndsAtFirstReturnViaRelay(t *testing.T) {
	runSelfLoopBurst(t, func(listenAddr string) string { return startSelfLoopRelay(t, listenAddr) })
}

// startSelfLoopRelay forwards every query it receives to target from a new
// socket per query, and relays the answer back.
func startSelfLoopRelay(t *testing.T, target string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, m *dns.Msg) {
		answer, _, err := (&dns.Client{Net: "udp", Timeout: 5 * time.Second}).Exchange(m, target)
		if err != nil || answer == nil {
			return
		}
		_ = w.WriteMsg(answer)
	})}
	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }
	go func() { _ = server.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = server.Shutdown() })
	return pc.LocalAddr().String()
}

const selfLoopClientID = 0x5a5a

func runSelfLoopBurst(t *testing.T, resolverFor func(string) string) {
	t.Helper()
	for _, mode := range []string{controld.SplitDNSModeResolvers, controld.SplitDNSModeResolversOnly} {
		t.Run(mode, func(t *testing.T) {
			logs := captureSelfLoopLog(t)
			p, listenAddr, sema, network := startSelfLoopListenerVia(t, mode, resolverFor)

			const lookups = 20
			var wg sync.WaitGroup
			rcodes := make([]int, lookups)
			errs := make([]error, lookups)
			start := time.Now()
			for i := 0; i < lookups; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					m := new(dns.Msg)
					m.SetQuestion("host.corp.example.", dns.TypeA)
					// One ID for every client. ctrld never forwards under the
					// client's own ID, so no forward can collide with a client
					// here; with random client IDs one in a few hundred bursts
					// would, and that client would rightly get REFUSED.
					m.Id = selfLoopClientID
					answer, _, err := (&dns.Client{Net: "udp", Timeout: 10 * time.Second}).Exchange(m, listenAddr)
					errs[i] = err
					if answer != nil {
						rcodes[i] = answer.Rcode
					}
				}(i)
			}
			wg.Wait()
			elapsed := time.Since(start)

			for i, err := range errs {
				if err != nil {
					t.Fatalf("lookup %d: %v", i, err)
				}
			}
			// The resolver's 3 s timeout is what each looping step would wait for
			// before the fix; a loop that ends at its first return takes nowhere near it.
			if elapsed > 2*time.Second {
				t.Errorf("%d lookups took %s; a self loop must end at its first return, not at the resolver timeout", lookups, elapsed)
			}
			if peak := sema.peak.Load(); peak > lookups {
				t.Errorf("listener slots peaked at %d for %d lookups; returned queries must not hold slots", peak, lookups)
			}
			wantRcode := dns.RcodeNameError // the network fixture's answer
			if mode == controld.SplitDNSModeResolversOnly {
				wantRcode = dns.RcodeServerFailure
			}
			for i, rc := range rcodes {
				if rc != wantRcode {
					t.Errorf("lookup %d rcode = %s, want %s", i, dns.RcodeToString[rc], dns.RcodeToString[wantRcode])
				}
			}
			if mode == controld.SplitDNSModeResolvers && len(network.questions()) == 0 {
				t.Error("fallback mode did not ask the network after the self loop")
			}
			if mode == controld.SplitDNSModeResolversOnly && len(network.questions()) != 0 {
				t.Errorf("explicit-only mode asked the network: %v", network.questions())
			}

			time.Sleep(200 * time.Millisecond) // the report is logged off the query path
			out := logs.String()
			events := selfLoopEvents(t, out)
			if len(events) != 1 {
				t.Fatalf("self loop reports = %d, want exactly 1 for one burst:\n%v", len(events), events)
			}
			e := events[0]
			if e["level"] != "warn" || e[ctrld.JournalField] != true || e["first"] != true {
				t.Errorf("report is not a journaled first warning: %v", e)
			}
			if !strings.Contains(e["paths"].(string), ctrld.SelfQueryKindLegacy+"=") {
				t.Errorf("report does not name the legacy path: %v", e)
			}
			if !strings.Contains(e["upstreams"].(string), "upstream.internal_0=") {
				t.Errorf("report does not name the looping upstream: %v", e)
			}
			if e["host_context"] != "stub" {
				t.Errorf("report lacks the host context: %v", e)
			}
			if _, ok := e["self_queries_local_port_zero"]; !ok {
				t.Errorf("report lacks the local port counters: %v", e)
			}
			for _, forbidden := range []string{"corp.example", listenAddr} {
				if strings.Contains(e["paths"].(string)+e["upstreams"].(string), forbidden) {
					t.Errorf("report leaks %q: %v", forbidden, e)
				}
			}
			for _, line := range strings.Split(out, "\n") {
				if strings.Contains(line, "DNS self loop suspected") && !strings.Contains(line, `"level":"info"`) {
					t.Errorf("a suspected self loop must stay at info: %s", line)
				}
			}
			// The listener marked the upstream, so the next lookup skips it at once.
			if !p.isLoop(p.cfg.Upstream["internal_0"]) {
				t.Error("the looping upstream was not marked")
			}
		})
	}
}

// An unrelated client query whose source port, ID and question happen to
// match a waiting outbound query is not a self loop unless it comes from this
// host.
func TestSelfQueryMatchRequiresLocalSource(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("x.example.", dns.TypeA)
	if _, ok := ctrld.MatchSelfQuery(&net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 5353}, m); ok {
		t.Fatal("matched a query with no outbound counterpart")
	}
}

// The loop check probe that comes back is reported once by the listener, not
// once more per probe as a warning.
func TestSelfLoopLoopCheckIsQuiet(t *testing.T) {
	logs := captureSelfLoopLog(t)
	p, _, _, _ := startSelfLoopListener(t, controld.SplitDNSModeResolvers)
	p.um = newUpstreamMonitor(p.cfg, p.logger.Load())
	p.checkDnsLoop()
	time.Sleep(200 * time.Millisecond)
	out := logs.String()
	if !p.isLoop(p.cfg.Upstream["internal_0"]) {
		t.Fatal("loop check did not mark the returned upstream")
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "Could not send DNS loop check query") && strings.Contains(line, `"level":"warn"`) {
			t.Errorf("returned loop probe logged a warning: %s", line)
		}
	}
	if n := len(selfLoopEvents(t, out)); n != 1 {
		t.Errorf("self loop reports = %d, want 1", n)
	}
}

func TestSelfLoopReporterRateLimit(t *testing.T) {
	var r selfLoopReporter
	t0 := time.Unix(1000, 0)
	rep, ok := r.note(t0, "legacy", "upstream.internal_0")
	if !ok || !rep.first || rep.count != 1 {
		t.Fatalf("first = %+v %v", rep, ok)
	}
	for i := 0; i < 99; i++ {
		if _, ok := r.note(t0.Add(time.Second), "os_resolver", ""); ok {
			t.Fatal("reported inside the interval")
		}
	}
	rep, ok = r.note(t0.Add(selfLoopReportInterval), "legacy", "upstream.internal_0")
	if !ok || rep.first || rep.count != 100 || rep.total != 101 || rep.paths["os_resolver"] != 99 || rep.paths["legacy"] != 1 {
		t.Fatalf("second = %+v %v", rep, ok)
	}
}

// An upstream the loop check does not manage is never reset by it, so the
// listener must not mark it: the mark would last until restart.
func TestSelfLoopDoesNotMarkUnmanagedUpstream(t *testing.T) {
	p, _, _, _ := startSelfLoopListener(t, controld.SplitDNSModeResolvers)
	uc := p.cfg.Upstream["internal_0"]
	p.loopMu.Lock()
	delete(p.loop, uc.UID())
	p.loopMu.Unlock()
	if got := p.markUpstreamLoop(uc.UID()); got != "upstream.internal_0" {
		t.Fatalf("markUpstreamLoop returned %q", got)
	}
	if p.isLoop(uc) {
		t.Fatal("an upstream the loop check does not manage was marked looping")
	}
	p.loopMu.Lock()
	_, present := p.loop[uc.UID()]
	p.loopMu.Unlock()
	if present {
		t.Fatal("markUpstreamLoop added an unmanaged upstream to the loop map")
	}
}
