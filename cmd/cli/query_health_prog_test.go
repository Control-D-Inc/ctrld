package cli

import (
	"context"
	"errors"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/dnscache"
	"github.com/Control-D-Inc/ctrld/testhelper"
)

// wantDNSConfigStrings compares one array field of a logged resolver entry.
func wantDNSConfigStrings(t *testing.T, event map[string]any, field string, want ...string) {
	t.Helper()
	values, ok := event[field].([]any)
	if !ok {
		t.Fatalf("field %q: got %T, want an array", field, event[field])
	}
	if len(values) != len(want) {
		t.Fatalf("field %q: got %v, want %v", field, values, want)
	}
	for i, value := range values {
		if value != want[i] {
			t.Fatalf("field %q at %d: got %v, want %v", field, i, value, want[i])
		}
	}
}

// Test_queryHealthCountsFailedProxyQueries drives the real query path against a
// refusing upstream: every sampled error reaches the tracker, so the window of
// the daemon grades as failing.
func Test_queryHealthCountsFailedProxyQueries(t *testing.T) {
	captureDebugMainLog(t)
	cfg := &ctrld.Config{}
	cfg.Service.LeakOnUpstreamFailure = func(v bool) *bool { return &v }(false)
	p := &prog{cfg: cfg, um: newUpstreamMonitor(cfg, mainLog.Load()), health: newQueryHealth()}
	p.logger.Store(mainLog.Load())
	// A new monitor holds back the failure counts for one second, and its
	// timer would mark the upstream down after the test.
	p.um.clearRecovered(upstreamOS)
	p.um.after = func(time.Duration, func()) {}
	p.querySampler.onFailure = p.health.countFailure
	// The zero value sampler arms a real timer. Close its window after the
	// assertions, so no late summary line reaches another test.
	t.Cleanup(func() { p.querySampler.closeExpired(time.Now().Add(querySampleWindow)) })

	origOSUpstream := osUpstreamConfig
	t.Cleanup(func() { osUpstreamConfig = origOSUpstream })
	osUpstreamConfig = &ctrld.UpstreamConfig{
		Name:     "dead resolver",
		Type:     ctrld.ResolverTypeLegacy,
		Endpoint: deadUpstreamEndpoint,
		Timeout:  500,
	}

	const failedQueries = 12
	const servedQueries = 20
	ctx := context.Background()
	for i := 0; i < failedQueries; i++ {
		if rcode := askThroughProxy(t, p, ctx).Rcode; rcode != dns.RcodeServerFailure {
			t.Fatalf("query %d: rcode %s, want SERVFAIL", i+1, dns.RcodeToString[rcode])
		}
	}
	// serveDNS counts every query it serves, and the eight answered ones never
	// reach the sampler.
	for i := 0; i < servedQueries; i++ {
		p.health.countQuery()
	}

	event, emit := p.health.evaluate(time.Now(), 0, false)
	if !emit {
		t.Fatal("the first evaluate did not emit")
	}
	if event.Class != queryHealthFailing {
		t.Fatalf("class: got %q, want %q", event.Class, queryHealthFailing)
	}
	if event.Queries != servedQueries {
		t.Fatalf("queries: got %d, want %d", event.Queries, servedQueries)
	}
	// The grade follows one failure per failed query. Each of those queries
	// also raised two sampler events, and the breakdown still shows them.
	if event.FailedQueries != failedQueries {
		t.Fatalf("failed queries: got %d, want %d", event.FailedQueries, failedQueries)
	}
	if got := event.Failures[sampleClassResolveFailed]; got != failedQueries {
		t.Fatalf("%s failures: got %d, want %d", sampleClassResolveFailed, got, failedQueries)
	}
	if got := event.Failures[sampleClassAllEndpointsFailed]; got != failedQueries {
		t.Fatalf("%s failures: got %d, want %d", sampleClassAllEndpointsFailed, got, failedQueries)
	}
}

// Test_queryHealthKeepsInternalDomainFailuresOutOfTheGrade drives the same
// number of failed queries against an Internal Domain resolver. An endpoint
// away from the organization network cannot reach that resolver, so the class
// stays healthy, the failures keep their own name, and the down entry of that
// resolver stays out of upstreams_down.
func Test_queryHealthKeepsInternalDomainFailuresOutOfTheGrade(t *testing.T) {
	captureDebugMainLog(t)
	const internalUpstream = upstreamPrefix + internalDomainUpstreamPrefix + "1"
	cfg := &ctrld.Config{}
	cfg.Service.LeakOnUpstreamFailure = func(v bool) *bool { return &v }(false)
	cfg.Upstream = map[string]*ctrld.UpstreamConfig{
		internalDomainUpstreamPrefix + "1": {
			Name:     "dead internal resolver",
			Type:     ctrld.ResolverTypeLegacy,
			Endpoint: deadUpstreamEndpoint,
			Timeout:  500,
		},
	}
	p := &prog{cfg: cfg, um: newUpstreamMonitor(cfg, mainLog.Load()), health: newQueryHealth()}
	p.logger.Store(mainLog.Load())
	p.um.after = func(time.Duration, func()) {}
	p.um.clearRecovered(internalUpstream)
	p.querySampler.onFailure = p.health.countFailure
	t.Cleanup(func() { p.querySampler.closeExpired(time.Now().Add(querySampleWindow)) })

	const failedQueries = 12
	const servedQueries = 20
	ctx := context.Background()
	msg := new(dns.Msg)
	msg.SetQuestion("internal.corp.example.", dns.TypeA)
	for i := 0; i < failedQueries; i++ {
		res := p.proxy(ctx, &proxyRequest{
			msg: msg,
			ufr: &upstreamForResult{upstreams: []string{internalUpstream}, srcAddr: "192.168.0.1:1234"},
		})
		if res == nil || res.answer == nil || res.answer.Rcode != dns.RcodeServerFailure {
			t.Fatalf("query %d: the internal resolver answered", i+1)
		}
	}
	for i := 0; i < servedQueries; i++ {
		p.health.countQuery()
	}
	p.um.mu.Lock()
	p.um.markDown(internalUpstream, 3, "immediate")
	p.um.mu.Unlock()

	event, emit := p.health.evaluate(time.Now(), p.um.countDownExcept(isInternalDomainUpstream), false)
	if !emit {
		t.Fatal("the first evaluate did not emit")
	}
	if event.Class != queryHealthHealthy {
		t.Fatalf("class: got %q, want %q", event.Class, queryHealthHealthy)
	}
	if event.FailedQueries != 0 {
		t.Fatalf("failed queries: got %d, want 0", event.FailedQueries)
	}
	if got := event.Failures[sampleClassInternalDomain]; got != failedQueries {
		t.Fatalf("%s failures: got %d, want %d", sampleClassInternalDomain, got, failedQueries)
	}
	if event.UpstreamsDown != 0 {
		t.Fatalf("upstreams_down: got %d, want 0", event.UpstreamsDown)
	}
	if got := p.um.countDown(); got != 1 {
		t.Fatalf("countDown: got %d, want 1", got)
	}
}

// Test_queryHealthCountsProxyCacheHits proves that an answer from the cache
// counts a cache hit, so the ratio of the journal follows the query path.
func Test_queryHealthCountsProxyCacheHits(t *testing.T) {
	captureDebugMainLog(t)
	p := &prog{cfg: testhelper.SampleConfig(t), health: newQueryHealth()}
	p.logger.Store(mainLog.Load())
	cache, err := dnscache.NewLRUCache(16)
	require.NoError(t, err)
	p.cache = cache

	msg := new(dns.Msg)
	msg.SetQuestion("cache.test.", dns.TypeA)
	answer := new(dns.Msg)
	answer.SetRcode(msg, dns.RcodeSuccess)
	p.cache.Add(dnscache.NewKey(msg, "upstream.1"), dnscache.NewValue(answer, time.Now().Add(time.Minute)))

	res := p.proxy(context.Background(), &proxyRequest{
		msg: msg,
		ufr: &upstreamForResult{upstreams: []string{"upstream.1"}},
	})
	require.NotNil(t, res)
	require.True(t, res.cached, "the answer did not come from the cache")

	event, _ := p.health.evaluate(time.Now(), 0, false)
	if event.CacheHits != 1 {
		t.Fatalf("cache hits: got %d, want 1", event.CacheHits)
	}
}

// Test_logDNSConfigChangesLogsEveryEntry proves that each changed resolver of
// the host reaches the journal with its fields. A resolver that vanished keeps
// an empty nameserver list.
func Test_logDNSConfigChangesLogsEveryEntry(t *testing.T) {
	logs := captureDebugMainLog(t)
	p := &prog{}
	p.logger.Store(mainLog.Load())

	p.logDNSConfigChanges([]dnsResolverEntry{
		{
			Order:         200000,
			Nameservers:   []string{"192.168.50.200", "192.168.50.1"},
			IfIndex:       16,
			Interface:     "en0",
			Flags:         "Request A records, Request AAAA records",
			SearchDomains: []string{"corp.example"},
			Reachable:     "Reachable,Directly Reachable Address",
		},
		{Order: 101600, IfIndex: 21, Interface: "utun4", Flags: "Scoped"},
	})

	events := jsonLogEvents(t, logs, dnsConfigChangedMessage)
	if len(events) != 2 {
		t.Fatalf("configuration lines: got %d, want 2", len(events))
	}

	wantField(t, events[0], "journal", true)
	wantField(t, events[0], "level", "info")
	wantField(t, events[0], "if_index", float64(16))
	wantField(t, events[0], "interface", "en0")
	wantField(t, events[0], "flags", "Request A records, Request AAAA records")
	wantField(t, events[0], "order", float64(200000))
	wantField(t, events[0], "reachable", "Reachable,Directly Reachable Address")
	wantDNSConfigStrings(t, events[0], "nameservers", "192.168.50.200", "192.168.50.1")
	// The suffixes of an organization stay out of the journal. Only their
	// number goes in.
	wantField(t, events[0], "search_domain_count", float64(1))
	if _, ok := events[0]["search_domains"]; ok {
		t.Fatal("the journal holds the search domains")
	}

	wantField(t, events[1], "journal", true)
	wantField(t, events[1], "interface", "utun4")
	wantDNSConfigStrings(t, events[1], "nameservers")
	wantField(t, events[1], "search_domain_count", float64(0))
}

// Test_startNetworkJournalLogsTheStartSnapshot proves that the daemon opens the
// journal with one snapshot and runs the trackers that follow the query path
// and the DNS configuration of the host.
func Test_startNetworkJournalLogsTheStartSnapshot(t *testing.T) {
	logs := captureDebugMainLog(t)
	stubHeaderSnapshotSources(t)
	origTick := queryHealthTick
	t.Cleanup(func() { queryHealthTick = origTick })
	queryHealthTick = time.Millisecond

	var polls atomic.Int64
	// The poll loop reads the delay on every pass, so it parks on a long delay
	// before the test puts the package value back.
	parked := make(chan struct{}, 1)
	origRunner, origDelay := runSCUtilDNSFn, dnsConfigDelayFn
	t.Cleanup(func() { runSCUtilDNSFn, dnsConfigDelayFn = origRunner, origDelay })
	movedResolver := wifiResolverEntry()
	movedResolver.Nameservers = []string{"10.0.0.1"}
	runSCUtilDNSFn = func() ([]dnsResolverEntry, error) {
		if polls.Add(1) == 1 {
			return []dnsResolverEntry{wifiResolverEntry()}, nil
		}
		return []dnsResolverEntry{movedResolver}, nil
	}
	dnsConfigDelayFn = func(*dnsConfigPoller, time.Time) time.Duration {
		if polls.Load() < 2 {
			return time.Millisecond
		}
		select {
		case parked <- struct{}{}:
		default:
		}
		return time.Hour
	}

	cfg := &ctrld.Config{}
	p := &prog{cfg: cfg, um: newUpstreamMonitor(cfg, mainLog.Load()), stopCh: make(chan struct{})}
	p.logger.Store(mainLog.Load())
	// The monitor arms a real timer for each upstream it resets. Nothing in
	// this test waits for one.
	p.um.after = func(time.Duration, func()) {}
	p.lastNetworkState.Store(sourceTestState("en0", true, "192.0.2.9/24"))
	p.recoveryBypass.Store(true)
	p.um.mu.Lock()
	p.um.markDown(upstreamOS, 3, "timer")
	p.um.mu.Unlock()

	p.newNetworkJournal()
	if p.health == nil || p.querySampler.onFailure == nil {
		t.Fatal("the trackers do not exist before the loops start")
	}
	// A counter of the query path works as soon as the trackers exist.
	p.health.countQuery()
	waitForJournalLoops := p.startNetworkJournal()
	t.Cleanup(func() {
		close(p.stopCh)
		waitForJournalLoops()
	})

	events := jsonLogEvents(t, logs, networkSnapshotMessage)
	if len(events) != 1 {
		t.Fatalf("snapshot lines: got %d, want 1", len(events))
	}
	wantField(t, events[0], "journal", true)
	wantField(t, events[0], "level", "info")
	wantField(t, events[0], "trigger", "start")

	waitForLogLine(t, logs, queryHealthMessage)
	health := jsonLogEvents(t, logs, queryHealthMessage)
	wantField(t, health[0], "upstreams_down", float64(1))
	wantField(t, health[0], "bypass_active", true)

	if runtime.GOOS != "darwin" {
		if p.dnsConfig != nil {
			t.Fatal("the DNS configuration poller runs outside macOS")
		}
		return
	}
	if p.dnsConfig == nil {
		t.Fatal("macOS starts no DNS configuration poller")
	}
	waitForLogLine(t, logs, dnsConfigChangedMessage)
	select {
	case <-parked:
	case <-time.After(5 * time.Second):
		t.Fatal("the poll loop did not park")
	}
	resolvers := jsonLogEvents(t, logs, dnsConfigChangedMessage)
	if len(resolvers) != 1 {
		t.Fatalf("configuration lines: got %d, want 1", len(resolvers))
	}
	wantField(t, resolvers[0], "interface", "en0")
	wantDNSConfigStrings(t, resolvers[0], "nameservers", "10.0.0.1")
}

// Test_startNetworkJournalReadsTheMonitorAcrossAReload replaces the upstream
// monitor while the health loop runs. A reload builds a new monitor, and the
// loop read the field of the prog with no lock, which the race detector
// reports.
func Test_startNetworkJournalReadsTheMonitorAcrossAReload(t *testing.T) {
	captureDebugMainLog(t)
	stubHeaderSnapshotSources(t)
	origTick := queryHealthTick
	t.Cleanup(func() { queryHealthTick = origTick })
	queryHealthTick = time.Millisecond

	cfg := &ctrld.Config{}
	p := &prog{cfg: cfg, stopCh: make(chan struct{})}
	p.logger.Store(mainLog.Load())
	p.lastNetworkState.Store(sourceTestState("en0", true, "192.0.2.9/24"))
	p.replaceUpstreamMonitor()
	p.health = newQueryHealth()

	waitForJournalLoops := p.startNetworkJournal()
	for i := 0; i < 30; i++ {
		p.replaceUpstreamMonitor()
		time.Sleep(time.Millisecond)
	}
	close(p.stopCh)
	waitForJournalLoops()
}

// Test_startNetworkJournalRunsAfterAFailedMonitorStart proves that a network
// monitor that cannot start leaves the journal running. The error line goes
// out, the start snapshot opens the journal, and the health loop reports.
func Test_startNetworkJournalRunsAfterAFailedMonitorStart(t *testing.T) {
	logs := captureDebugMainLog(t)
	stubHeaderSnapshotSources(t)
	origTick := queryHealthTick
	t.Cleanup(func() { queryHealthTick = origTick })
	queryHealthTick = time.Millisecond

	origMonitor := newNetworkChangeMonitorFn
	t.Cleanup(func() { newNetworkChangeMonitorFn = origMonitor })
	newNetworkChangeMonitorFn = func(func(string, ...any)) (networkChangeMonitor, error) {
		return nil, errors.New("no network monitor here")
	}
	origRunner, origDelay := runSCUtilDNSFn, dnsConfigDelayFn
	t.Cleanup(func() { runSCUtilDNSFn, dnsConfigDelayFn = origRunner, origDelay })
	runSCUtilDNSFn = func() ([]dnsResolverEntry, error) {
		return []dnsResolverEntry{wifiResolverEntry()}, nil
	}
	dnsConfigDelayFn = func(*dnsConfigPoller, time.Time) time.Duration { return time.Hour }

	cfg := &ctrld.Config{}
	p := &prog{cfg: cfg, stopCh: make(chan struct{})}
	p.logger.Store(mainLog.Load())
	p.lastNetworkState.Store(sourceTestState("en0", true, "192.0.2.9/24"))
	p.replaceUpstreamMonitor()
	p.upstreamMonitorNow().after = func(time.Duration, func()) {}

	p.newNetworkJournal()
	p.health.countQuery()
	p.health.mu.Lock()
	queries := p.health.queries
	p.health.mu.Unlock()
	if queries != 1 {
		t.Fatalf("queries after one count: got %d, want 1", queries)
	}

	waitForJournalLoops := p.startNetworkMonitorAndJournal(context.Background())
	t.Cleanup(func() {
		close(p.stopCh)
		waitForJournalLoops()
	})

	failures := jsonLogEvents(t, logs, "Failed to start network monitoring")
	if len(failures) != 1 {
		t.Fatalf("monitor failure lines: got %d, want 1", len(failures))
	}
	wantField(t, failures[0], "level", "error")

	snapshots := jsonLogEvents(t, logs, networkSnapshotMessage)
	if len(snapshots) != 1 {
		t.Fatalf("snapshot lines: got %d, want 1", len(snapshots))
	}
	wantField(t, snapshots[0], "trigger", "start")

	waitForLogLine(t, logs, queryHealthMessage)
}

// Test_queryHealthCountsNoFailureWhenAnUpstreamAnswers proves that a failure on
// one upstream does not grade the query. The client got an answer, so the
// failure stays in the breakdown only. The DNS64 companion lookup fails through
// the same call, so it cannot grade a query either.
func Test_queryHealthCountsNoFailureWhenAnUpstreamAnswers(t *testing.T) {
	captureDebugMainLog(t)
	fixture := startDNSFixture(t)
	cfg := &ctrld.Config{}
	cfg.Service.LeakOnUpstreamFailure = func(v bool) *bool { return &v }(false)
	cfg.Upstream = map[string]*ctrld.UpstreamConfig{
		"0": {Name: "dead resolver", Type: ctrld.ResolverTypeLegacy, Endpoint: deadUpstreamEndpoint, Timeout: 500},
		"1": {Name: "live resolver", Type: ctrld.ResolverTypeLegacy, Endpoint: fixture.addr, Timeout: 2000},
	}
	p := &prog{cfg: cfg, um: newUpstreamMonitor(cfg, mainLog.Load()), health: newQueryHealth()}
	p.logger.Store(mainLog.Load())
	p.um.after = func(time.Duration, func()) {}
	p.um.clearRecovered(upstreamPrefix + "0")
	p.querySampler.onFailure = p.health.countFailure
	t.Cleanup(func() { p.querySampler.closeExpired(time.Now().Add(querySampleWindow)) })

	msg := new(dns.Msg)
	msg.SetQuestion("failover.test.", dns.TypeA)
	res := p.proxy(context.Background(), &proxyRequest{
		msg: msg,
		ufr: &upstreamForResult{
			upstreams: []string{upstreamPrefix + "0", upstreamPrefix + "1"},
			srcAddr:   "192.168.0.1:1234",
		},
	})
	if res == nil || res.answer == nil || res.answer.Rcode != dns.RcodeSuccess {
		t.Fatal("the second upstream did not answer")
	}
	p.health.countQuery()

	event, _ := p.health.evaluate(time.Now(), 0, false)
	if event.FailedQueries != 0 {
		t.Fatalf("failed queries: got %d, want 0", event.FailedQueries)
	}
	if got := event.Failures[sampleClassResolveFailed]; got != 1 {
		t.Fatalf("%s failures: got %d, want 1", sampleClassResolveFailed, got)
	}
	if event.Class != queryHealthHealthy {
		t.Fatalf("class: got %q, want %q", event.Class, queryHealthHealthy)
	}
}
