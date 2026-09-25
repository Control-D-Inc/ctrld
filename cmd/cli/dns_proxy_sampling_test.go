package cli

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Control-D-Inc/ctrld"
)

// deadUpstreamEndpoint is a port that nothing listens on, so every query to it
// fails at once.
const deadUpstreamEndpoint = "127.0.0.1:1"

// countSamplingLines counts the captured lines of one level whose message
// starts with the given text. A request id rides in front of the message.
func countSamplingLines(t *testing.T, logs *syncBuffer, level, message string) int {
	t.Helper()
	count := 0
	for _, event := range jsonLogEvents(t, logs, "") {
		text, _ := event["message"].(string)
		if !strings.HasPrefix(text, message) || event["level"] != level {
			continue
		}
		count++
	}
	return count
}

func Test_querySamplingBoundsPerQueryErrors(t *testing.T) {
	logs := captureDebugMainLog(t)
	p := &prog{}
	p.logger.Store(mainLog.Load())
	// The zero value sampler arms a real timer. Close its window after the
	// assertions, so no late summary line reaches another test.
	t.Cleanup(func() { p.querySampler.closeExpired(time.Now().Add(querySampleWindow)) })

	for i := 0; i < querySampleLimit+1; i++ {
		ctrld.Log(context.Background(), p.querySampler.event(sampleClassResolveFailed, "upstream.0"), samplerTestMessage)
	}

	if got := countSamplingLines(t, logs, "error", samplerTestMessage); got != querySampleLimit {
		t.Fatalf("error lines: got %d, want %d", got, querySampleLimit)
	}
	if got := countSamplingLines(t, logs, "debug", samplerTestMessage); got != 1 {
		t.Fatalf("debug lines: got %d, want 1", got)
	}
}

// askThroughProxy sends one query through the real proxy path and returns the
// answer.
func askThroughProxy(t *testing.T, p *prog, ctx context.Context) *dns.Msg {
	t.Helper()
	msg := new(dns.Msg)
	msg.SetQuestion("sampling.test.", dns.TypeA)
	res := p.proxy(ctx, &proxyRequest{msg: msg, ufr: &upstreamForResult{srcAddr: "192.168.0.1:1234"}})
	if res == nil || res.answer == nil {
		t.Fatal("the proxy returned no answer")
	}
	return res.answer
}

// Test_querySamplingOnTheQueryPath drives the real query path with an upstream
// that answers nothing: the flood keeps its request id, the sampler bounds it,
// and one state event brackets each end of the outage.
func Test_querySamplingOnTheQueryPath(t *testing.T) {
	logs := captureDebugMainLog(t)
	cfg := &ctrld.Config{}
	cfg.Service.LeakOnUpstreamFailure = func(v bool) *bool { return &v }(false)
	p := &prog{cfg: cfg, um: newUpstreamMonitor(cfg, mainLog.Load())}
	p.logger.Store(mainLog.Load())
	// A new monitor holds back the failure counts for one second. The test
	// clears the flag instead of waiting for that timer.
	p.um.clearRecovered(upstreamOS)
	var armed []func()
	p.um.after = func(_ time.Duration, fn func()) { armed = append(armed, fn) }
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

	ctx := context.WithValue(context.Background(), ctrld.ReqIdCtxKey{}, "r1")
	for i := 0; i < querySampleLimit+2; i++ {
		if rcode := askThroughProxy(t, p, ctx).Rcode; rcode != dns.RcodeServerFailure {
			t.Fatalf("query %d: rcode %s, want SERVFAIL", i+1, dns.RcodeToString[rcode])
		}
	}

	const failedMessage = "[r1] " + samplerTestMessage
	if got := countSamplingLines(t, logs, "error", failedMessage); got != querySampleLimit {
		t.Fatalf("error lines: got %d, want %d", got, querySampleLimit)
	}
	if got := countSamplingLines(t, logs, "debug", failedMessage); got != 2 {
		t.Fatalf("debug lines: got %d, want 2", got)
	}

	if len(armed) != 1 {
		t.Fatalf("armed timers: got %d, want 1", len(armed))
	}
	armed[0]()
	startOSResolverStub(t)
	if rcode := askThroughProxy(t, p, ctx).Rcode; rcode != dns.RcodeSuccess {
		t.Fatalf("the answered query returned %s, want NOERROR", dns.RcodeToString[rcode])
	}

	events := jsonLogEvents(t, logs, upstreamStateMessage)
	if len(events) != 2 {
		t.Fatalf("state events: got %d, want 2", len(events))
	}
	wantField(t, events[0], "upstream", upstreamOS)
	wantField(t, events[0], "state", "down")
	wantField(t, events[0], "reason", "timer")
	wantField(t, events[1], "upstream", upstreamOS)
	wantField(t, events[1], "state", "up")
}

// Test_allEndpointsFailedBoundsTheUpstreamName drives the query path with an
// operator-chosen upstream key. The line that reports the loss of every
// endpoint reaches the journal, so it must name the upstream by its bounded
// name.
func Test_allEndpointsFailedBoundsTheUpstreamName(t *testing.T) {
	logs := captureDebugMainLog(t)
	uc := &ctrld.UpstreamConfig{
		Name:     probeSecret,
		Type:     ctrld.ResolverTypeLegacy,
		Endpoint: deadUpstreamEndpoint,
		Timeout:  200,
	}
	uc.Init(context.Background())
	cfg := &ctrld.Config{Upstream: map[string]*ctrld.UpstreamConfig{probeSecret: uc}}
	cfg.Service.LeakOnUpstreamFailure = func(v bool) *bool { return &v }(false)
	p := &prog{cfg: cfg, um: newUpstreamMonitor(cfg, mainLog.Load())}
	p.logger.Store(mainLog.Load())
	// The zero value sampler arms a real timer. Close its window after the
	// assertions, so no late summary line reaches another test.
	t.Cleanup(func() { p.querySampler.closeExpired(time.Now().Add(querySampleWindow)) })

	msg := new(dns.Msg)
	msg.SetQuestion("private.test.", dns.TypeA)
	res := p.proxy(context.Background(), &proxyRequest{
		msg: msg,
		ufr: &upstreamForResult{
			srcAddr:   "192.168.0.1:1234",
			upstreams: []string{upstreamPrefix + probeSecret},
		},
	})
	if res == nil || res.answer == nil || res.answer.Rcode != dns.RcodeServerFailure {
		t.Fatal("the proxy answered although every endpoint failed")
	}

	var reported string
	for _, event := range jsonLogEvents(t, logs, "") {
		text, _ := event["message"].(string)
		if strings.Contains(text, "endpoints failed") {
			reported = text
		}
	}
	if !strings.Contains(reported, upstreamPrefix+"custom") {
		t.Fatalf("the all-endpoints line does not name the bounded upstream: %q", reported)
	}
	if strings.Contains(reported, probeSecret) {
		t.Fatalf("the all-endpoints line holds the operator key: %q", reported)
	}
}
