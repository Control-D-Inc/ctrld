package cli

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Control-D-Inc/ctrld"
)

// fakeSleepClocks drives the sleep check: sleep moves the wall clock only, as
// a sleeping host does, and awake moves both.
type fakeSleepClocks struct {
	mu    sync.Mutex
	wall  time.Time
	awake time.Duration
}

func stubSleepClocks(t *testing.T) *fakeSleepClocks {
	t.Helper()
	c := &fakeSleepClocks{wall: time.Date(2026, 10, 14, 21, 38, 0, 0, time.UTC)}
	oldWall, oldAwake := sleepWatchWallFn, sleepWatchAwakeFn
	t.Cleanup(func() { sleepWatchWallFn, sleepWatchAwakeFn = oldWall, oldAwake })
	sleepWatchWallFn = func() time.Time {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.wall
	}
	sleepWatchAwakeFn = func() time.Duration {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.awake
	}
	return c
}

func (c *fakeSleepClocks) sleep(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wall = c.wall.Add(d)
}

func (c *fakeSleepClocks) run(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wall = c.wall.Add(d)
	c.awake += d
}

// The wall clock moving ahead of the awake clock is a sleep. Both moving
// together is not, however long, and neither is the awake clock's rate error.
func TestSleepWatch(t *testing.T) {
	for _, tc := range []struct {
		name  string
		pass  func(*fakeSleepClocks)
		slept bool
	}{
		{"awake", func(c *fakeSleepClocks) { c.run(time.Hour) }, false},
		{"slept", func(c *fakeSleepClocks) { c.run(time.Second); c.sleep(time.Minute) }, true},
		{"short nap", func(c *fakeSleepClocks) { c.sleep(time.Second) }, false},
		{"drift", func(c *fakeSleepClocks) { c.run(24 * time.Hour); c.sleep(10 * time.Minute) }, false},
		{"slept after a long idle", func(c *fakeSleepClocks) { c.run(24 * time.Hour); c.sleep(time.Hour) }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := stubSleepClocks(t)
			var w sleepWatch
			if w.slept() {
				t.Fatal("the first check found a sleep")
			}
			tc.pass(c)
			if got := w.slept(); got != tc.slept {
				t.Fatalf("slept = %v, want %v", got, tc.slept)
			}
			if w.slept() {
				t.Fatal("the same sleep was found twice")
			}
		})
	}
}

// freshConnResolver models upstream connections opened in network epoch 0 as
// dead: the upstream fails until the connections are renewed. onFirst runs
// during the upstream's first query. The OS resolver records its use and
// answers.
type freshConnResolver struct {
	p     *prog
	os    bool
	state *freshConnState
}

type freshConnState struct {
	upstreamCalls int
	osCalls       int
	onFirst       func()
}

func (r freshConnResolver) Resolve(_ context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if r.os {
		r.state.osCalls++
	} else {
		r.state.upstreamCalls++
		dead := r.p.networkEpoch.Load() == 0
		if r.state.upstreamCalls == 1 && r.state.onFirst != nil {
			r.state.onFirst()
		}
		if dead {
			return nil, errors.New("context deadline exceeded")
		}
	}
	answer := new(dns.Msg)
	answer.SetReply(msg)
	return answer, nil
}

func newFreshConnProg(t *testing.T, typ string) (*prog, *freshConnState, *fakeSleepClocks) {
	t.Helper()
	captureDebugMainLog(t)
	clocks := stubSleepClocks(t)
	leak := true
	cfg := &ctrld.Config{Upstream: map[string]*ctrld.UpstreamConfig{
		"0": {Name: "control d", Type: typ, Endpoint: "https://192.0.2.1/dns-query", Timeout: 100},
	}}
	cfg.Service.LeakOnUpstreamFailure = &leak
	p := &prog{cfg: cfg, um: newUpstreamMonitor(cfg)}
	p.um.after = func(time.Duration, func()) {}
	p.lanLoopGuard = newLoopGuard()
	p.ptrLoopGuard = newLoopGuard()
	t.Cleanup(func() { p.querySampler.closeExpired(time.Now().Add(querySampleWindow)) })
	state := &freshConnState{}
	oldResolver, oldRecovery := newResolverFn, queryRecoveryFn
	t.Cleanup(func() { newResolverFn, queryRecoveryFn = oldResolver, oldRecovery })
	newResolverFn = func(uc *ctrld.UpstreamConfig) (ctrld.Resolver, error) {
		return freshConnResolver{p: p, os: uc.Name == osUpstreamConfig.Name, state: state}, nil
	}
	queryRecoveryFn = func(*prog, RecoveryReason) {}
	// The watch has seen the host awake before the test.
	p.sleepWatch.slept()
	return p, state, clocks
}

func freshConnQuery(p *prog) *proxyResponse {
	msg := new(dns.Msg)
	msg.SetQuestion("time.apple.com.", dns.TypeA)
	return p.proxy(context.Background(), &proxyRequest{msg: msg, ufr: &upstreamForResult{
		upstreams: []string{upstreamPrefix + "0"}, srcAddr: "127.0.0.1:5353",
	}})
}

// A query does not ride connections that predate the network to a plaintext
// fallback (#631). A sleep found before the query renews the connections
// before it is sent. A network change, or a sleep found when the query fails,
// retries it once on fresh connections. Without such evidence a failure goes
// to the OS resolver at once, as before.
func TestFreshConnectionRetryBeforeOSFallback(t *testing.T) {
	for _, tc := range []struct {
		name         string
		typ          string
		before       func(*prog, *fakeSleepClocks)
		during       func(*prog, *fakeSleepClocks)
		wantUpstream int
		wantOS       int
	}{
		{name: "host slept before the query", typ: ctrld.ResolverTypeDOH,
			before:       func(_ *prog, c *fakeSleepClocks) { c.sleep(time.Hour) },
			wantUpstream: 1},
		{name: "host slept during the query", typ: ctrld.ResolverTypeDOH,
			during:       func(_ *prog, c *fakeSleepClocks) { c.sleep(time.Hour) },
			wantUpstream: 2},
		{name: "network change during the query", typ: ctrld.ResolverTypeDOH,
			during:       func(p *prog, _ *fakeSleepClocks) { p.renewUpstreamConnections() },
			wantUpstream: 2},
		{name: "DoT, network change during the query", typ: ctrld.ResolverTypeDOT,
			during:       func(p *prog, _ *fakeSleepClocks) { p.renewUpstreamConnections() },
			wantUpstream: 2},
		{name: "stable network", typ: ctrld.ResolverTypeDOH,
			during:       func(_ *prog, c *fakeSleepClocks) { c.run(time.Second) },
			wantUpstream: 1, wantOS: 1},
		{name: "plain DNS upstream", typ: ctrld.ResolverTypeLegacy,
			during:       func(p *prog, _ *fakeSleepClocks) { p.renewUpstreamConnections() },
			wantUpstream: 1, wantOS: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, state, clocks := newFreshConnProg(t, tc.typ)
			if tc.before != nil {
				tc.before(p, clocks)
			}
			if tc.during != nil {
				state.onFirst = func() { tc.during(p, clocks) }
			}

			res := freshConnQuery(p)

			if res.answer == nil || res.answer.Rcode != dns.RcodeSuccess {
				t.Fatalf("answer = %v, want an answer", res.answer)
			}
			if state.upstreamCalls != tc.wantUpstream || state.osCalls != tc.wantOS {
				t.Fatalf("upstream calls = %d, OS resolver calls = %d; want %d and %d",
					state.upstreamCalls, state.osCalls, tc.wantUpstream, tc.wantOS)
			}
		})
	}
}

// Of the queries that run after a sleep, one renews the connections.
func TestFreshConnectionSleepRenewsOnce(t *testing.T) {
	p, _, clocks := newFreshConnProg(t, ctrld.ResolverTypeDOH)
	clocks.sleep(time.Hour)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() { p.renewConnectionsIfSlept(context.Background()) })
	}
	wg.Wait()
	if got := p.networkEpoch.Load(); got != 1 {
		t.Fatalf("network epoch = %d, want 1", got)
	}
}

// A wake and an accepted network change both renew the upstream connections.
func TestWakeAndNetworkChangeRenewConnections(t *testing.T) {
	h := newNetworkEventsHarness(t, "en0", "en7")
	h.prog.noteHostWoke("detector", time.Minute, nil)
	if got := h.prog.networkEpoch.Load(); got != 1 {
		t.Fatalf("network epoch after the wake = %d, want 1", got)
	}
	before := orderTestState("", "", map[string][]string{"en0": nil}, map[string]bool{"en0": true})
	before.HaveV4 = false
	after := orderTestState("en7", "", map[string][]string{"en0": nil, "en7": {"192.0.2.30/24"}}, map[string]bool{"en0": true})
	h.handle(before, after, false)
	if got := h.prog.networkEpoch.Load(); got != 2 {
		t.Fatalf("network epoch after the change = %d, want 2", got)
	}
}
