package cli

import (
	"context"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/Control-D-Inc/ctrld"
)

const (
	// maxFailureRequest is the maximum failed queries allowed before an upstream is marked as down.
	maxFailureRequest = 100
	// checkUpstreamBackoffSleep is the time interval between each upstream checks.
	checkUpstreamBackoffSleep = 2 * time.Second
)

// upstreamMonitor performs monitoring upstreams health.
type upstreamMonitor struct {
	cfg *ctrld.Config

	mu         sync.Mutex
	checking   map[string]bool
	down       map[string]bool
	failureReq map[string]uint64
}

func newUpstreamMonitor(cfg *ctrld.Config) *upstreamMonitor {
	um := &upstreamMonitor{
		cfg:        cfg,
		checking:   make(map[string]bool),
		down:       make(map[string]bool),
		failureReq: make(map[string]uint64),
	}
	for n := range cfg.Upstream {
		upstream := upstreamPrefix + n
		um.reset(upstream)
	}
	um.reset(upstreamOS)
	return um
}

// increaseFailureCount increase failed queries count for an upstream by 1.
func (um *upstreamMonitor) increaseFailureCount(upstream string) {
	um.mu.Lock()
	defer um.mu.Unlock()

	um.failureReq[upstream] += 1
	failedCount := um.failureReq[upstream]
	um.down[upstream] = failedCount >= maxFailureRequest
}

// isDown reports whether the given upstream is being marked as down.
func (um *upstreamMonitor) isDown(upstream string) bool {
	um.mu.Lock()
	defer um.mu.Unlock()

	return um.down[upstream]
}

// isChecking reports whether the given upstream is being checked.
func (um *upstreamMonitor) isChecking(upstream string) bool {
	um.mu.Lock()
	defer um.mu.Unlock()

	return um.checking[upstream]
}

// reset marks an upstream as up and set failed queries counter to zero.
func (um *upstreamMonitor) reset(upstream string) {
	um.mu.Lock()
	defer um.mu.Unlock()

	um.failureReq[upstream] = 0
	um.down[upstream] = false
}

// checkUpstream checks the given upstream status, periodically sending query to upstream
// until successfully. An upstream status/counter will be reset once it becomes reachable.
func (p *prog) checkUpstream(upstream string, uc *ctrld.UpstreamConfig) {
	p.um.mu.Lock()
	isChecking := p.um.checking[upstream]
	if isChecking {
		p.um.mu.Unlock()
		return
	}
	p.um.checking[upstream] = true
	p.um.mu.Unlock()
	defer func() {
		p.um.mu.Lock()
		p.um.checking[upstream] = false
		p.um.mu.Unlock()
	}()

	isOsResolver := uc.Type == ctrld.ResolverTypeOS
	if isOsResolver {
		p.resetDNS()
		defer p.setDNS()
	}
	resolver, err := ctrld.NewResolver(uc)
	if err != nil {
		mainLog.Load().Warn().Err(err).Msg("could not check upstream")
		return
	}
	msg := new(dns.Msg)
	msg.SetQuestion(".", dns.TypeNS)
	timeout := 1000 * time.Millisecond
	if uc.Timeout > 0 {
		timeout = time.Duration(uc.Timeout) * time.Millisecond
	}
	check := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		uc.ReBootstrap()
		if isOsResolver {
			ctrld.InitializeOsResolver()
		}
		_, err := resolver.Resolve(ctx, msg)
		return err
	}
	mainLog.Load().Warn().Msgf("upstream %q is offline", uc.Endpoint)
	for {
		if err := check(); err == nil {
			mainLog.Load().Warn().Msgf("upstream %q is online", uc.Endpoint)
			p.um.reset(upstream)
			if p.leakingQuery.CompareAndSwap(true, false) {
				p.leakingQueryMu.Lock()
				p.leakingQueryWasRun = false
				p.leakingQueryMu.Unlock()
				mainLog.Load().Warn().Msg("stop leaking query")
			}
			return
		} else {
			mainLog.Load().Debug().Msgf("checked upstream %q failed: %v", uc.Endpoint, err)
		}
		time.Sleep(checkUpstreamBackoffSleep)
	}
}
