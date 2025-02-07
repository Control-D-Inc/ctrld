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

	mu         sync.RWMutex
	checking   map[string]bool
	down       map[string]bool
	failureReq map[string]uint64
	recovered  map[string]bool
}

func newUpstreamMonitor(cfg *ctrld.Config) *upstreamMonitor {
	um := &upstreamMonitor{
		cfg:        cfg,
		checking:   make(map[string]bool),
		down:       make(map[string]bool),
		failureReq: make(map[string]uint64),
		recovered:  make(map[string]bool),
	}
	for n := range cfg.Upstream {
		upstream := upstreamPrefix + n
		um.reset(upstream)
	}
	um.reset(upstreamOS)
	return um
}

// increaseFailureCount increases failed queries count for an upstream by 1 and logs debug information.
func (um *upstreamMonitor) increaseFailureCount(upstream string) {
	um.mu.Lock()
	defer um.mu.Unlock()

	if um.recovered[upstream] {
		mainLog.Load().Debug().Msgf("upstream %q is recovered, skipping failure count increase", upstream)
		return
	}

	um.failureReq[upstream] += 1
	failedCount := um.failureReq[upstream]

	// Log the updated failure count
	mainLog.Load().Debug().Msgf("upstream %q failure count updated to %d", upstream, failedCount)

	// Check if the failure count has reached the threshold to mark the upstream as down.
	if failedCount >= maxFailureRequest {
		um.down[upstream] = true
		mainLog.Load().Warn().Msgf("upstream %q marked as down (failure count: %d)", upstream, failedCount)
	} else {
		um.down[upstream] = false
	}
}

// isDown reports whether the given upstream is being marked as down.
func (um *upstreamMonitor) isDown(upstream string) bool {
	um.mu.Lock()
	defer um.mu.Unlock()

	return um.down[upstream]
}

// reset marks an upstream as up and set failed queries counter to zero.
func (um *upstreamMonitor) reset(upstream string) {
	um.mu.Lock()
	defer um.mu.Unlock()

	um.failureReq[upstream] = 0
	um.down[upstream] = false
	um.recovered[upstream] = true
	go func() {
		// debounce the recovery to avoid incrementing failure counts already in flight
		time.Sleep(1 * time.Second)
		um.mu.Lock()
		um.recovered[upstream] = false
		um.mu.Unlock()
	}()
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
		_, err := resolver.Resolve(ctx, msg)
		return err
	}
	endpoint := uc.Endpoint
	if endpoint == "" {
		endpoint = uc.Name
	}
	mainLog.Load().Warn().Msgf("upstream %q is offline", endpoint)
	for {
		if err := check(); err == nil {
			mainLog.Load().Warn().Msgf("upstream %q is online", endpoint)
			p.um.reset(upstream)
			return
		} else {
			mainLog.Load().Debug().Msgf("checked upstream %q failed: %v", endpoint, err)
		}
		time.Sleep(checkUpstreamBackoffSleep)
	}
}

// countHealthy returns the number of upstreams in the provided map that are considered healthy.
func (um *upstreamMonitor) countHealthy(upstreams []string) int {
	var count int
	um.mu.RLock()
	for _, upstream := range upstreams {
		if !um.down[upstream] {
			count++
		}
	}
	um.mu.RUnlock()
	return count
}
