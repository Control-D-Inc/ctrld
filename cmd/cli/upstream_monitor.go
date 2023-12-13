package cli

import (
	"context"
	"sync"
	"sync/atomic"
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

	down       map[string]*atomic.Bool
	failureReq map[string]*atomic.Uint64

	mu       sync.Mutex
	checking map[string]bool
}

func newUpstreamMonitor(cfg *ctrld.Config) *upstreamMonitor {
	um := &upstreamMonitor{
		cfg:        cfg,
		down:       make(map[string]*atomic.Bool),
		failureReq: make(map[string]*atomic.Uint64),
		checking:   make(map[string]bool),
	}
	for n := range cfg.Upstream {
		upstream := upstreamPrefix + n
		um.down[upstream] = new(atomic.Bool)
		um.failureReq[upstream] = new(atomic.Uint64)
	}
	um.down[upstreamOS] = new(atomic.Bool)
	um.failureReq[upstreamOS] = new(atomic.Uint64)
	return um
}

// increaseFailureCount increase failed queries count for an upstream by 1.
func (um *upstreamMonitor) increaseFailureCount(upstream string) {
	failedCount := um.failureReq[upstream].Add(1)
	um.down[upstream].Store(failedCount >= maxFailureRequest)
}

// isDown reports whether the given upstream is being marked as down.
func (um *upstreamMonitor) isDown(upstream string) bool {
	return um.down[upstream].Load()
}

// reset marks an upstream as up and set failed queries counter to zero.
func (um *upstreamMonitor) reset(upstream string) {
	um.failureReq[upstream].Store(0)
	um.down[upstream].Store(false)
}

// checkUpstream checks the given upstream status, periodically sending query to upstream
// until successfully. An upstream status/counter will be reset once it becomes reachable.
func (um *upstreamMonitor) checkUpstream(upstream string, uc *ctrld.UpstreamConfig) {
	um.mu.Lock()
	isChecking := um.checking[upstream]
	if isChecking {
		um.mu.Unlock()
		return
	}
	um.checking[upstream] = true
	um.mu.Unlock()

	resolver, err := ctrld.NewResolver(uc)
	if err != nil {
		mainLog.Load().Warn().Err(err).Msg("could not check upstream")
		return
	}
	msg := new(dns.Msg)
	msg.SetQuestion(".", dns.TypeNS)

	check := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		uc.ReBootstrap()
		_, err := resolver.Resolve(ctx, msg)
		return err
	}
	for {
		if err := check(); err == nil {
			mainLog.Load().Debug().Msgf("upstream %q is online", uc.Endpoint)
			um.reset(upstream)
			return
		}
		time.Sleep(checkUpstreamBackoffSleep)
	}
}
