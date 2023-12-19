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

// reset marks an upstream as up and set failed queries counter to zero.
func (um *upstreamMonitor) reset(upstream string) {
	um.mu.Lock()
	defer um.mu.Unlock()

	um.failureReq[upstream] = 0
	um.down[upstream] = false
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
	defer func() {
		um.mu.Lock()
		um.checking[upstream] = false
		um.mu.Unlock()
	}()

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
