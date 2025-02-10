package cli

import (
	"sync"
	"time"

	"github.com/Control-D-Inc/ctrld"
)

const (
	// maxFailureRequest is the maximum failed queries allowed before an upstream is marked as down.
	maxFailureRequest = 50
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

	// failureTimerActive tracks if a timer is already running for a given upstream.
	failureTimerActive map[string]bool
}

func newUpstreamMonitor(cfg *ctrld.Config) *upstreamMonitor {
	um := &upstreamMonitor{
		cfg:                cfg,
		checking:           make(map[string]bool),
		down:               make(map[string]bool),
		failureReq:         make(map[string]uint64),
		recovered:          make(map[string]bool),
		failureTimerActive: make(map[string]bool),
	}
	for n := range cfg.Upstream {
		upstream := upstreamPrefix + n
		um.reset(upstream)
	}
	um.reset(upstreamOS)
	return um
}

// increaseFailureCount increases failed queries count for an upstream by 1 and logs debug information.
// It uses a timer to debounce failure detection, ensuring that an upstream is marked as down
// within 10 seconds if failures persist, without spawning duplicate goroutines.
func (um *upstreamMonitor) increaseFailureCount(upstream string) {
	um.mu.Lock()
	defer um.mu.Unlock()

	if um.recovered[upstream] {
		mainLog.Load().Debug().Msgf("upstream %q is recovered, skipping failure count increase", upstream)
		return
	}

	um.failureReq[upstream] += 1
	failedCount := um.failureReq[upstream]

	// Log the updated failure count.
	mainLog.Load().Debug().Msgf("upstream %q failure count updated to %d", upstream, failedCount)

	// If this is the first failure and no timer is running, start a 10-second timer.
	if failedCount == 1 && !um.failureTimerActive[upstream] {
		um.failureTimerActive[upstream] = true
		go func(upstream string) {
			time.Sleep(10 * time.Second)
			um.mu.Lock()
			defer um.mu.Unlock()
			// If no success occurred during the 10-second window (i.e. counter remains > 0)
			// and the upstream is not in a recovered state, mark it as down.
			if um.failureReq[upstream] > 0 && !um.recovered[upstream] {
				um.down[upstream] = true
				mainLog.Load().Warn().Msgf("upstream %q marked as down after 10 seconds (failure count: %d)", upstream, um.failureReq[upstream])
			}
			// Reset the timer flag so that a new timer can be spawned if needed.
			um.failureTimerActive[upstream] = false
		}(upstream)
	}

	// If the failure count quickly reaches the threshold, mark the upstream as down immediately.
	if failedCount >= maxFailureRequest {
		um.down[upstream] = true
		mainLog.Load().Warn().Msgf("upstream %q marked as down immediately (failure count: %d)", upstream, failedCount)
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
	um.failureReq[upstream] = 0
	um.down[upstream] = false
	um.recovered[upstream] = true
	um.mu.Unlock()
	go func() {
		// debounce the recovery to avoid incrementing failure counts already in flight
		time.Sleep(1 * time.Second)
		um.mu.Lock()
		um.recovered[upstream] = false
		um.mu.Unlock()
	}()
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
