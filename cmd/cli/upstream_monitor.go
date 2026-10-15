package cli

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Control-D-Inc/ctrld"
)

const (
	// maxFailureRequest is the maximum failed queries allowed before an upstream is marked as down.
	maxFailureRequest = 50
	// checkUpstreamBackoffSleep is the time interval between each upstream checks.
	checkUpstreamBackoffSleep = 2 * time.Second
	// checkUpstreamUnreachableBackoffMax caps the recovery retry interval for an
	// endpoint that keeps failing with a network-unreachable error. It bounds
	// the backoff so an unroutable endpoint is still re-probed periodically and
	// recovers once the route returns.
	checkUpstreamUnreachableBackoffMax = 60 * time.Second
	// upstreamDownDelay is the time that the failures of an upstream must last
	// before the monitor marks it down.
	upstreamDownDelay = 10 * time.Second
	// upstreamRecoveredDelay is the time that a reset holds back the failure
	// counts of an upstream.
	upstreamRecoveredDelay = 1 * time.Second
)

// unreachableRecoveryBackoff returns the retry interval for the given streak of
// consecutive network-unreachable failures. It starts at checkUpstreamBackoffSleep
// and doubles each attempt, capped at checkUpstreamUnreachableBackoffMax.
func unreachableRecoveryBackoff(streak int) time.Duration {
	d := checkUpstreamBackoffSleep
	for i := 1; i < streak; i++ {
		d *= 2
		if d >= checkUpstreamUnreachableBackoffMax {
			return checkUpstreamUnreachableBackoffMax
		}
	}
	return d
}

// upstreamDownState remembers when an upstream went down and how many
// failures put it there, so the up event can report the outage.
type upstreamDownState struct {
	since    time.Time
	failures uint64
}

// upstreamMonitor performs monitoring upstreams health.
type upstreamMonitor struct {
	cfg    *ctrld.Config
	logger atomic.Pointer[ctrld.Logger]

	mu sync.RWMutex
	// down holds one entry for each upstream that is down now.
	down       map[string]upstreamDownState
	checking   map[string]bool
	failureReq map[string]uint64
	recovered  map[string]bool

	// failureTimerActive tracks if a timer is already running for a given upstream.
	failureTimerActive map[string]bool
	// retired is set when a reload replaced this monitor. A timer that was
	// armed before the reload must not open an outage that nothing closes.
	retired bool

	// now is a seam, so a test can set the reported down time.
	now func() time.Time
	// after arms a one-shot timer, so a test fires the check itself instead of
	// waiting for it. nil means time.AfterFunc.
	after func(time.Duration, func())
}

// afterFunc returns the timer seam. A real timer drops its handle, because
// nothing stops these checks.
func (um *upstreamMonitor) afterFunc() func(time.Duration, func()) {
	if um.after != nil {
		return um.after
	}
	return func(d time.Duration, fn func()) { time.AfterFunc(d, fn) }
}

// newUpstreamMonitor creates a new upstream monitor instance
func newUpstreamMonitor(cfg *ctrld.Config, logger *ctrld.Logger) *upstreamMonitor {
	um := &upstreamMonitor{
		cfg:                cfg,
		checking:           make(map[string]bool),
		down:               make(map[string]upstreamDownState),
		failureReq:         make(map[string]uint64),
		recovered:          make(map[string]bool),
		failureTimerActive: make(map[string]bool),
		now:                time.Now,
	}
	um.logger.Store(logger)
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

	if um.retired {
		return
	}
	if um.recovered[upstream] {
		um.logger.Load().Debug().Msgf("Upstream %q is recovered, skipping failure count increase", upstream)
		return
	}

	um.failureReq[upstream] += 1
	failedCount := um.failureReq[upstream]

	// Log the updated failure count.
	um.logger.Load().Debug().Msgf("Upstream %q failure count updated to %d", upstream, failedCount)

	// If this is the first failure and no timer is running, start the timer.
	if failedCount == 1 && !um.failureTimerActive[upstream] {
		um.failureTimerActive[upstream] = true
		um.afterFunc()(upstreamDownDelay, func() { um.markDownAfterDelay(upstream) })
	}

	// If the failure count quickly reaches the threshold, mark the upstream as down immediately.
	if failedCount >= maxFailureRequest {
		um.markDown(upstream, failedCount, "immediate")
	}
}

// markDownAfterDelay marks an upstream down when its failures did not clear
// while the timer ran. A success during that time leaves the count at zero.
func (um *upstreamMonitor) markDownAfterDelay(upstream string) {
	um.mu.Lock()
	defer um.mu.Unlock()
	if um.retired {
		return
	}
	if um.failureReq[upstream] > 0 && !um.recovered[upstream] {
		um.markDown(upstream, um.failureReq[upstream], "timer")
	}
	// The next failure of this upstream can arm a new timer.
	um.failureTimerActive[upstream] = false
}

// markDown marks an upstream as down and logs the transition once. The caller holds the lock.
func (um *upstreamMonitor) markDown(upstream string, failures uint64, reason string) {
	if um.retired {
		return
	}
	if _, down := um.down[upstream]; down {
		return
	}
	um.down[upstream] = upstreamDownState{since: um.now(), failures: failures}
	journal(um.logger.Load().Warn()).
		Str("upstream", journalUpstreamName(upstream)).
		Str("state", "down").
		Uint64("failure_count", failures).
		Str("reason", reason).
		Msg("Upstream state changed")
}

// markUp marks an upstream as up and logs the transition once. The caller holds the lock.
func (um *upstreamMonitor) markUp(upstream, reason string) {
	state, down := um.down[upstream]
	if !down {
		return
	}
	delete(um.down, upstream)
	journal(um.logger.Load().Info()).
		Str("upstream", journalUpstreamName(upstream)).
		Str("state", "up").
		Str("reason", reason).
		Int64("down_for_ms", um.now().Sub(state.since).Milliseconds()).
		Uint64("failure_count", state.failures).
		Msg("Upstream state changed")
}

// journalUpstreamName bounds the upstream name that a journal event carries.
// ctrld generates upstream.os, upstream.<n>, and upstream.internal_<n>; every
// other key is operator text that can hold a token, so it reads as
// upstream.custom. An empty name holds no operator text and stays empty,
// because a line that names no upstream must not read as a custom one.
func journalUpstreamName(upstream string) string {
	if upstream == "" || upstream == upstreamOS || generatedUpstreamKey(strings.TrimPrefix(upstream, upstreamPrefix)) {
		return upstream
	}
	return upstreamPrefix + "custom"
}

// journalUpstreamNames bounds every name of a list, for a line that names
// several upstreams.
func journalUpstreamNames(upstreams []string) []string {
	names := make([]string, 0, len(upstreams))
	for _, upstream := range upstreams {
		names = append(names, journalUpstreamName(upstream))
	}
	return names
}

// generatedUpstreamKey reports whether key is a number, or internal_ and a
// number, the two shapes that ctrld writes itself.
func generatedUpstreamKey(key string) bool {
	digits := strings.TrimPrefix(key, internalDomainUpstreamPrefix)
	if digits == "" {
		return false
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// retire closes the outage of every upstream that is still down and stops
// every later state change. A reload builds a new monitor, so the journal ends
// the outages of the old one, and the old timers must not open new ones.
func (um *upstreamMonitor) retire() {
	um.mu.Lock()
	defer um.mu.Unlock()
	for upstream := range um.down {
		um.markUp(upstream, "reload")
	}
	um.retired = true
	clear(um.failureReq)
	clear(um.failureTimerActive)
}

// noteSuccess records an answer from an upstream. It does not set the recovered
// flag, because that flag stops failure counts for one second and an answer
// must not hide the failures that follow it.
func (um *upstreamMonitor) noteSuccess(upstream string) {
	um.mu.Lock()
	defer um.mu.Unlock()

	um.failureReq[upstream] = 0
	um.markUp(upstream, "recovered")
}

// countDown reports how many upstreams are down at this time.
func (um *upstreamMonitor) countDown() int {
	um.mu.RLock()
	defer um.mu.RUnlock()
	return len(um.down)
}

// countDownExcept reports how many upstreams are down at this time, without
// the ones that skip accepts. The grade of the query path leaves out the
// resolvers that only an endpoint on the organization network can reach.
func (um *upstreamMonitor) countDownExcept(skip func(string) bool) int {
	if skip == nil {
		return um.countDown()
	}
	um.mu.RLock()
	defer um.mu.RUnlock()
	count := 0
	for upstream := range um.down {
		if skip(upstream) {
			continue
		}
		count++
	}
	return count
}

// downFor reports how long an upstream has been down. An upstream that is up
// gives zero, so a caller logs the field without a branch.
func (um *upstreamMonitor) downFor(upstream string) time.Duration {
	um.mu.RLock()
	defer um.mu.RUnlock()
	state, down := um.down[upstream]
	if !down {
		return 0
	}
	return um.now().Sub(state.since)
}

// isDown reports whether the given upstream is being marked as down.
func (um *upstreamMonitor) isDown(upstream string) bool {
	um.mu.Lock()
	defer um.mu.Unlock()

	_, down := um.down[upstream]
	return down
}

// reset marks an upstream as up and set failed queries counter to zero.
func (um *upstreamMonitor) reset(upstream string) {
	um.mu.Lock()
	um.failureReq[upstream] = 0
	um.markUp(upstream, "recovered")
	um.recovered[upstream] = true
	um.mu.Unlock()
	// The flag holds back the failure counts that are already in flight.
	um.afterFunc()(upstreamRecoveredDelay, func() { um.clearRecovered(upstream) })
}

// clearRecovered lets the failures of an upstream count again.
func (um *upstreamMonitor) clearRecovered(upstream string) {
	um.mu.Lock()
	defer um.mu.Unlock()
	um.recovered[upstream] = false
}

// countHealthy returns the number of upstreams in the provided map that are considered healthy.
func (um *upstreamMonitor) countHealthy(upstreams []string) int {
	var count int
	um.mu.RLock()
	for _, upstream := range upstreams {
		if _, down := um.down[upstream]; !down {
			count++
		}
	}
	um.mu.RUnlock()
	return count
}
