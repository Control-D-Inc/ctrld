package cli

import "time"

// Suspend/resume detection without an OS notification API.
//
// A host sleep suspends the whole process: timers stop advancing and resume where they
// left off, so a tick scheduled two seconds out can arrive a minute later. That
// overshoot is the only in-process evidence that the host slept, and nothing else tells
// the DNS-intercept repair paths that the state they proved before sleep - rule text,
// resolver list, upstream connections - may no longer hold.

const (
	// suspendProbeInterval is how often the detector measures elapsed wall-clock time.
	// Short enough that a resume is noticed within a couple of seconds, which is what
	// the post-wake continuity contract measures from.
	suspendProbeInterval = 2 * time.Second

	// suspendGapThreshold is the elapsed wall clock over one interval that counts as a
	// suspend. A pfctl storm or a loaded host can stretch a tick, so this sits at
	// several times the interval; a real sleep overshoots by far more. Erring low is
	// cheap on purpose: a false positive costs one probe, and a stall this long is
	// worth a probe either way.
	suspendGapThreshold = 8 * time.Second
)

// wallNanoNow reads the wall clock in nanoseconds.
//
// The detector works in wall-clock nanoseconds rather than time.Time on purpose.
// time.Time.Sub prefers the monotonic reading whenever both operands carry one, and
// Darwin's monotonic clock stops while the host is asleep - so a monotonic difference
// across a suspend is just the tick interval and hides the very gap this looks for.
// Taking int64 wall nanos makes that mistake unrepresentable rather than a comment.
func wallNanoNow() int64 { return time.Now().UnixNano() }

// suspendDetector turns observations of a fixed-interval tick into suspend/resume
// events. It measures elapsed time rather than counting ticks, because a suspended
// process gets one late tick, not the ticks it missed.
type suspendDetector struct {
	threshold time.Duration
	wallNano  func() int64
	lastNano  int64
}

// newSuspendDetector returns a detector that reports gaps of at least threshold.
// wallNano is a seam for tests; nil means the real wall clock.
func newSuspendDetector(threshold time.Duration, wallNano func() int64) *suspendDetector {
	if wallNano == nil {
		wallNano = wallNanoNow
	}
	return &suspendDetector{threshold: threshold, wallNano: wallNano, lastNano: wallNano()}
}

// observe records a tick and reports the elapsed time when it reaches the threshold,
// which means the process was not running for most of that span.
func (d *suspendDetector) observe() (time.Duration, bool) {
	current := d.wallNano()
	gap := time.Duration(current - d.lastNano)
	d.lastNano = current
	if gap < d.threshold {
		return 0, false
	}
	return gap, true
}

// reset re-baselines the detector to the current wall clock. Time that has already
// passed is deliberately discarded rather than measured: use it after doing work
// outside the sampling loop, which is not a suspend even though it looks like one.
func (d *suspendDetector) reset() { d.lastNano = d.wallNano() }

// watchForResume calls onResume once per detected suspend/resume gap, until stopCh
// closes or tick is closed. tick is a parameter so tests can drive it directly.
//
// onResume runs on this goroutine, so recovery is serialized against detection - one
// resume cannot start a second recovery on top of the first. The cost is that no
// sampling happens while it runs, which the re-baseline below accounts for.
func watchForResume(stopCh <-chan struct{}, tick <-chan time.Time, d *suspendDetector, onResume func(gap time.Duration)) {
	for {
		select {
		case <-stopCh:
			return
		case _, ok := <-tick:
			if !ok {
				return
			}
			if gap, resumed := d.observe(); resumed {
				onResume(gap)
				// Re-baseline: the recovery just ran, and its own runtime exceeds the
				// threshold on its own (the post-wake probe schedule waits for seconds
				// before a single probe timeout or reload). The ticker keeps firing and
				// buffers a tick while it works, so without this the next observe()
				// measures the callback and reports it as a fresh suspend - which starts
				// another recovery, which is again long enough to look like a suspend.
				// Under a persistent pf failure that is an unbounded reload loop, and
				// each pass flushes pf state and kills in-flight DoH connections.
				d.reset()
			}
		}
	}
}

// runSuspendWatcher watches for suspend/resume against a real ticker.
//
//lint:ignore U1000 used on darwin (post-wake interception verification)
func runSuspendWatcher(stopCh <-chan struct{}, onResume func(gap time.Duration)) {
	ticker := time.NewTicker(suspendProbeInterval)
	defer ticker.Stop()
	watchForResume(stopCh, ticker.C, newSuspendDetector(suspendGapThreshold, nil), onResume)
}
