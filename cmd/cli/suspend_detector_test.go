package cli

import (
	"testing"
	"time"
)

// fakeWallClock returns the queued offsets from a fixed base, then repeats the last one.
type fakeWallClock struct {
	nanos []int64
	calls int
}

func (c *fakeWallClock) now() int64 {
	if c.calls < len(c.nanos) {
		n := c.nanos[c.calls]
		c.calls++
		return n
	}
	return c.nanos[len(c.nanos)-1]
}

// wallClockAt builds a clock whose readings are the given offsets from an arbitrary
// epoch. The first reading is consumed by newSuspendDetector; the rest are ticks.
func wallClockAt(offsets ...time.Duration) *fakeWallClock {
	const base = int64(1787081656_000000000) // 2026-08-18T14:34:16-05:00
	nanos := make([]int64, 0, len(offsets))
	for _, off := range offsets {
		nanos = append(nanos, base+int64(off))
	}
	return &fakeWallClock{nanos: nanos}
}

func TestSuspendDetectorIgnoresOrdinaryTicks(t *testing.T) {
	// Construction, then three ticks two seconds apart, one stretched to 3s by a
	// loaded host. None of these is a suspend.
	clock := wallClockAt(0, 2*time.Second, 4*time.Second, 7*time.Second)
	d := newSuspendDetector(suspendGapThreshold, clock.now)

	for i := 0; i < 3; i++ {
		if gap, resumed := d.observe(); resumed {
			t.Errorf("tick %d reported a suspend of %s; ordinary jitter must not count", i, gap)
		}
	}
}

// TestSuspendDetectorReportsTheGapOnce replays the captured incident: the last pre-sleep
// sample at 14:34:47 and the first post-resume one at 14:35:05.
func TestSuspendDetectorReportsTheGapOnce(t *testing.T) {
	clock := wallClockAt(
		31*time.Second, // construction, 14:34:47
		33*time.Second, // ordinary tick
		49*time.Second, // 14:35:05 - a 16s gap over a 2s interval
		51*time.Second, // ordinary again
	)
	d := newSuspendDetector(suspendGapThreshold, clock.now)

	if _, resumed := d.observe(); resumed {
		t.Fatal("the tick before the suspend reported a resume")
	}
	gap, resumed := d.observe()
	if !resumed {
		t.Fatal("a 16s gap over a 2s interval was not reported as a suspend")
	}
	if gap != 16*time.Second {
		t.Errorf("gap = %s, want 16s: the reported gap must be the measured wall clock", gap)
	}
	if _, resumed := d.observe(); resumed {
		t.Error("the resume was reported twice; the baseline must advance to the late tick")
	}
}

// TestSuspendDetectorThresholdCoversShortNaps guards the lower bound. A nap only a few
// seconds longer than the interval still breaks pf translation, so the threshold must not
// drift up to a value that only catches long sleeps.
func TestSuspendDetectorThresholdCoversShortNaps(t *testing.T) {
	if suspendGapThreshold > 10*time.Second {
		t.Errorf("suspendGapThreshold = %s; a short nap would go unnoticed", suspendGapThreshold)
	}
	if suspendGapThreshold <= 2*suspendProbeInterval {
		t.Errorf("suspendGapThreshold = %s is too close to the %s interval; ordinary jitter would fire it",
			suspendGapThreshold, suspendProbeInterval)
	}

	clock := wallClockAt(0, suspendGapThreshold)
	d := newSuspendDetector(suspendGapThreshold, clock.now)
	if _, resumed := d.observe(); !resumed {
		t.Error("a gap exactly at the threshold was not reported")
	}
}

func TestSuspendDetectorIgnoresBackwardClockSteps(t *testing.T) {
	// An NTP step backwards must not read as a resume, and must not leave the baseline
	// in the future either: the next ordinary tick still has to look ordinary.
	clock := wallClockAt(0, -30*time.Second, -28*time.Second)
	d := newSuspendDetector(suspendGapThreshold, clock.now)

	if gap, resumed := d.observe(); resumed {
		t.Errorf("a backward clock step reported a suspend of %s", gap)
	}
	if gap, resumed := d.observe(); resumed {
		t.Errorf("the tick after a backward step reported a suspend of %s", gap)
	}
}

func TestWatchForResumeCallsBackPerGap(t *testing.T) {
	clock := wallClockAt(
		0,
		2*time.Second,  // ordinary
		40*time.Second, // resume: 38s
		42*time.Second, // ordinary
		99*time.Second, // second resume: 57s
	)
	d := newSuspendDetector(suspendGapThreshold, clock.now)

	tick := make(chan time.Time, 4)
	for i := 0; i < 4; i++ {
		tick <- time.Time{}
	}
	close(tick)

	var gaps []time.Duration
	watchForResume(nil, tick, d, func(gap time.Duration) { gaps = append(gaps, gap) })

	if len(gaps) != 2 {
		t.Fatalf("onResume called %d times (%v), want 2", len(gaps), gaps)
	}
	if gaps[0] != 38*time.Second || gaps[1] != 57*time.Second {
		t.Errorf("gaps = %v, want [38s 57s]", gaps)
	}
}

// advancingClock is a wall clock the test moves by hand, so a callback's runtime can be
// simulated without sleeping for it.
type advancingClock struct{ nano int64 }

func (c *advancingClock) now() int64              { return c.nano }
func (c *advancingClock) advance(d time.Duration) { c.nano += int64(d) }

// TestWatchForResumeDoesNotRetriggerOnItsOwnCallback pins the loop this closes. onResume
// runs on the watcher goroutine, and the real callback - verifyInterceptAfterWake - takes
// longer than the gap threshold by design: its configured waits alone total more than the
// threshold, before any probe timeout or forced reload. The ticker buffers a tick while it
// works, so a detector that keeps its pre-callback baseline measures the callback itself as
// the next gap and starts another recovery, with another repair budget, indefinitely under
// a persistent pf failure.
func TestWatchForResumeDoesNotRetriggerOnItsOwnCallback(t *testing.T) {
	clock := &advancingClock{}
	d := newSuspendDetector(suspendGapThreshold, clock.now)

	// Capacity 1, like time.Ticker's channel: exactly one tick can queue up behind a
	// callback in production.
	tick := make(chan time.Time, 1)
	calls := 0
	done := make(chan struct{})
	go func() {
		defer close(done)
		watchForResume(nil, tick, d, func(time.Duration) {
			calls++
			if calls > 1 {
				// A retrigger - the failure this test reports. There is nothing left to
				// simulate, and tick is already closed.
				return
			}
			// The recovery takes longer than the threshold, and a tick lands while it
			// runs. Closing here ends the watcher after it drains that queued tick,
			// which is the observation under test.
			clock.advance(2 * suspendGapThreshold)
			tick <- time.Time{}
			close(tick)
		})
	}()

	clock.advance(2 * suspendGapThreshold) // the genuine suspend
	tick <- time.Time{}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchForResume did not finish; the queued tick was never consumed")
	}

	if calls != 1 {
		t.Errorf("onResume called %d times, want 1: the callback's own runtime was measured as a second suspend", calls)
	}
}

func TestWatchForResumeStopsOnStopCh(t *testing.T) {
	stopCh := make(chan struct{})
	tick := make(chan time.Time) // never fires
	clock := wallClockAt(0, time.Hour)
	d := newSuspendDetector(suspendGapThreshold, clock.now)

	done := make(chan struct{})
	go func() {
		watchForResume(stopCh, tick, d, func(time.Duration) {
			t.Error("onResume ran without a tick")
		})
		close(done)
	}()

	close(stopCh)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchForResume did not return once stopCh was closed")
	}
}
