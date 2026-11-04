package cli

import (
	"maps"
	"slices"
	"sync"
	"tailscale.com/net/netmon"
	"time"
)

// noiseSummaryInterval bounds a storm of noise deltas to one journal line,
// because AirDrop and virtual adapters can churn for hours.
const noiseSummaryInterval = 10 * time.Minute

// wakeReportInterval merges the reports of the wake sources. netmon polls for
// a time jump every 15 s, so one wake can reach ctrld over half a minute.
const wakeReportInterval = 30 * time.Second

// repeatLogger holds the last value of each named line, so a line that
// repeats every few seconds reaches the log on change only.
type repeatLogger struct {
	mu      sync.Mutex
	last    map[string]string
	repeats map[string]uint64
}

// changed reports whether the value of a key differs from the value before it.
// The repeat count tells how many lines the caller held back, so the next line
// it writes can carry them.
func (r *repeatLogger) changed(key, value string) (changed bool, repeats uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.last == nil {
		r.last = make(map[string]string)
		r.repeats = make(map[string]uint64)
	}
	if previous, seen := r.last[key]; seen && previous == value {
		r.repeats[key]++
		return false, r.repeats[key]
	}
	repeats = r.repeats[key]
	r.last[key] = value
	r.repeats[key] = 0
	return true, repeats
}

// wakeHoldInterval is the time that a wake report without a gap waits for the
// detector. The detector ticks every two seconds, so it reports well inside
// this hold when it runs.
const wakeHoldInterval = 8 * time.Second

// wakeReport is one wake as a source saw it.
type wakeReport struct {
	source string
	gap    time.Duration
	state  *netmon.State
}

// wakeReporter keeps one report per wake. netmon measures no gap, so its
// report waits for the detector, which measures one. When no detector report
// comes, the held report goes out as it is.
type wakeReporter struct {
	mu   sync.Mutex
	last time.Time
	held *wakeReport
	// after arms the hold timer. nil means time.AfterFunc, and a test fires
	// the hold itself.
	after func(time.Duration, func())
}

// note takes one report of a wake and hands the report that the journal gets
// to emit. The first source of a window reports. A report with a gap replaces
// a held report without one. Every other report of the window is the same
// wake and drops.
func (w *wakeReporter) note(now time.Time, report wakeReport, emit func(wakeReport)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	gapKnown := report.gap > 0
	if !w.last.IsZero() && now.Sub(w.last) < wakeReportInterval {
		if w.held != nil && gapKnown {
			w.held = nil
			emit(report)
		}
		return
	}
	w.last = now
	if gapKnown {
		w.held = nil
		emit(report)
		return
	}
	held := &wakeReport{source: report.source, gap: report.gap, state: report.state}
	w.held = held
	w.afterFunc()(wakeHoldInterval, func() { w.release(held, emit) })
}

// release emits a held report when no source with a gap replaced it.
func (w *wakeReporter) release(held *wakeReport, emit func(wakeReport)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.held != held {
		return
	}
	w.held = nil
	emit(*held)
}

func (w *wakeReporter) afterFunc() func(time.Duration, func()) {
	if w.after != nil {
		return w.after
	}
	return func(d time.Duration, fn func()) { time.AfterFunc(d, fn) }
}

// noiseSummary describes the noise deltas that one journal line covers.
type noiseSummary struct {
	Count      int
	First      time.Time
	Last       time.Time
	Interfaces []string
}

// noiseCoalescer counts the noise deltas of a storm and reports when the
// journal needs a line for them. The count, the first time, and the names
// cover the open window; last covers the storm, so a quiet period ends it.
type noiseCoalescer struct {
	mu      sync.Mutex
	count   int
	first   time.Time
	last    time.Time
	emitted time.Time
	names   map[string]struct{}
}

// add records one noise delta and reports whether to log a summary now. The
// summary covers the deltas since the last one, so a storm of any length
// keeps to one line per interval.
func (c *noiseCoalescer) add(interfaces []string, now time.Time) (summary noiseSummary, emit bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	newRun := c.stormEnded(now)
	if newRun {
		c.clearWindow()
	}
	c.record(interfaces, now)
	if !newRun && now.Sub(c.emitted) < noiseSummaryInterval {
		return noiseSummary{}, false
	}
	summary = c.summary()
	c.emitted = now
	c.clearWindow()
	return summary, true
}

// flush reports the open window and closes it. A storm ends with a delta that
// the daemon acts on, so the last window of the storm reaches the journal
// there instead of waiting for the next storm.
func (c *noiseCoalescer) flush(now time.Time) (summary noiseSummary, emit bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.count == 0 {
		return noiseSummary{}, false
	}
	summary = c.summary()
	c.emitted = now
	c.clearWindow()
	return summary, true
}

// stormEnded is true when the deltas stopped for longer than the interval, so
// a new storm does not inherit the count of the storm before it.
func (c *noiseCoalescer) stormEnded(now time.Time) bool {
	return c.last.IsZero() || now.Sub(c.last) > noiseSummaryInterval
}

func (c *noiseCoalescer) record(interfaces []string, now time.Time) {
	if c.count == 0 {
		c.first = now
	}
	c.count++
	c.last = now
	if c.names == nil {
		c.names = make(map[string]struct{})
	}
	for _, name := range interfaces {
		c.names[name] = struct{}{}
	}
}

// summary sorts the names, because a log line that keeps its order reads as
// one value across a capture.
func (c *noiseCoalescer) summary() noiseSummary {
	return noiseSummary{
		Count:      c.count,
		First:      c.first,
		Last:       c.last,
		Interfaces: slices.Sorted(maps.Keys(c.names)),
	}
}

func (c *noiseCoalescer) clearWindow() {
	c.count = 0
	c.first = time.Time{}
	c.names = nil
}
