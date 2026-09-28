package cli

import (
	"sync"
	"time"

	"github.com/Control-D-Inc/ctrld"
)

// Classes of per-query errors. Each class keeps its own budget per upstream.
const (
	sampleClassResolveFailed      = "resolve_failed"
	sampleClassAllEndpointsFailed = "all_endpoints_failed"
	sampleClassSendResponseFailed = "send_response_failed"
	// sampleClassInternalDomain names a failure of an Internal Domain resolver.
	// It stays apart from the other classes, because an endpoint away from the
	// organization network cannot reach such a resolver.
	sampleClassInternalDomain = "internal_domain"
)

const (
	// querySampleLimit is the number of lines that stay at error level in one window.
	querySampleLimit = 5
	// querySampleWindow is the length of a window. It starts at the first error of the window.
	querySampleWindow = 60 * time.Second
)

// sampleKey identifies one budget.
type sampleKey struct {
	class    string
	upstream string
}

// sampleWindow counts the events of one budget between its start and its end.
type sampleWindow struct {
	start      time.Time
	count      int
	suppressed int
	timer      *time.Timer
}

// ended reports whether the window closed at or before now.
func (w *sampleWindow) ended(now time.Time) bool {
	return !now.Before(w.start.Add(querySampleWindow))
}

// sampleSummary holds what one closed window reports.
type sampleSummary struct {
	key        sampleKey
	count      int
	suppressed int
}

// errorSampler bounds the noise of a repeated per-query error. It lowers the
// level of a line, never its presence, so the debug stream stays complete.
// The console and the log_path file show the lowered lines at debug level only.
// The zero value is ready to use.
type errorSampler struct {
	mu      sync.Mutex
	windows map[sampleKey]*sampleWindow
	now     func() time.Time
	after   func(time.Duration, func()) *time.Timer
	// onFailure counts the event for the query health tracker. The daemon sets
	// it once at start, before a listener serves a query.
	onFailure func(class string)
}

// event returns the event a call site logs with. The first querySampleLimit
// events of a window come back at error level, the later ones at debug level.
// The caller adds its own fields and the message.
func (s *errorSampler) event(class, upstream string) *ctrld.LogEvent {
	key := sampleKey{class: class, upstream: upstream}

	s.mu.Lock()
	now := s.clock()
	var summaries []sampleSummary
	window := s.windows[key]
	if window != nil && window.ended(now) {
		summaries = appendWindowSummary(summaries, key, window)
		s.dropWindow(key, window)
		window = nil
	}
	if window == nil {
		window = s.startWindow(key, now)
	}
	window.count++
	suppressed := window.count > querySampleLimit
	if suppressed {
		window.suppressed++
	}
	s.mu.Unlock()

	// A lowered line keeps its place in the breakdown of the window. It is one
	// event, not one failed query, so it does not change the grade.
	if s.onFailure != nil {
		s.onFailure(class)
	}
	s.logSummaries(summaries)

	if suppressed {
		return mainLog.Load().Debug()
	}
	return mainLog.Load().Error()
}

// closeExpired closes every window that ended at or before now. The window
// timer calls it, so an idle window reports without a new event.
func (s *errorSampler) closeExpired(now time.Time) {
	s.mu.Lock()
	var summaries []sampleSummary
	for key, window := range s.windows {
		if !window.ended(now) {
			continue
		}
		summaries = appendWindowSummary(summaries, key, window)
		s.dropWindow(key, window)
	}
	s.mu.Unlock()

	s.logSummaries(summaries)
}

// startWindow opens a window and arms the timer that closes it. The caller holds the lock.
func (s *errorSampler) startWindow(key sampleKey, start time.Time) *sampleWindow {
	if s.windows == nil {
		s.windows = make(map[sampleKey]*sampleWindow)
	}
	window := &sampleWindow{start: start}
	s.windows[key] = window
	window.timer = s.afterFunc()(querySampleWindow, func() { s.closeExpired(s.clock()) })
	return window
}

// dropWindow forgets a window and stops its timer. The caller holds the lock.
func (s *errorSampler) dropWindow(key sampleKey, window *sampleWindow) {
	if window.timer != nil {
		window.timer.Stop()
	}
	delete(s.windows, key)
}

// logSummaries reports the closed windows. The caller released the lock first,
// because the logger writes back through code that can take it again.
func (s *errorSampler) logSummaries(summaries []sampleSummary) {
	for _, summary := range summaries {
		mainLog.Load().Error().
			Str("class", summary.key.class).
			Str("upstream", journalUpstreamName(summary.key.upstream)).
			Int("count", summary.count).
			Int("suppressed", summary.suppressed).
			Int("window_s", int(querySampleWindow/time.Second)).
			Msg("Per-query errors sampled")
	}
}

// clock reads the time of the sampler. A test sets its own clock, so a window
// closes without a wait.
func (s *errorSampler) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *errorSampler) afterFunc() func(time.Duration, func()) *time.Timer {
	if s.after != nil {
		return s.after
	}
	return time.AfterFunc
}

// appendWindowSummary keeps the windows that suppressed at least one line.
func appendWindowSummary(summaries []sampleSummary, key sampleKey, window *sampleWindow) []sampleSummary {
	if window.suppressed == 0 {
		return summaries
	}
	return append(summaries, sampleSummary{key: key, count: window.count, suppressed: window.suppressed})
}
