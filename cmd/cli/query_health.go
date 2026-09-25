package cli

import (
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/Control-D-Inc/ctrld"
)

// Health classes of the query path. The names go into the journal.
const (
	queryHealthHealthy  = "healthy"
	queryHealthDegraded = "degraded"
	queryHealthFailing  = "failing"
)

const (
	// queryHealthWindow is the length of one counting window and the time
	// between two heartbeats.
	queryHealthWindow = 15 * time.Minute
	// queryHealthFailingRatio and queryHealthDegradedRatio grade the failed
	// share of a window.
	queryHealthFailingRatio  = 0.5
	queryHealthDegradedRatio = 0.05
	// queryHealthFailingQueries is the smallest sample that can leave the
	// healthy class and the smallest sample that can report a class change.
	queryHealthFailingQueries = 10
	// queryHealthClassTicks is the number of ticks in a row that a new class
	// must hold before it reports.
	queryHealthClassTicks = 2
	// queryHealthMessage names the journal event of the tracker.
	queryHealthMessage = "Query health"
)

// queryHealthTick is the time between two evaluations. A test shortens it.
var queryHealthTick = time.Minute

// queryHealth grades the query path over a window. Support reads the grade
// after an incident, so the journal needs one class per window instead of a
// line per query.
type queryHealth struct {
	mu          sync.Mutex
	window      time.Duration
	now         func() time.Time
	windowStart time.Time
	queries     uint64
	cacheHits   uint64
	// failedQueries counts the client queries that ended without an answer.
	// The grade follows this count, and failures holds the sampler classes
	// behind it, which raise several events for one failed query.
	failedQueries uint64
	failures      map[string]uint64
	lastClass     string
	// pendingClass is the class that the last tick graded, and pendingTicks
	// counts how many ticks in a row graded it. A class reports only after it
	// held, so one noisy minute opens no event.
	pendingClass string
	pendingTicks int
}

// queryHealthEvent holds the class and the counters of one window.
type queryHealthEvent struct {
	Class         string
	WindowSeconds int
	Queries       uint64
	CacheHits     uint64
	FailedQueries uint64
	Failures      map[string]uint64
	UpstreamsDown int
	BypassActive  bool
	CacheHitRatio float64
}

func newQueryHealth() *queryHealth {
	return &queryHealth{
		window:   queryHealthWindow,
		now:      time.Now,
		failures: make(map[string]uint64),
	}
}

// A prog outside a run holds no tracker, so every counter of the query path
// and every loop accepts a nil receiver.
func (q *queryHealth) countQuery() {
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.queries++
}

func (q *queryHealth) countCacheHit() {
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.cacheHits++
}

// countFailedQuery counts one client query that ended without an answer. A
// query that failed on several upstreams counts once, because the grade
// measures the service the client got.
func (q *queryHealth) countFailedQuery() {
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.failedQueries++
}

func (q *queryHealth) countFailure(class string) {
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.failures == nil {
		q.failures = make(map[string]uint64)
	}
	q.failures[class]++
}

// evaluate grades the counters and reports whether the event goes out. The
// report covers the window that just closed, or the running one. The window
// starts at the first evaluate, so the caller owns the clock.
func (q *queryHealth) evaluate(now time.Time, upstreamsDown int, bypassActive bool) (queryHealthEvent, bool) {
	if q == nil {
		return queryHealthEvent{}, false
	}
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.windowStart.IsZero() {
		q.windowStart = now
	}
	event := queryHealthEvent{
		Class:         healthClass(q.queries, q.failedQueries),
		WindowSeconds: int(q.window / time.Second),
		Queries:       q.queries,
		CacheHits:     q.cacheHits,
		FailedQueries: q.failedQueries,
		Failures:      copyFailures(q.failures),
		UpstreamsDown: upstreamsDown,
		BypassActive:  bypassActive,
		CacheHitRatio: shareOf(q.cacheHits, q.queries),
	}
	// The end of a window always reports, so a quiet daemon stays visible and
	// no window is lost after an early report. A class change waits for a
	// sample and for a second tick.
	windowEnded := !now.Before(q.windowStart.Add(q.window))
	emit := q.lastClass == "" || windowEnded || q.classChangeHolds(event.Class)
	if emit {
		q.lastClass = event.Class
		q.pendingClass, q.pendingTicks = "", 0
	}
	if windowEnded {
		q.startWindow(now)
	}
	return event, emit
}

// classChangeHolds reports whether a new class may open an event. It needs a
// window with enough queries, and the same class on two ticks in a row. The
// caller holds the lock.
func (q *queryHealth) classChangeHolds(class string) bool {
	if class == q.lastClass || q.queries < queryHealthFailingQueries {
		q.pendingClass, q.pendingTicks = "", 0
		return false
	}
	if class != q.pendingClass {
		q.pendingClass, q.pendingTicks = class, 1
		return false
	}
	q.pendingTicks++
	return q.pendingTicks >= queryHealthClassTicks
}

// startWindow drops the counters of the window that closed. Each report covers
// one window, so a quiet hour cannot hide inside the totals of a busy one. The
// caller holds the lock.
func (q *queryHealth) startWindow(now time.Time) {
	q.windowStart = now
	q.queries = 0
	q.cacheHits = 0
	q.failedQueries = 0
	q.failures = make(map[string]uint64)
}

func (q *queryHealth) log(event queryHealthEvent) {
	if q == nil {
		return
	}
	journal(mainLog.Load().Info()).
		Str("class", event.Class).
		Int("window_s", event.WindowSeconds).
		Uint64("queries", event.Queries).
		Uint64("cache_hits", event.CacheHits).
		Uint64("failed_queries", event.FailedQueries).
		Dict("failures_by_class", failuresDict(event.Failures)).
		Int("upstreams_down", event.UpstreamsDown).
		Bool("bypass_active", event.BypassActive).
		Float64("cache_hit_ratio", event.CacheHitRatio).
		Msg(queryHealthMessage)
}

// startLoop runs the grading loop and returns a channel that closes when the
// loop returns. A caller joins that channel before it reads the log.
func (q *queryHealth) startLoop(stop <-chan struct{}, inputs func() (upstreamsDown int, bypassActive bool)) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		q.loop(stop, inputs)
	}()
	return done
}

// loop grades the counters on every tick until the caller stops it.
func (q *queryHealth) loop(stop <-chan struct{}, inputs func() (upstreamsDown int, bypassActive bool)) {
	if q == nil {
		return
	}
	ticker := time.NewTicker(queryHealthTick)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			upstreamsDown, bypassActive := inputs()
			event, emit := q.evaluate(q.now(), upstreamsDown, bypassActive)
			if !emit {
				continue
			}
			q.log(event)
		}
	}
}

// healthClass grades the failed share of a window. A small sample stays
// healthy, because a few failures at a start are not an outage.
func healthClass(queries, failures uint64) string {
	if queries < queryHealthFailingQueries {
		return queryHealthHealthy
	}
	failed := shareOf(failures, queries)
	if failed >= queryHealthFailingRatio {
		return queryHealthFailing
	}
	if failed >= queryHealthDegradedRatio {
		return queryHealthDegraded
	}
	return queryHealthHealthy
}

// shareOf reports the part of the total, and 0 for an empty total.
func shareOf(part, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return float64(part) / float64(total)
}

// copyFailures gives the report its own map, because the counters keep running
// while the caller holds the report.
func copyFailures(failures map[string]uint64) map[string]uint64 {
	copied := make(map[string]uint64, len(failures))
	maps.Copy(copied, failures)
	return copied
}

// failuresDict renders the classes in a stable order, so two lines of the same
// window compare by eye.
func failuresDict(failures map[string]uint64) *ctrld.LogEvent {
	dict := ctrld.Dict()
	for _, class := range slices.Sorted(maps.Keys(failures)) {
		dict = dict.Uint64(class, failures[class])
	}
	return dict
}
