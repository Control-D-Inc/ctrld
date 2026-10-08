package cli

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Control-D-Inc/ctrld"
)

// queryHealthBase is the start time of every tracker test. The tracker takes
// the time from the caller, so no test waits for a real clock.
var queryHealthBase = time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)

// feedQueryHealth counts queries, and one failed query for each failure of a
// class. The grade follows the failed queries, so a test that wants a class
// gives the failures that produced it.
func feedQueryHealth(q *queryHealth, queries int, failures map[string]int) {
	for i := 0; i < queries; i++ {
		q.countQuery()
	}
	for class, count := range failures {
		for i := 0; i < count; i++ {
			q.countFailure(class)
			q.countFailedQuery()
		}
	}
}

// waitForLogLine polls the buffer, because the loop logs from its own goroutine.
func waitForLogLine(t *testing.T, logs *syncBuffer, message string) {
	t.Helper()
	waitForLogLineOrExplain(t, logs, message, nil)
}

// waitForLogLineOrExplain is waitForLogLine with extra text for the failure.
func waitForLogLineOrExplain(t *testing.T, logs *syncBuffer, message string, explain func() string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(logs.String(), message) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	extra := ""
	if explain != nil {
		extra = " " + explain()
	}
	t.Fatalf("no %q line before the deadline (captured %q)%s", message, logs.String(), extra)
}

// loggerSwapRecord is one change of the main logger.
type loggerSwapRecord struct {
	at     time.Duration
	writer string
}

// watchLoggerSwaps records every change of the main logger while the test
// runs, so a missing line names what took the logger.
func watchLoggerSwaps(t *testing.T) func() string {
	t.Helper()
	start := time.Now()
	stop := make(chan struct{})
	done := make(chan struct{})
	var mu sync.Mutex
	var records []loggerSwapRecord
	go func() {
		defer close(done)
		lastLogger := mainLog.Load()
		for {
			select {
			case <-stop:
				return
			default:
			}
			logger := mainLog.Load()
			if logger != lastLogger {
				mu.Lock()
				records = append(records, loggerSwapRecord{time.Since(start), loggerWriterType(logger)})
				mu.Unlock()
				lastLogger = logger
			}
			time.Sleep(50 * time.Microsecond)
		}
	}()
	t.Cleanup(func() { close(stop); <-done })
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		parts := make([]string, 0, len(records))
		for _, r := range slices.Clone(records) {
			parts = append(parts, fmt.Sprintf("{at=%s writer=%s}", r.at, r.writer))
		}
		return fmt.Sprintf("swaps=%d %s current=%s", len(records), strings.Join(parts, " "), loggerWriterType(mainLog.Load()))
	}
}

// loggerWriterType names the core behind a logger, so a swapped logger tells
// which init function built it.
func loggerWriterType(l *ctrld.Logger) string {
	if l == nil || l.Logger == nil {
		return "nil"
	}
	return fmt.Sprintf("%T", l.Core())
}

func Test_queryHealthClassThresholds(t *testing.T) {
	// The class names go into the journal, so the test pins the text.
	tests := []struct {
		name     string
		queries  int
		failures int
		want     string
	}{
		{"no queries", 0, 0, "healthy"},
		{"two percent", 100, 2, "healthy"},
		{"five percent", 100, 5, "degraded"},
		{"six percent", 100, 6, "degraded"},
		{"half of twenty", 20, 12, "failing"},
		{"half of ten", 10, 5, "failing"},
		{"small sample cannot fail", 9, 9, "healthy"},
		{"small sample cannot degrade", 9, 1, "healthy"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q := newQueryHealth()
			feedQueryHealth(q, tc.queries, map[string]int{sampleClassResolveFailed: tc.failures})

			event, emit := q.evaluate(queryHealthBase, 0, false)
			if !emit {
				t.Fatal("the first evaluate did not emit")
			}
			if event.Class != tc.want {
				t.Fatalf("class: got %q, want %q", event.Class, tc.want)
			}
		})
	}
}

func Test_queryHealthEmitsHeartbeatWithoutClassChange(t *testing.T) {
	q := newQueryHealth()
	if _, emit := q.evaluate(queryHealthBase, 0, false); !emit {
		t.Fatal("the first evaluate did not emit")
	}

	for _, minutes := range []int{1, 7, 14} {
		at := queryHealthBase.Add(time.Duration(minutes) * time.Minute)
		if _, emit := q.evaluate(at, 0, false); emit {
			t.Fatalf("emit at minute %d without a class change", minutes)
		}
	}

	event, emit := q.evaluate(queryHealthBase.Add(15*time.Minute), 0, false)
	if !emit {
		t.Fatal("no heartbeat at 15 minutes")
	}
	if event.Class != "healthy" {
		t.Fatalf("heartbeat class: got %q, want %q", event.Class, "healthy")
	}
	if _, emit := q.evaluate(queryHealthBase.Add(16*time.Minute), 0, false); emit {
		t.Fatal("a second emit follows the heartbeat")
	}
}

func Test_queryHealthEmitsOnClassChange(t *testing.T) {
	q := newQueryHealth()
	feedQueryHealth(q, 100, nil)
	event, emit := q.evaluate(queryHealthBase, 0, false)
	if !emit || event.Class != "healthy" {
		t.Fatalf("first report: emit %v, class %q", emit, event.Class)
	}

	feedQueryHealth(q, 0, map[string]int{sampleClassResolveFailed: 50})
	if _, emit := q.evaluate(queryHealthBase.Add(time.Minute), 0, false); emit {
		t.Fatal("emit on the first tick of the new class")
	}

	event, emit = q.evaluate(queryHealthBase.Add(2*time.Minute), 0, false)
	if !emit {
		t.Fatal("no emit after the new class held two ticks")
	}
	if event.Class != "failing" {
		t.Fatalf("class: got %q, want %q", event.Class, "failing")
	}

	if _, emit := q.evaluate(queryHealthBase.Add(3*time.Minute), 0, false); emit {
		t.Fatal("emit without a class change")
	}
}

// Test_queryHealthHoldsAClassChangeForTwoTicks proves that a class which lasts
// one tick reports nothing. A minute of noise must not open an event.
func Test_queryHealthHoldsAClassChangeForTwoTicks(t *testing.T) {
	q := newQueryHealth()
	feedQueryHealth(q, 20, nil)
	event, emit := q.evaluate(queryHealthBase, 0, false)
	if !emit || event.Class != queryHealthHealthy {
		t.Fatalf("first report: emit %v, class %q", emit, event.Class)
	}

	feedQueryHealth(q, 0, map[string]int{sampleClassResolveFailed: 12})
	if event, emit := q.evaluate(queryHealthBase.Add(time.Minute), 0, false); emit {
		t.Fatalf("emit after one tick of class %q", event.Class)
	}

	// The next tick grades the same window as degraded, so the failing class
	// never held two ticks and never reported.
	feedQueryHealth(q, 80, nil)
	if event, emit := q.evaluate(queryHealthBase.Add(2*time.Minute), 0, false); emit {
		t.Fatalf("emit after the class moved again to %q", event.Class)
	}

	event, emit = q.evaluate(queryHealthBase.Add(3*time.Minute), 0, false)
	if !emit {
		t.Fatal("no emit after the new class held two ticks")
	}
	if event.Class != queryHealthDegraded {
		t.Fatalf("class: got %q, want %q", event.Class, queryHealthDegraded)
	}
}

// Test_queryHealthNeedsASampleBeforeAClassChange proves that the empty window
// which follows a heartbeat reports nothing. The counters start at zero, and
// zero queries say nothing about the query path.
func Test_queryHealthNeedsASampleBeforeAClassChange(t *testing.T) {
	q := newQueryHealth()
	feedQueryHealth(q, 20, map[string]int{sampleClassResolveFailed: 12})
	event, emit := q.evaluate(queryHealthBase, 0, false)
	if !emit || event.Class != queryHealthFailing {
		t.Fatalf("first report: emit %v, class %q", emit, event.Class)
	}

	event, emit = q.evaluate(queryHealthBase.Add(15*time.Minute), 0, false)
	if !emit || event.Class != queryHealthFailing {
		t.Fatalf("window end: emit %v, class %q", emit, event.Class)
	}

	for _, minutes := range []int{16, 17} {
		at := queryHealthBase.Add(time.Duration(minutes) * time.Minute)
		if event, emit := q.evaluate(at, 0, false); emit {
			t.Fatalf("emit at minute %d with %d queries and class %q", minutes, event.Queries, event.Class)
		}
	}
}

func Test_queryHealthCacheHitRatio(t *testing.T) {
	q := newQueryHealth()
	event, _ := q.evaluate(queryHealthBase, 0, false)
	if event.CacheHitRatio != 0 {
		t.Fatalf("ratio without queries: got %v, want 0", event.CacheHitRatio)
	}

	feedQueryHealth(q, 20, nil)
	for i := 0; i < 5; i++ {
		q.countCacheHit()
	}

	event, _ = q.evaluate(queryHealthBase.Add(time.Minute), 0, false)
	if event.Queries != 20 || event.CacheHits != 5 {
		t.Fatalf("counters: got %d queries and %d cache hits, want 20 and 5", event.Queries, event.CacheHits)
	}
	if event.CacheHitRatio != 0.25 {
		t.Fatalf("ratio: got %v, want 0.25", event.CacheHitRatio)
	}
}

func Test_queryHealthResetsCountersAtWindowEnd(t *testing.T) {
	q := newQueryHealth()
	if _, emit := q.evaluate(queryHealthBase, 0, false); !emit {
		t.Fatal("the first evaluate did not emit")
	}
	feedQueryHealth(q, 20, map[string]int{sampleClassResolveFailed: 12})
	q.countCacheHit()

	closed, emit := q.evaluate(queryHealthBase.Add(15*time.Minute), 0, false)
	if !emit {
		t.Fatal("no emit at the window end")
	}
	if closed.Queries != 20 || closed.CacheHits != 1 || closed.Failures[sampleClassResolveFailed] != 12 {
		t.Fatalf("the closed window lost its counters: %+v", closed)
	}

	q.countFailure(sampleClassResolveFailed)
	next, _ := q.evaluate(queryHealthBase.Add(16*time.Minute), 0, false)
	if next.Queries != 0 || next.CacheHits != 0 {
		t.Fatalf("the counters survived the window end: %+v", next)
	}
	if next.Failures[sampleClassResolveFailed] != 1 {
		t.Fatalf("failures of the new window: got %d, want 1", next.Failures[sampleClassResolveFailed])
	}
}

func Test_queryHealthReportKeepsItsOwnFailures(t *testing.T) {
	q := newQueryHealth()
	feedQueryHealth(q, 10, map[string]int{sampleClassResolveFailed: 1})

	report, _ := q.evaluate(queryHealthBase, 0, false)
	q.countFailure(sampleClassResolveFailed)

	if got := report.Failures[sampleClassResolveFailed]; got != 1 {
		t.Fatalf("the report shares the live failure map: got %d, want 1", got)
	}
}

func Test_queryHealthLogsJournalEvent(t *testing.T) {
	swaps := watchLoggerSwaps(t)
	logs := captureDebugMainLog(t)
	q := newQueryHealth()
	feedQueryHealth(q, 20, map[string]int{
		sampleClassResolveFailed:      8,
		sampleClassAllEndpointsFailed: 4,
	})
	for i := 0; i < 5; i++ {
		q.countCacheHit()
	}

	event, emit := q.evaluate(queryHealthBase, 2, true)
	if !emit {
		t.Fatal("the first evaluate did not emit")
	}
	q.log(event)

	events := jsonLogEvents(t, logs, queryHealthMessage)
	if len(events) != 1 {
		t.Fatalf("health lines: got %d, want 1 (captured %q) %s", len(events), logs.String(), swaps())
	}
	logged := events[0]
	wantField(t, logged, "journal", true)
	wantField(t, logged, "level", "info")
	wantField(t, logged, "class", "failing")
	wantField(t, logged, "window_s", float64(900))
	wantField(t, logged, "queries", float64(20))
	wantField(t, logged, "cache_hits", float64(5))
	wantField(t, logged, "upstreams_down", float64(2))
	wantField(t, logged, "bypass_active", true)
	wantField(t, logged, "cache_hit_ratio", 0.25)

	failures, ok := logged["failures_by_class"].(map[string]any)
	if !ok {
		t.Fatalf("failures_by_class: got %T, want an object", logged["failures_by_class"])
	}
	if len(failures) != 2 {
		t.Fatalf("failure classes: got %d, want 2", len(failures))
	}
	wantField(t, failures, sampleClassResolveFailed, float64(8))
	wantField(t, failures, sampleClassAllEndpointsFailed, float64(4))
}

func Test_queryHealthLoopEmitsUntilStop(t *testing.T) {
	swaps := watchLoggerSwaps(t)
	logs := captureDebugMainLog(t)
	tick := queryHealthTick
	defer func() { queryHealthTick = tick }()
	queryHealthTick = time.Millisecond

	q := newQueryHealth()
	stop := make(chan struct{})
	done := make(chan struct{})
	var once sync.Once
	stopLoop := func() {
		once.Do(func() {
			close(stop)
			<-done
		})
	}
	defer stopLoop()

	go func() {
		defer close(done)
		q.loop(stop, func() (int, bool) { return 1, true })
	}()

	waitForLogLineOrExplain(t, logs, queryHealthMessage, swaps)
	stopLoop()

	events := jsonLogEvents(t, logs, queryHealthMessage)
	if len(events) == 0 {
		t.Fatal("the loop logged no health event")
	}
	wantField(t, events[0], "journal", true)
	wantField(t, events[0], "upstreams_down", float64(1))
	wantField(t, events[0], "bypass_active", true)
}

// Test_queryHealthReportsEveryWindowAfterAnEarlyEmit proves that a class
// change in the middle of a window does not make the rest of the window
// vanish. The heartbeat follows the window, not the last report.
func Test_queryHealthReportsEveryWindowAfterAnEarlyEmit(t *testing.T) {
	q := newQueryHealth()
	if _, emit := q.evaluate(queryHealthBase, 0, false); !emit {
		t.Fatal("the first evaluate did not emit")
	}
	feedQueryHealth(q, 20, map[string]int{sampleClassResolveFailed: 20})
	if _, emit := q.evaluate(queryHealthBase.Add(5*time.Minute), 0, false); emit {
		t.Fatal("emit on the first tick of the new class")
	}
	event, emit := q.evaluate(queryHealthBase.Add(6*time.Minute), 0, false)
	if !emit || event.Class != queryHealthFailing {
		t.Fatalf("class change at 6 minutes: emit %v, class %q", emit, event.Class)
	}
	feedQueryHealth(q, 7, nil)
	event, emit = q.evaluate(queryHealthBase.Add(15*time.Minute), 0, false)
	if !emit {
		t.Fatal("the end of the window did not emit")
	}
	if event.Queries != 27 {
		t.Fatalf("queries in the window report: got %d, want 27", event.Queries)
	}
}
