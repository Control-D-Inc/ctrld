package cli

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// samplerTestMessage is the message the fake call site writes on every sampled event.
const samplerTestMessage = "Failed to resolve query"

// samplerSummaryMessage is the message of the window summary.
const samplerSummaryMessage = "Per-query errors sampled"

// captureDebugMainLog sends mainLog into a JSON buffer at debug level, so the
// test also sees the lines that the code under test drops to debug. It swaps
// a global, so no test of this package runs in parallel.
func captureDebugMainLog(t *testing.T) *syncBuffer {
	t.Helper()
	return captureJSONMainLog(t)
}

// jsonLogEvents parses the captured lines as JSON events, in order. An empty
// message takes every line.
func jsonLogEvents(t *testing.T, logs *syncBuffer, message string) []map[string]any {
	t.Helper()
	var events []map[string]any
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		event := map[string]any{}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("log line is not JSON: %q: %v", line, err)
		}
		if message != "" && event["message"] != message {
			continue
		}
		events = append(events, event)
	}
	return events
}

// samplerHarness drives an errorSampler on a clock and a timer queue the test owns.
type samplerHarness struct {
	sampler *errorSampler
	logs    *syncBuffer
	now     time.Time
	pending []func()
}

func newSamplerHarness(t *testing.T) *samplerHarness {
	t.Helper()
	h := &samplerHarness{
		logs: captureDebugMainLog(t),
		now:  time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC),
	}
	h.sampler = &errorSampler{
		now: func() time.Time { return h.now },
		after: func(_ time.Duration, fn func()) *time.Timer {
			h.pending = append(h.pending, fn)
			return nil
		},
	}
	return h
}

// emit plays a call site: it takes an event from the sampler and adds its own fields.
func (h *samplerHarness) emit(class, upstream string) {
	h.sampler.event(class, upstream).Str("class", class).Str("upstream", upstream).Msg(samplerTestMessage)
}

func (h *samplerHarness) advance(d time.Duration) {
	h.now = h.now.Add(d)
}

func (h *samplerHarness) events(t *testing.T) []map[string]any {
	t.Helper()
	return jsonLogEvents(t, h.logs, "")
}

func countSampled(events []map[string]any, level, upstream string) int {
	count := 0
	for _, event := range events {
		if event["message"] != samplerTestMessage {
			continue
		}
		if event["level"] != level || event["upstream"] != upstream {
			continue
		}
		count++
	}
	return count
}

func samplerSummaries(events []map[string]any) []map[string]any {
	var summaries []map[string]any
	for _, event := range events {
		if event["message"] == samplerSummaryMessage {
			summaries = append(summaries, event)
		}
	}
	return summaries
}

func wantField(t *testing.T, event map[string]any, field string, want any) {
	t.Helper()
	if got := event[field]; got != want {
		t.Fatalf("field %q: got %v, want %v", field, got, want)
	}
}

func Test_errorSamplerLimitsWindowAndSummarizes(t *testing.T) {
	h := newSamplerHarness(t)

	for i := 0; i < querySampleLimit+2; i++ {
		h.emit(sampleClassResolveFailed, "upstream.0")
	}

	events := h.events(t)
	if got := countSampled(events, "error", "upstream.0"); got != querySampleLimit {
		t.Fatalf("error lines: got %d, want %d", got, querySampleLimit)
	}
	if got := countSampled(events, "debug", "upstream.0"); got != 2 {
		t.Fatalf("debug lines: got %d, want 2", got)
	}
	if got := len(samplerSummaries(events)); got != 0 {
		t.Fatalf("summaries before the window closed: got %d, want 0", got)
	}

	h.advance(querySampleWindow)
	h.emit(sampleClassResolveFailed, "upstream.0")

	events = h.events(t)
	summaries := samplerSummaries(events)
	if len(summaries) != 1 {
		t.Fatalf("summaries after the window closed: got %d, want 1", len(summaries))
	}
	summary := summaries[0]
	wantField(t, summary, "level", "error")
	wantField(t, summary, "class", sampleClassResolveFailed)
	wantField(t, summary, "upstream", "upstream.0")
	wantField(t, summary, "count", float64(7))
	wantField(t, summary, "suppressed", float64(2))
	wantField(t, summary, "window_s", float64(60))

	last := events[len(events)-1]
	wantField(t, last, "message", samplerTestMessage)
	wantField(t, last, "level", "error")
}

func Test_errorSamplerKeepsBudgetPerUpstream(t *testing.T) {
	h := newSamplerHarness(t)

	for i := 0; i < querySampleLimit+1; i++ {
		h.emit(sampleClassResolveFailed, "upstream.0")
	}
	for i := 0; i < querySampleLimit; i++ {
		h.emit(sampleClassResolveFailed, "upstream.1")
	}

	events := h.events(t)
	if got := countSampled(events, "error", "upstream.1"); got != querySampleLimit {
		t.Fatalf("error lines for the second upstream: got %d, want %d", got, querySampleLimit)
	}
	if got := countSampled(events, "debug", "upstream.1"); got != 0 {
		t.Fatalf("debug lines for the second upstream: got %d, want 0", got)
	}
	if got := countSampled(events, "debug", "upstream.0"); got != 1 {
		t.Fatalf("debug lines for the first upstream: got %d, want 1", got)
	}
}

func Test_errorSamplerKeepsQuietWindowSilent(t *testing.T) {
	h := newSamplerHarness(t)

	for i := 0; i < 3; i++ {
		h.emit(sampleClassAllEndpointsFailed, "")
	}

	h.advance(querySampleWindow)
	h.sampler.closeExpired(h.now)

	if got := len(samplerSummaries(h.events(t))); got != 0 {
		t.Fatalf("summaries for a window without suppressed lines: got %d, want 0", got)
	}
}

func Test_errorSamplerCloseExpiredSummarizesOnce(t *testing.T) {
	h := newSamplerHarness(t)

	for i := 0; i < querySampleLimit+2; i++ {
		h.emit(sampleClassSendResponseFailed, "")
	}
	sampled := len(h.events(t))

	h.advance(querySampleWindow)
	h.sampler.closeExpired(h.now)

	events := h.events(t)
	if len(events) != sampled+1 {
		t.Fatalf("lines after closeExpired: got %d, want %d", len(events), sampled+1)
	}
	summaries := samplerSummaries(events)
	if len(summaries) != 1 {
		t.Fatalf("summaries after closeExpired: got %d, want 1", len(summaries))
	}
	wantField(t, summaries[0], "class", sampleClassSendResponseFailed)
	wantField(t, summaries[0], "suppressed", float64(2))

	h.sampler.closeExpired(h.now.Add(querySampleWindow))

	if got := len(h.events(t)); got != sampled+1 {
		t.Fatalf("lines after the second closeExpired: got %d, want %d", got, sampled+1)
	}
}

func Test_errorSamplerTimerClosesIdleWindow(t *testing.T) {
	h := newSamplerHarness(t)

	for i := 0; i < querySampleLimit+1; i++ {
		h.emit(sampleClassResolveFailed, "upstream.0")
	}
	if len(h.pending) != 1 {
		t.Fatalf("window timers: got %d, want 1", len(h.pending))
	}

	h.advance(querySampleWindow)
	h.pending[0]()

	summaries := samplerSummaries(h.events(t))
	if len(summaries) != 1 {
		t.Fatalf("summaries after the timer fired: got %d, want 1", len(summaries))
	}
	wantField(t, summaries[0], "suppressed", float64(1))
	wantField(t, summaries[0], "count", float64(6))
}

func Test_errorSamplerZeroValueWorks(t *testing.T) {
	buf := captureDebugMainLog(t)

	var sampler errorSampler
	// The zero value arms a real timer. Close its window after the assertions,
	// so no late summary line reaches another test.
	t.Cleanup(func() { sampler.closeExpired(time.Now().Add(querySampleWindow)) })
	sampler.event(sampleClassResolveFailed, "upstream.0").Msg(samplerTestMessage)

	if got := strings.Count(buf.String(), samplerTestMessage); got != 1 {
		t.Fatalf("lines from the zero value sampler: got %d, want 1", got)
	}
	if !strings.Contains(buf.String(), `"level":"error"`) {
		t.Fatalf("first line of a window is not at error level: %s", buf.String())
	}
}

// Test_errorSamplerKeepsAnEmptyUpstreamEmpty drives a window of a class that
// names no upstream. The summary must not report the window as a custom
// upstream.
func Test_errorSamplerKeepsAnEmptyUpstreamEmpty(t *testing.T) {
	h := newSamplerHarness(t)

	for i := 0; i < querySampleLimit+1; i++ {
		h.emit(sampleClassAllEndpointsFailed, "")
	}
	h.advance(querySampleWindow)
	h.sampler.closeExpired(h.now)

	summaries := samplerSummaries(h.events(t))
	if len(summaries) != 1 {
		t.Fatalf("summaries after the window closed: got %d, want 1", len(summaries))
	}
	wantField(t, summaries[0], "upstream", "")
}
