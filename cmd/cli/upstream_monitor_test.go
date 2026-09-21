package cli

import (
	"testing"
	"time"

	"github.com/Control-D-Inc/ctrld"
)

// upstreamStateMessage is the message of every upstream transition event.
const upstreamStateMessage = "Upstream state changed"

// downMonitor returns a monitor on a clock the test owns, with the upstream down.
func downMonitor(t *testing.T, upstream string) (*upstreamMonitor, *syncBuffer, *time.Time) {
	t.Helper()
	logs := captureDebugMainLog(t)
	um := newUpstreamMonitor(&ctrld.Config{}, mainLog.Load())
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	um.now = func() time.Time { return now }
	for i := 0; i < maxFailureRequest; i++ {
		um.increaseFailureCount(upstream)
	}
	if got := len(jsonLogEvents(t, logs, upstreamStateMessage)); got != 1 {
		t.Fatalf("state events after the failures: got %d, want 1", got)
	}
	return um, logs, &now
}

func Test_upstreamMonitorLogsOneDownEvent(t *testing.T) {
	const upstream = upstreamPrefix + "0"
	logs := captureDebugMainLog(t)
	um := newUpstreamMonitor(&ctrld.Config{}, mainLog.Load())

	for i := 0; i < 633; i++ {
		um.increaseFailureCount(upstream)
	}

	events := jsonLogEvents(t, logs, upstreamStateMessage)
	if len(events) != 1 {
		t.Fatalf("state events: got %d, want 1", len(events))
	}
	wantField(t, events[0], "level", "warn")
	wantField(t, events[0], "journal", true)
	wantField(t, events[0], "upstream", upstream)
	wantField(t, events[0], "state", "down")
	wantField(t, events[0], "reason", "immediate")
	wantField(t, events[0], "failure_count", float64(maxFailureRequest))
}

func Test_upstreamMonitorTimerLogsDownEvent(t *testing.T) {
	const upstream = upstreamPrefix + "0"
	logs := captureDebugMainLog(t)
	um := newUpstreamMonitor(&ctrld.Config{}, mainLog.Load())
	var armed []func()
	um.after = func(_ time.Duration, fn func()) { armed = append(armed, fn) }

	um.increaseFailureCount(upstream)
	if len(armed) != 1 {
		t.Fatalf("armed timers: got %d, want 1", len(armed))
	}
	armed[0]()

	events := jsonLogEvents(t, logs, upstreamStateMessage)
	if len(events) != 1 {
		t.Fatalf("state events: got %d, want 1", len(events))
	}
	wantField(t, events[0], "state", "down")
	wantField(t, events[0], "reason", "timer")
	wantField(t, events[0], "failure_count", float64(1))
}

func Test_upstreamMonitorResetLogsOneUpEvent(t *testing.T) {
	const upstream = upstreamPrefix + "0"
	um, logs, now := downMonitor(t, upstream)

	*now = now.Add(1500 * time.Millisecond)
	um.reset(upstream)

	events := jsonLogEvents(t, logs, upstreamStateMessage)
	if len(events) != 2 {
		t.Fatalf("state events: got %d, want 2", len(events))
	}
	up := events[1]
	wantField(t, up, "level", "info")
	wantField(t, up, "journal", true)
	wantField(t, up, "upstream", upstream)
	wantField(t, up, "state", "up")
	wantField(t, up, "reason", "recovered")
	wantField(t, up, "down_for_ms", float64(1500))
	wantField(t, up, "failure_count", float64(maxFailureRequest))
}

func Test_upstreamMonitorRetireLogsTheOpenOutage(t *testing.T) {
	const upstream = upstreamPrefix + "0"
	um, logs, now := downMonitor(t, upstream)

	*now = now.Add(3 * time.Second)
	um.retire()

	events := jsonLogEvents(t, logs, upstreamStateMessage)
	if len(events) != 2 {
		t.Fatalf("state events: got %d, want 2", len(events))
	}
	up := events[1]
	wantField(t, up, "upstream", upstream)
	wantField(t, up, "state", "up")
	wantField(t, up, "reason", "reload")
	wantField(t, up, "down_for_ms", float64(3000))

	um.retire()

	if got := len(jsonLogEvents(t, logs, upstreamStateMessage)); got != 2 {
		t.Fatalf("state events after the second retire: got %d, want 2", got)
	}
}

func Test_upstreamMonitorNoteSuccessLogsOneUpEvent(t *testing.T) {
	const upstream = upstreamPrefix + "0"
	um, logs, now := downMonitor(t, upstream)

	*now = now.Add(2 * time.Second)
	um.noteSuccess(upstream)

	events := jsonLogEvents(t, logs, upstreamStateMessage)
	if len(events) != 2 {
		t.Fatalf("state events: got %d, want 2", len(events))
	}
	up := events[1]
	wantField(t, up, "state", "up")
	wantField(t, up, "reason", "recovered")
	wantField(t, up, "down_for_ms", float64(2000))
	wantField(t, up, "failure_count", float64(maxFailureRequest))
	if got := um.failureReq[upstream]; got != 0 {
		t.Fatalf("failure count after the answer: got %d, want 0", got)
	}
}

func Test_upstreamMonitorNoteSuccessOnUpUpstreamIsQuiet(t *testing.T) {
	const upstream = upstreamPrefix + "0"
	logs := captureDebugMainLog(t)
	um := newUpstreamMonitor(&ctrld.Config{}, mainLog.Load())

	um.noteSuccess(upstream)
	um.noteSuccess(upstream)

	if got := len(jsonLogEvents(t, logs, upstreamStateMessage)); got != 0 {
		t.Fatalf("state events: got %d, want 0", got)
	}
}

// Test_upstreamMonitorRetiredTimerStaysSilent fires the down timer that a
// failure armed before the reload retired the monitor. A retired monitor
// owns no outage, so the timer must add no event.
func Test_upstreamMonitorRetiredTimerStaysSilent(t *testing.T) {
	const upstream = upstreamPrefix + "0"
	logs := captureDebugMainLog(t)
	um := newUpstreamMonitor(&ctrld.Config{}, mainLog.Load())
	var armed []func()
	um.after = func(_ time.Duration, fn func()) { armed = append(armed, fn) }

	um.increaseFailureCount(upstream)
	um.retire()
	for _, fire := range armed {
		fire()
	}

	if got := len(jsonLogEvents(t, logs, upstreamStateMessage)); got != 0 {
		t.Fatalf("state events from the retired monitor: got %d, want 0: %s", got, logs.String())
	}
	if um.isDown(upstream) {
		t.Fatal("the retired monitor marked the upstream down")
	}
}

// Test_upstreamMonitorRetiredAfterImmediateDownStaysSilent retires a monitor
// that already reported an outage. The armed timer and a late failure must
// add no event after the closing up event.
func Test_upstreamMonitorRetiredAfterImmediateDownStaysSilent(t *testing.T) {
	const upstream = upstreamPrefix + "0"
	logs := captureDebugMainLog(t)
	um := newUpstreamMonitor(&ctrld.Config{}, mainLog.Load())
	var armed []func()
	um.after = func(_ time.Duration, fn func()) { armed = append(armed, fn) }

	for i := 0; i < maxFailureRequest; i++ {
		um.increaseFailureCount(upstream)
	}
	um.retire()
	before := jsonLogEvents(t, logs, upstreamStateMessage)
	if len(before) != 2 {
		t.Fatalf("state events after the retire: got %d, want down and up", len(before))
	}
	for _, fire := range armed {
		fire()
	}
	um.increaseFailureCount(upstream)

	if got := len(jsonLogEvents(t, logs, upstreamStateMessage)); got != 2 {
		t.Fatalf("state events after the retired timer fired: got %d, want 2: %s", got, logs.String())
	}
	if um.isDown(upstream) {
		t.Fatal("the retired monitor marked the upstream down again")
	}
}

// Test_upstreamMonitorKeepsACustomNameOutOfTheJournal marks an upstream with
// an operator-chosen key down. The key can hold a token, so the event names
// the upstream by a bounded name.
func Test_upstreamMonitorKeepsACustomNameOutOfTheJournal(t *testing.T) {
	const upstream = upstreamPrefix + "dns.controld.com/org-v1-SECRET0123"
	logs := captureDebugMainLog(t)
	um := newUpstreamMonitor(&ctrld.Config{}, mainLog.Load())

	for i := 0; i < maxFailureRequest; i++ {
		um.increaseFailureCount(upstream)
	}
	um.noteSuccess(upstream)

	events := jsonLogEvents(t, logs, upstreamStateMessage)
	if len(events) != 2 {
		t.Fatalf("state events: got %d, want down and up", len(events))
	}
	for _, event := range events {
		wantField(t, event, "upstream", upstreamPrefix+"custom")
	}
	for _, generated := range []string{upstreamOS, upstreamPrefix + "0", upstreamPrefix + "internal_3"} {
		if got := journalUpstreamName(generated); got != generated {
			t.Fatalf("journalUpstreamName(%q) = %q, want the name itself", generated, got)
		}
	}
}

func Test_upstreamMonitorCountDown(t *testing.T) {
	captureDebugMainLog(t)
	um := newUpstreamMonitor(&ctrld.Config{}, mainLog.Load())
	if got := um.countDown(); got != 0 {
		t.Fatalf("countDown on a new monitor = %d, want 0", got)
	}
	um.mu.Lock()
	um.markDown(upstreamPrefix+"0", 3, "immediate")
	um.markDown(upstreamPrefix+"1", 3, "immediate")
	um.mu.Unlock()
	if got := um.countDown(); got != 2 {
		t.Fatalf("countDown with two down upstreams = %d, want 2", got)
	}
}

func Test_upstreamMonitorDownFor(t *testing.T) {
	const upstream = upstreamPrefix + "0"
	um, _, now := downMonitor(t, upstream)

	*now = now.Add(2500 * time.Millisecond)

	if got := um.downFor(upstream); got != 2500*time.Millisecond {
		t.Fatalf("downFor a down upstream = %s, want 2.5s", got)
	}
	if got := um.downFor(upstreamPrefix + "9"); got != 0 {
		t.Fatalf("downFor an unknown upstream = %s, want 0", got)
	}

	um.reset(upstream)

	if got := um.downFor(upstream); got != 0 {
		t.Fatalf("downFor an upstream that is up = %s, want 0", got)
	}
}

func Test_upstreamMonitorCountDownExcept(t *testing.T) {
	captureDebugMainLog(t)
	um := newUpstreamMonitor(&ctrld.Config{}, mainLog.Load())
	um.mu.Lock()
	um.markDown(upstreamPrefix+"0", 3, "immediate")
	um.markDown(upstreamPrefix+internalDomainUpstreamPrefix+"1", 3, "immediate")
	um.markDown(upstreamPrefix+internalDomainUpstreamPrefix+"2", 3, "immediate")
	um.mu.Unlock()

	if got := um.countDown(); got != 3 {
		t.Fatalf("countDown = %d, want 3", got)
	}
	if got := um.countDownExcept(isInternalDomainUpstream); got != 1 {
		t.Fatalf("countDownExcept(isInternalDomainUpstream) = %d, want 1", got)
	}
	if got := um.countDownExcept(nil); got != 3 {
		t.Fatalf("countDownExcept(nil) = %d, want 3", got)
	}
}
