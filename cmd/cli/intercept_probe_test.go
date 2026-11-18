package cli

import (
	"testing"
	"time"
)

func signalAfter(d time.Duration) <-chan struct{} {
	ch := make(chan struct{}, 1)
	time.AfterFunc(d, func() { ch <- struct{}{} })
	return ch
}

func TestAwaitInterceptProbeOnTime(t *testing.T) {
	got, _ := awaitInterceptProbe(signalAfter(5*time.Millisecond), 200*time.Millisecond, time.Second, 10*time.Millisecond, nil)
	if got != interceptProbeOnTime {
		t.Fatalf("outcome = %v, want on time", got)
	}
}

// A probe that arrives after the on-time window but inside the late window is late, not
// missed (#657).
func TestAwaitInterceptProbeLate(t *testing.T) {
	got, waited := awaitInterceptProbe(signalAfter(150*time.Millisecond), 50*time.Millisecond, time.Second, 10*time.Millisecond, nil)
	if got != interceptProbeLate {
		t.Fatalf("outcome = %v, want late", got)
	}
	if waited < 150*time.Millisecond {
		t.Errorf("waited = %v, want at least the arrival time", waited)
	}
}

// Without a late window, the same arrival is a miss, which is the behaviour probeNRPT
// keeps for health ticks and the retry ladder.
func TestAwaitInterceptProbeNoGraceMissesLateArrival(t *testing.T) {
	got, waited := awaitInterceptProbe(signalAfter(150*time.Millisecond), 50*time.Millisecond, 50*time.Millisecond, 10*time.Millisecond, nil)
	if got != interceptProbeMissed {
		t.Fatalf("outcome = %v, want missed", got)
	}
	if waited >= 150*time.Millisecond {
		t.Errorf("waited = %v, want the wait to end at the on-time window", waited)
	}
}

func TestAwaitInterceptProbeMissedAfterLateWindow(t *testing.T) {
	got, _ := awaitInterceptProbe(make(chan struct{}), 20*time.Millisecond, 60*time.Millisecond, 10*time.Millisecond, nil)
	if got != interceptProbeMissed {
		t.Fatalf("outcome = %v, want missed", got)
	}
}

// A stop must end the late window too, so a service stop never waits it out.
func TestAwaitInterceptProbeAbandonEndsLateWindow(t *testing.T) {
	start := time.Now()
	got, _ := awaitInterceptProbe(make(chan struct{}), 20*time.Millisecond, 10*time.Second, 10*time.Millisecond,
		func() bool { return time.Since(start) > 50*time.Millisecond })
	if got != interceptProbeAbandoned {
		t.Fatalf("outcome = %v, want abandoned", got)
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("abandon took %v, want it to end the wait promptly", time.Since(start))
	}
}
