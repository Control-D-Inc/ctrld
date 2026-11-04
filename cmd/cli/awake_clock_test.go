package cli

import (
	"testing"
	"time"
)

// While the host is awake, the awake clock runs with the wall clock, so the
// real clocks find no sleep.
func TestAwakeClockRunsWhileAwake(t *testing.T) {
	before := awakeClock()
	time.Sleep(50 * time.Millisecond)
	if d := awakeClock() - before; d < 40*time.Millisecond || d > 5*time.Second {
		t.Fatalf("awake clock moved %v over a 50ms wait", d)
	}
	var w sleepWatch
	w.slept()
	time.Sleep(10 * time.Millisecond)
	if w.slept() {
		t.Fatal("the real clocks found a sleep while awake")
	}
}
