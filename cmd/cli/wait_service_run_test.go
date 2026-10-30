package cli

import (
	"testing"
	"time"
)

// A run must not return, and so let the process exit, while s.Run is still
// reporting the stop to the service manager (#652).
func TestWaitServiceRunWaitsForServiceRun(t *testing.T) {
	done := make(chan struct{})
	returned := make(chan struct{})
	go func() {
		waitServiceRun(done, time.Minute)
		close(returned)
	}()

	select {
	case <-returned:
		t.Fatal("waitServiceRun returned before s.Run finished")
	case <-time.After(100 * time.Millisecond):
	}

	close(done)
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("waitServiceRun did not return after s.Run finished")
	}
}

func TestWaitServiceRunGivesUpAfterTimeout(t *testing.T) {
	start := time.Now()
	waitServiceRun(make(chan struct{}), 50*time.Millisecond)
	if elapsed := time.Since(start); elapsed < 50*time.Millisecond {
		t.Fatalf("waitServiceRun returned after %s, before its timeout", elapsed)
	}
}

func TestWaitServiceRunWithoutServiceRun(t *testing.T) {
	returned := make(chan struct{})
	go func() {
		waitServiceRun(nil, time.Minute)
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("waitServiceRun waited although nothing runs s.Run")
	}
}
