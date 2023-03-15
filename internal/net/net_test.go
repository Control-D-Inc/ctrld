package net

import (
	"context"
	"testing"
	"time"
)

func TestProbeStackTimeout(t *testing.T) {
	done := make(chan struct{})
	started := make(chan struct{})
	go func() {
		defer close(done)
		close(started)
		supportIPv6(context.Background())
	}()

	<-started
	select {
	case <-time.After(probeStackTimeout + time.Second):
		t.Error("probeStack timeout is not enforce")
	case <-done:
	}
}
