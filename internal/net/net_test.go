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
		hasV6, port := supportIPv6(context.Background())
		if hasV6 {
			t.Logf("connect to port %s using ipv6: %v", port, hasV6)
		} else {
			t.Log("ipv6 is not available")
		}
	}()

	<-started
	select {
	case <-time.After(probeStackTimeout + time.Second):
		t.Error("probeStack timeout is not enforce")
	case <-done:
	}
}
