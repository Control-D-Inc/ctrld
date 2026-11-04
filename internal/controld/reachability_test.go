package controld

import (
	"context"
	"testing"
)

func TestProbeReachabilityRespectsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ProbeReachability(ctx, false); err == nil {
		t.Error("expected an error for an already-cancelled context")
	}
}
