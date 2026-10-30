package ctrld

import (
	"context"
	"sync"
	"testing"
)

// resetIPv6Probe clears the one-time IPv6 probe. Test only: the process runs
// the probe once, so a test cannot see it without this reset.
func resetIPv6Probe(t *testing.T) {
	t.Helper()
	reset := func() {
		hasIPv6Once = sync.Once{}
		ipv6Available.Store(false)
	}
	reset()
	t.Cleanup(reset)
}

func TestHasIPv6KeepsTheProbeThenTakesTheStoredFlag(t *testing.T) {
	resetIPv6Probe(t)

	probed := HasIPv6(context.Background())
	if got := HasIPv6(context.Background()); got != probed {
		t.Fatalf("HasIPv6 = %v on the second call, want the probe value %v", got, probed)
	}

	SetIPv6Available(!probed)
	if got := HasIPv6(context.Background()); got == probed {
		t.Fatalf("HasIPv6 = %v after SetIPv6Available(%v), want the stored value", got, !probed)
	}

	SetIPv6Available(false)
	if HasIPv6(context.Background()) {
		t.Fatal("HasIPv6 = true after SetIPv6Available(false), want false")
	}
}
