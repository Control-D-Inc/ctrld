package cli

import (
	"sync"
	"sync/atomic"
	"testing"
)

func Test_loopGuard(t *testing.T) {
	lg := newLoopGuard()
	key := "foo"

	var i atomic.Int64
	var started atomic.Int64
	n := 1000
	do := func() {
		locked := lg.TryLock(key)
		defer lg.Unlock(key)
		started.Add(1)
		for started.Load() < 2 {
			// Wait until at least 2 goroutines started, otherwise, on system with heavy load,
			// or having only 1 CPU, all goroutines can be scheduled to run consequently.
		}
		if locked {
			i.Add(1)
		}
	}

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			do()
		}()
	}
	wg.Wait()

	if i.Load() == int64(n) {
		t.Fatalf("i must not be increased %d times", n)
	}
}
