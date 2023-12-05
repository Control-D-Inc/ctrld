package cli

import (
	"sync"
	"testing"
)

func Test_loopGuard(t *testing.T) {
	lg := newLoopGuard()
	key := "foo"

	var mu sync.Mutex
	i := 0
	n := 1000
	do := func() {
		locked := lg.TryLock(key)
		defer lg.Unlock(key)
		if locked {
			mu.Lock()
			i++
			mu.Unlock()
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

	if i == n {
		t.Fatalf("i must not be increased %d times", n)
	}
}
