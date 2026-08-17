package cli

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
)

// progForRefresh builds a prog that can run a configuration refresh: Firewall
// Mode on, and a buffered reload channel so a refresh that decides ctrld must
// reload does not block on a listener that does not exist in a test.
func progForRefresh() *prog {
	p := progWithAllowList()
	p.rc = &controld.ResolverConfig{}
	p.apiReloadCh = make(chan *ctrld.Config, 1)
	return p
}

// refresh runs one configuration refresh through the handler apiConfigReload
// uses, which is the point: a test that called applyAllowedDestinations directly
// would still pass if the refresh path stopped calling it.
func refresh(t *testing.T, p *prog, forced bool, rc *controld.ResolverConfig) {
	t.Helper()
	p.applyFetchedResolverConfig(context.Background(), discardLogger(), rc, forced, time.Now().Unix())
}

// TestRefreshAppliesAllowedDestinations drives the real refresh handler for both
// the scheduled and the forced path, in the case where nothing else about the
// configuration changed - no custom config, unchanged exclusions - so the
// refresh takes its early return. That is where an allowed-destination update is
// easiest to lose, because the refresh has no other work to do.
func TestRefreshAppliesAllowedDestinations(t *testing.T) {
	direct := netip.MustParseAddr("203.0.113.10")
	inRange := netip.MustParseAddr("198.51.100.7")

	for _, forced := range []bool{false, true} {
		name := "scheduled refresh"
		if forced {
			name = "forced refresh"
		}
		t.Run(name, func(t *testing.T) {
			p := progForRefresh()

			refresh(t, p, forced, &controld.ResolverConfig{
				DestinationIPs: []string{"203.0.113.10", "198.51.100.0/24"},
			})
			if !p.allowList.Contains(direct) || !p.allowList.Contains(inRange) {
				t.Fatalf("refresh did not apply the organization list: %s=%v %s=%v",
					direct, p.allowList.Contains(direct), inRange, p.allowList.Contains(inRange))
			}
			select {
			case cfg := <-p.apiReloadCh:
				t.Fatalf("unchanged configuration signaled a reload (%v)", cfg)
			default:
			}

			// A later refresh withdraws one entry and keeps the other.
			refresh(t, p, forced, &controld.ResolverConfig{
				DestinationIPs: []string{"203.0.113.10"},
			})
			if p.allowList.Contains(inRange) {
				t.Fatalf("%s still allowed after the refresh that withdrew it", inRange)
			}
			if !p.allowList.Contains(direct) {
				t.Fatalf("%s should still be allowed", direct)
			}

			// And one clears the list entirely.
			refresh(t, p, forced, &controld.ResolverConfig{})
			if p.allowList.Contains(direct) {
				t.Fatalf("%s still allowed after the refresh that cleared the list", direct)
			}
		})
	}
}

// TestRefreshAppliesAllowedDestinationsWhenReloading covers the other branch of
// the same handler: a refresh that also changes the exclusion list, and so
// signals a ctrld reload, must still apply the destinations - and they must
// survive the allowlist flush that the reload performs.
func TestRefreshAppliesAllowedDestinationsWhenReloading(t *testing.T) {
	p := progForRefresh()
	p.rc = &controld.ResolverConfig{Exclude: []string{"example.com"}}
	direct := netip.MustParseAddr("203.0.113.10")

	refresh(t, p, false, &controld.ResolverConfig{
		Exclude:        []string{"example.com", "example.net"},
		DestinationIPs: []string{"203.0.113.10"},
	})

	select {
	case <-p.apiReloadCh:
	default:
		t.Fatal("exclusion list change did not signal a reload")
	}
	if !p.allowList.Contains(direct) {
		t.Fatalf("%s not allowed after a refresh that reloaded ctrld", direct)
	}
}

// TestRefreshKeepsAllowedDestinationsPendingUntilMirrored pins that the refresh
// path reports honestly: while platform enforcement is rejecting the change, the
// refresh leaves it pending and retries it, instead of recording it as applied.
func TestRefreshKeepsAllowedDestinationsPendingUntilMirrored(t *testing.T) {
	p := progForRefresh()
	var calls []mirrorCall
	failing := true
	stubMirror(t, &calls, &failing)

	rc := &controld.ResolverConfig{DestinationIPs: []string{"203.0.113.10"}}
	refresh(t, p, false, rc)
	if got := p.pendingDestinations(p.allowList); got != 1 {
		t.Fatalf("pendingDestinations = %d after a rejected mirror, want 1", got)
	}

	refresh(t, p, false, rc)
	if len(calls) != 2 {
		t.Fatalf("refresh did not retry the rejected change: calls = %v", calls)
	}

	failing = false
	refresh(t, p, false, rc)
	if got := p.pendingDestinations(p.allowList); got != 0 {
		t.Fatalf("pendingDestinations = %d after the mirror succeeded, want 0", got)
	}
}

// stubResolverConfigFetch replaces the refresh loop's API call for the duration
// of a test, and points cdUID at a device so apiConfigReload does not return
// immediately. Each fetch returns the config the test currently wants and
// reports on fetched, which is how a test knows a refresh cycle has run.
func stubResolverConfigFetch(t *testing.T, config func() *controld.ResolverConfig, fetched chan<- struct{}) {
	t.Helper()
	origFetch, origUID := fetchResolverConfigFn, cdUID
	t.Cleanup(func() { fetchResolverConfigFn, cdUID = origFetch, origUID })

	cdUID = "test-uid"
	fetchResolverConfigFn = func(context.Context, *controld.ResolverConfigRequest, bool) (*controld.ResolverConfig, error) {
		rc := config()
		select {
		case fetched <- struct{}{}:
		default:
		}
		return rc, nil
	}
}

// startRefreshLoop runs apiConfigReload in the background and joins it before the
// test finishes. The loop must not outlive the test: it calls through the same
// package-level stubs the next test replaces, so a leaked one would both race
// those globals and act on another test's prog.
func startRefreshLoop(t *testing.T, p *prog) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.apiConfigReload()
	}()
	t.Cleanup(func() {
		close(p.stopCh)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("apiConfigReload did not stop")
		}
	})
}

// waitForCondition polls until cond holds, failing the test if it never does. The
// refresh loop runs in its own goroutine, so its effects land asynchronously.
func waitForCondition(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestApiConfigReloadAppliesAllowedDestinations drives apiConfigReload itself -
// the loop that owns the refresh ticker and the forced-reload channel - rather
// than the handler it calls, so the wiring between them is covered too: removing
// the handler call from the loop must fail a test, not just removing the work
// inside the handler.
func TestApiConfigReloadAppliesAllowedDestinations(t *testing.T) {
	direct := netip.MustParseAddr("203.0.113.10")

	for _, forced := range []bool{true, false} {
		name := "forced reload"
		if !forced {
			name = "refresh ticker"
		}
		t.Run(name, func(t *testing.T) {
			p := progForRefresh()
			p.cfg = &ctrld.Config{}
			refetch := 1 // seconds; only the ticker path waits for it
			p.cfg.Service.RefetchTime = &refetch
			p.stopCh = make(chan struct{})
			p.apiForceReloadCh = make(chan struct{})

			var mu sync.Mutex
			destinations := []string{"203.0.113.10"}
			fetched := make(chan struct{}, 1)
			stubResolverConfigFetch(t, func() *controld.ResolverConfig {
				mu.Lock()
				defer mu.Unlock()
				return &controld.ResolverConfig{DestinationIPs: append([]string(nil), destinations...)}
			}, fetched)

			startRefreshLoop(t, p)

			if forced {
				p.apiForceReloadCh <- struct{}{}
			}
			waitForCondition(t, "the destination to be applied", func() bool {
				return p.allowList.Contains(direct)
			})

			// The organization withdraws it; the next cycle must take it away.
			mu.Lock()
			destinations = nil
			mu.Unlock()

			if forced {
				p.apiForceReloadCh <- struct{}{}
			}
			waitForCondition(t, "the withdrawn destination to stop being allowed", func() bool {
				return !p.allowList.Contains(direct)
			})
		})
	}
}
