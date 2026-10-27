package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
)

// TestVersionTargetTrackedOnReload checks that every API config refresh
// records the version target, including a target that was cleared.
func TestVersionTargetTrackedOnReload(t *testing.T) {
	oldFetch, oldUID := fetchResolverConfigFn, cdUID
	oldTarget := cdVersionTarget.Load()
	t.Cleanup(func() {
		fetchResolverConfigFn, cdUID = oldFetch, oldUID
		cdVersionTarget.Store(oldTarget)
	})
	cdUID = "test-uid"
	cdVersionTarget.Store(nil)

	var target atomic.Value
	target.Store("1.5.8")
	fetchResolverConfigFn = func(context.Context, *controld.ResolverConfigRequest, bool) (*controld.ResolverConfig, error) {
		rc := &controld.ResolverConfig{}
		rc.Ctrld.VersionTarget = target.Load().(string)
		return rc, nil
	}

	p := &prog{
		cfg:              &ctrld.Config{Service: ctrld.ServiceConfig{RefetchTime: ptrTo(3600)}},
		stopCh:           make(chan struct{}),
		runAbortCh:       make(chan struct{}),
		apiForceReloadCh: make(chan struct{}),
		apiReloadCh:      make(chan *ctrld.Config, 8),
	}
	p.logger.Store(discardLogger())
	done := make(chan struct{})
	go func() { defer close(done); p.apiConfigReload() }()
	t.Cleanup(func() {
		close(p.stopCh)
		<-done
	})

	waitForTarget := func(want string) {
		t.Helper()
		p.apiForceReloadCh <- struct{}{}
		deadline := time.Now().Add(5 * time.Second)
		for {
			if got := versionTarget(); got == want {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("version target = %q after a reload, want %q", versionTarget(), want)
			}
			time.Sleep(time.Millisecond)
		}
	}
	waitForTarget("1.5.8")
	target.Store("")
	waitForTarget("")
}

func TestVersionTargetControlEndpoint(t *testing.T) {
	old := cdVersionTarget.Load()
	t.Cleanup(func() { cdVersionTarget.Store(old) })

	p := &prog{cfg: &ctrld.Config{}, cs: &controlServer{mux: http.NewServeMux()}}
	p.logger.Store(discardLogger())
	p.registerControlServerHandler()
	empty, target := "", "1.5.8"
	for _, tc := range []struct {
		stored *string
		want   string
	}{{&target, "1.5.8"}, {&empty, ""}, {nil, ""}} {
		cdVersionTarget.Store(tc.stored)
		want := tc.want
		rec := httptest.NewRecorder()
		p.cs.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, versionTargetPath, nil))
		if rec.Code != http.StatusOK || rec.Body.String() != want {
			t.Errorf("%s answered (%d, %q), want (200, %q)", versionTargetPath, rec.Code, rec.Body.String(), want)
		}
	}
}

// TestVersionTargetTrackedAtStartup checks that the startup config fetch
// records the version target, so it is known before the first reload.
func TestVersionTargetTrackedAtStartup(t *testing.T) {
	oldFetch, oldUID, oldStartup := fetchResolverConfig, cdUID, startupMetadata
	oldTarget := cdVersionTarget.Load()
	oldPin, oldKnown := cdDeactivationPin.Load(), deactivationPinKnown.Load()
	t.Cleanup(func() {
		fetchResolverConfig, cdUID, startupMetadata = oldFetch, oldUID, oldStartup
		cdVersionTarget.Store(oldTarget)
		cdDeactivationPin.Store(oldPin)
		deactivationPinKnown.Store(oldKnown)
	})
	cdUID = "test-uid"
	cdVersionTarget.Store(nil)
	startupMetadata = func(context.Context) map[string]string { return map[string]string{} }
	fetchResolverConfig = func(context.Context, *controld.ResolverConfigRequest, bool) (*controld.ResolverConfig, error) {
		rc := &controld.ResolverConfig{}
		rc.Ctrld.VersionTarget = "1.5.8"
		return rc, nil
	}

	_, _ = processCDFlags(context.Background(), &ctrld.Config{})
	if got := versionTarget(); got != "1.5.8" {
		t.Errorf("version target after startup = %q, want %q", got, "1.5.8")
	}
}
