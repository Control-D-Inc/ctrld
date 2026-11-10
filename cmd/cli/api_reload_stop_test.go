package cli

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
)

// stubReload sets the platform and replaces the reload fetch until the test
// ends. The uninstall does nothing, because the real one changes the host and
// ends the process.
func stubReload(t *testing.T, mobile bool, fetch resolverConfigFetch) {
	t.Helper()
	oldFetch, oldUID, oldDev, oldIsMobile, oldUninstall := fetchResolverConfigForReload, cdUID, cdDev, isMobile, selfUninstallFn
	t.Cleanup(func() {
		fetchResolverConfigForReload, cdUID, cdDev, isMobile, selfUninstallFn = oldFetch, oldUID, oldDev, oldIsMobile, oldUninstall
	})
	fetchResolverConfigForReload = fetch
	cdUID = "test-uid"
	isMobile = func() bool { return mobile }
	selfUninstallFn = func(*prog, zerolog.Logger) {}
}

// newReloadRun returns the prog of one run with what the reload and
// finishRun use.
func newReloadRun(callback *AppCallback) *prog {
	p := &prog{
		cfg:              &ctrld.Config{Service: ctrld.ServiceConfig{RefetchTime: ptrTo(3600)}},
		rc:               &controld.ResolverConfig{},
		stopCh:           make(chan struct{}),
		runAbortCh:       make(chan struct{}),
		runDone:          make(chan struct{}),
		dnsWatcherStopCh: make(chan struct{}),
		apiForceReloadCh: make(chan struct{}),
		apiReloadCh:      make(chan *ctrld.Config),
		appCallback:      callback,
	}
	close(p.runDone)
	return p
}

// startReload starts the reload worker as the run does. The test does not
// end before the worker returns, so a worker that outlives a failed test does
// not see the real globals that stubReload puts back. A test that holds the
// fetch must release it in a cleanup that it registers after this call,
// because cleanups run last in, first out.
func startReload(t *testing.T, p *prog) {
	t.Helper()
	p.startAPIConfigReload()
	t.Cleanup(func() {
		if !stopRequested(p.stopCh) {
			close(p.stopCh)
		}
		p.apiReloadWg.Wait()
	})
}

// forceReload makes the worker fetch now, as a query for the verify domain
// does.
func forceReload(t *testing.T, p *prog) {
	t.Helper()
	select {
	case p.apiForceReloadCh <- struct{}{}:
	case <-time.After(2 * time.Second):
		t.Fatal("the reload worker did not take the forced reload")
	}
}

// holdFetch returns a fetch that blocks until release is called and ignores
// its context, like the metadata collection, which does not take it. entered
// closes when the fetch starts, and returned closes when it returns.
func holdFetch(answer *controld.ResolverConfig, err error) (fetch resolverConfigFetch, entered, returned <-chan struct{}, release func()) {
	enteredCh, returnedCh, releaseCh := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	release = func() { releaseOnce.Do(func() { close(releaseCh) }) }
	fetch = func(context.Context, *controld.ResolverConfigRequest, bool) (*controld.ResolverConfig, error) {
		defer close(returnedCh)
		close(enteredCh)
		<-releaseCh
		return answer, err
	}
	return fetch, enteredCh, returnedCh, release
}

func platformName(mobile bool) string {
	if mobile {
		return "mobile"
	}
	return "desktop"
}

// The stop of the run must not wait for a reload fetch that does not return
// at the cancel. Before, finishRun waited for it in apiReloadWg.
func TestReloadStopDoesNotWaitForTheFetch(t *testing.T) {
	for _, mobile := range []bool{true, false} {
		t.Run(platformName(mobile), func(t *testing.T) {
			fetch, entered, _, release := holdFetch(nil, deviceInvalidErr())
			stubReload(t, mobile, fetch)
			run := newReloadRun(nil)

			startReload(t, run)
			t.Cleanup(release)
			forceReload(t, run)
			waitNetworkShutdownSignal(t, entered, "the reload fetch")
			waitNetworkShutdownSignal(t, stopRun(run), "finishRun while the reload fetch is held")
		})
	}
}

// On mobile the next run starts in the same process. The fetch of an ended
// run returns during that run, and its answer must change nothing: not the
// state of either run, and not the deactivation PIN.
func TestLateReloadAnswerChangesNothing(t *testing.T) {
	oldPin, oldKnown := cdDeactivationPin.Load(), deactivationPinKnown.Load()
	t.Cleanup(func() {
		cdDeactivationPin.Store(oldPin)
		deactivationPinKnown.Store(oldKnown)
	})
	latePin := int64(424242)
	lateAnswer := &controld.ResolverConfig{Exclude: []string{"late.example"}, DeactivationPin: &latePin}
	fetchA, enteredA, returnedA, releaseA := holdFetch(lateAnswer, nil)
	stubReload(t, true, fetchA)
	runA := newReloadRun(nil)
	rcA := runA.rc

	startReload(t, runA)
	t.Cleanup(releaseA)
	forceReload(t, runA)
	waitNetworkShutdownSignal(t, enteredA, "the reload fetch of run A")
	waitNetworkShutdownSignal(t, stopRun(runA), "finishRun of run A")

	// Run B writes the globals that run A read before its fetch started.
	rcB := &controld.ResolverConfig{}
	cdUID, cdDev = "test-uid-b", true
	fetchResolverConfigForReload = func(context.Context, *controld.ResolverConfigRequest, bool) (*controld.ResolverConfig, error) {
		return rcB, nil
	}
	runB := newReloadRun(nil)
	startReload(t, runB)
	forceReload(t, runB)
	runBApplied := func() bool {
		runB.mu.Lock()
		defer runB.mu.Unlock()
		return runB.rc == rcB
	}
	waitUntil(t, runBApplied, "run B to apply its answer")

	releaseA()
	waitNetworkShutdownSignal(t, returnedA, "the fetch of run A to return")
	// A force reload of run B waits for the worker to finish the earlier
	// one, so the checks below see everything that worker did.
	forceReload(t, runB)

	runA.mu.Lock()
	gotA := runA.rc
	runA.mu.Unlock()
	if gotA != rcA {
		t.Errorf("the late answer replaced the resolver config of run A: %+v", gotA)
	}
	if !runBApplied() {
		t.Error("the late answer replaced the resolver config of run B")
	}
	if pin := cdDeactivationPin.Load(); pin == latePin {
		t.Errorf("the late answer stored its deactivation PIN %d", pin)
	}
}

// On desktop the uninstall of a deleted device stops the service, and that
// stop waits for this process to exit. The reload must not keep finishRun
// waiting for it, or the stop hangs until the service manager kills ctrld.
func TestFinishRunDoesNotWaitForTheUninstallOfTheReload(t *testing.T) {
	stubReload(t, false, fetchDeviceInvalid)
	inUninstall, leaveUninstall := make(chan struct{}), make(chan struct{})
	selfUninstallFn = func(*prog, zerolog.Logger) {
		close(inUninstall)
		<-leaveUninstall
	}
	run := newReloadRun(nil)

	startReload(t, run)
	t.Cleanup(func() { close(leaveUninstall) })
	forceReload(t, run)
	waitNetworkShutdownSignal(t, inUninstall, "the reload to start the uninstall")
	waitNetworkShutdownSignal(t, stopRun(run), "finishRun during the desktop uninstall")
}

// On mobile the end of the run waits for a reload that is in Exit, so the
// Exit reaches the app before the app can start the next run. A long wait
// writes a warning, because the usual cause is an Exit that waits for the run.
func TestFinishRunWaitsForTheExitOfTheReload(t *testing.T) {
	stubReload(t, true, fetchDeviceInvalid)
	logs := captureMainLog(t)
	oldWarning := reloadWaitWarning
	t.Cleanup(func() { reloadWaitWarning = oldWarning })
	reloadWaitWarning = 10 * time.Millisecond
	inExit, leaveExit := make(chan struct{}), make(chan struct{})
	run := newReloadRun(&AppCallback{Exit: func(string) {
		close(inExit)
		<-leaveExit
	}})

	startReload(t, run)
	var leaveOnce sync.Once
	leave := func() { leaveOnce.Do(func() { close(leaveExit) }) }
	t.Cleanup(leave)
	forceReload(t, run)
	waitNetworkShutdownSignal(t, inExit, "the reload to call Exit")
	finished := stopRun(run)
	select {
	case <-finished:
		t.Fatal("finishRun returned while the reload of its run was still in Exit")
	case <-time.After(100 * time.Millisecond):
	}
	if !strings.Contains(logs.String(), "the stop waits for the configuration reload") {
		t.Errorf("no warning while the stop waited for Exit; log: %s", logs.String())
	}

	leave()
	waitNetworkShutdownSignal(t, finished, "finishRun after Exit returned")
}

// The reload goes on after it starts the desktop uninstall, so a later answer
// can find the device deleted again while the uninstall runs. Only one
// uninstall may run at a time. One that returned, as a failed uninstall on
// Windows does, can start again.
func TestDesktopUninstallRunsOnceAtATime(t *testing.T) {
	stubReload(t, false, fetchDeviceInvalid)
	started, leave := make(chan struct{}, 8), make(chan struct{})
	selfUninstallFn = func(*prog, zerolog.Logger) {
		started <- struct{}{}
		<-leave
	}
	var leaveOnce sync.Once
	t.Cleanup(func() { leaveOnce.Do(func() { close(leave) }) })
	p := newSelfUninstallTestProg()
	check := func() {
		t.Helper()
		returned := make(chan struct{})
		go func() {
			defer close(returned)
			selfUninstallCheck(deviceInvalidErr(), p, zerolog.Nop())
		}()
		waitNetworkShutdownSignal(t, returned, "selfUninstallCheck to return during the uninstall")
	}

	check()
	waitNetworkShutdownSignal(t, started, "the first uninstall")
	check()
	select {
	case <-started:
		t.Fatal("a second uninstall started while the first one ran")
	case <-time.After(100 * time.Millisecond):
	}

	leaveOnce.Do(func() { close(leave) })
	waitUntil(t, func() bool {
		selfUninstallCheck(deviceInvalidErr(), p, zerolog.Nop())
		select {
		case <-started:
			return true
		default:
			return false
		}
	}, "an uninstall to start again after the first one returned")
}

// waitUntil polls cond until it is true, and fails the test after 2 seconds.
func waitUntil(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}
