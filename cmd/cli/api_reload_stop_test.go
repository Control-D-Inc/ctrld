package cli

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
)

// stubReload sets the platform and replaces the reload fetch until the test
// ends. The metadata collection returns nothing, so the test queries nothing
// on the host. The uninstall does nothing, because the real one changes the
// host and ends the process.
func stubReload(t *testing.T, mobile bool, fetch resolverConfigFetch) {
	t.Helper()
	oldFetch, oldMetadata, oldUID, oldDev, oldIsMobile, oldUninstall := fetchResolverConfigFn, runtimeMetadata, cdUID, cdDev, isMobile, selfUninstallFn
	t.Cleanup(func() {
		fetchResolverConfigFn, runtimeMetadata, cdUID, cdDev, isMobile, selfUninstallFn = oldFetch, oldMetadata, oldUID, oldDev, oldIsMobile, oldUninstall
	})
	fetchResolverConfigFn = fetch
	runtimeMetadata = noMetadata
	cdUID = "test-uid"
	isMobile = func() bool { return mobile }
	selfUninstallFn = func(*prog, *ctrld.Logger) {}
}

func noMetadata(context.Context) map[string]string { return nil }

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
	p.logger.Store(discardLogger())
	close(p.runDone)
	return p
}

// startReload starts the reload worker as the run does. The test does not
// end before the worker returns, so a worker that outlives a failed test does
// not see the real globals that stubReload puts back. A test that holds the
// worker must release it in a cleanup that it registers after this call,
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

// hold returns a wait that blocks until release is called. entered closes
// when the first wait starts. The wait takes no context, like the metadata
// collection, which does not stop at the cancel.
func hold() (wait func(), entered <-chan struct{}, release func()) {
	enteredCh, releaseCh := make(chan struct{}), make(chan struct{})
	var enterOnce, releaseOnce sync.Once
	wait = func() {
		enterOnce.Do(func() { close(enteredCh) })
		<-releaseCh
	}
	release = func() { releaseOnce.Do(func() { close(releaseCh) }) }
	return wait, enteredCh, release
}

// The stop of the run must not wait for a reload that holds on in the
// metadata collection or in the fetch, because neither stops at the cancel.
func TestReloadStopDoesNotWaitForTheFetch(t *testing.T) {
	for _, platform := range platforms {
		for _, held := range []string{"metadata", "fetch"} {
			t.Run(platform.name+"/"+held, func(t *testing.T) {
				stubReload(t, platform.mobile, fetchDeviceInvalid)
				wait, entered, release := hold()
				if held == "metadata" {
					runtimeMetadata = func(context.Context) map[string]string { wait(); return nil }
				} else {
					fetchResolverConfigFn = func(context.Context, *controld.ResolverConfigRequest, bool) (*controld.ResolverConfig, error) {
						wait()
						return nil, deviceInvalidErr()
					}
				}
				run := newReloadRun(nil)

				startReload(t, run)
				t.Cleanup(release)
				forceReload(t, run)
				waitNetworkShutdownSignal(t, entered, "the reload to hold in the "+held)
				waitNetworkShutdownSignal(t, stopRun(run), "finishRun while the reload holds in the "+held)
			})
		}
	}
}

// On mobile the next run starts in the same process, and it writes the
// globals of the reload. The fetch of an ended run goes on during that run.
// It must use what its own run read, and its answer must change nothing: not
// the state of either run, and not the deactivation PIN.
func TestLateReloadAnswerChangesNothing(t *testing.T) {
	oldPin, oldKnown := cdDeactivationPin.Load(), deactivationPinKnown.Load()
	t.Cleanup(func() {
		cdDeactivationPin.Store(oldPin)
		deactivationPinKnown.Store(oldKnown)
	})
	latePin := int64(424242)
	lateAnswer := &controld.ResolverConfig{Exclude: []string{"late.example"}, DeactivationPin: &latePin}
	// servedA names the fetch that got the request of run A.
	servedA := make(chan string, 4)
	stubReload(t, true, func(_ context.Context, _ *controld.ResolverConfigRequest, dev bool) (*controld.ResolverConfig, error) {
		servedA <- fmt.Sprintf("fetch of run A with dev=%t", dev)
		return lateAnswer, nil
	})
	uidA := cdUID
	waitA, enteredA, releaseA := hold()
	runtimeMetadata = func(context.Context) map[string]string { waitA(); return nil }
	runA := newReloadRun(nil)
	rcA := runA.rc

	startReload(t, runA)
	t.Cleanup(releaseA)
	forceReload(t, runA)
	waitNetworkShutdownSignal(t, enteredA, "the metadata collection of run A")
	waitNetworkShutdownSignal(t, stopRun(runA), "finishRun of run A")

	// Run B writes the globals that run A read before its goroutine started.
	rcB := &controld.ResolverConfig{}
	cdUID, cdDev = "test-uid-b", true
	runtimeMetadata = noMetadata
	fetchResolverConfigFn = func(_ context.Context, req *controld.ResolverConfigRequest, dev bool) (*controld.ResolverConfig, error) {
		if req.RawUID == uidA {
			servedA <- fmt.Sprintf("fetch of run B with dev=%t", dev)
		}
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
	waitForCondition(t, "run B to apply its answer", runBApplied)

	releaseA()
	select {
	case got := <-servedA:
		if want := "fetch of run A with dev=false"; got != want {
			t.Errorf("the late request of run A went to the %s, want the %s", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the late request of run A")
	}
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

// An answer that arrives with the stop belongs to a run that ended. It must
// change nothing, not even the deactivation PIN, which outlives the run.
func TestFetchedConfigAfterTheStopChangesNothing(t *testing.T) {
	oldPin, oldKnown := cdDeactivationPin.Load(), deactivationPinKnown.Load()
	t.Cleanup(func() {
		cdDeactivationPin.Store(oldPin)
		deactivationPinKnown.Store(oldKnown)
	})
	cdDeactivationPin.Store(defaultDeactivationPin)
	deactivationPinKnown.Store(false)
	run := newReloadRun(nil)
	rc := run.rc
	latePin := int64(424242)
	lateAnswer := &controld.ResolverConfig{Exclude: []string{"late.example"}, DeactivationPin: &latePin}
	stopped, cancel := context.WithCancel(context.Background())
	cancel()

	const lastUpdated = 7
	if got := run.applyFetchedResolverConfig(stopped, discardLogger(), lateAnswer, true, lastUpdated); got != lastUpdated {
		t.Errorf("lastUpdated = %d, want %d", got, lastUpdated)
	}
	if run.rc != rc {
		t.Errorf("the answer after the stop replaced the resolver config: %+v", run.rc)
	}
	if pin := cdDeactivationPin.Load(); pin == latePin {
		t.Errorf("the answer after the stop stored its deactivation PIN %d", pin)
	}
	if deactivationPinKnown.Load() {
		t.Error("the answer after the stop marked the deactivation PIN as known")
	}
}

// The fetch of a stopped run sends its answer to a channel that nobody reads
// any more. Its goroutine must still end, or each stop during a fetch leaks
// one on mobile, where the process lives on.
func TestFetchUntilDoneEndsItsGoroutineAfterTheStop(t *testing.T) {
	wait, entered, release := hold()
	t.Cleanup(release)
	fetch := func(context.Context, *controld.ResolverConfigRequest, bool) (*controld.ResolverConfig, error) {
		wait()
		return &controld.ResolverConfig{}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	returned := make(chan error, 1)
	go func() {
		_, err := fetchUntilDone(ctx, noMetadata, fetch, &controld.ResolverConfigRequest{}, false)
		returned <- err
	}()
	waitNetworkShutdownSignal(t, entered, "the fetch")

	cancel()
	select {
	case err := <-returned:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("fetchUntilDone error = %v, want %v", err, context.Canceled)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fetchUntilDone did not return at the stop")
	}
	release()
	waitForCondition(t, "the goroutine of fetchUntilDone to end", func() bool {
		return !goroutineRuns("cli.fetchUntilDone.func")
	})
}

// goroutineRuns reports whether a goroutine has a frame whose name contains
// frame.
func goroutineRuns(frame string) bool {
	stacks := make([]byte, 1<<20)
	n := runtime.Stack(stacks, true)
	return strings.Contains(string(stacks[:n]), frame)
}

// On desktop the uninstall of a deleted device stops the service, and that
// stop waits for this process to exit. The reload must not keep finishRun
// waiting for it, or the stop hangs until the service manager kills ctrld.
func TestFinishRunDoesNotWaitForTheUninstallOfTheReload(t *testing.T) {
	stubReload(t, false, fetchDeviceInvalid)
	inUninstall, leaveUninstall := make(chan struct{}), make(chan struct{})
	selfUninstallFn = func(*prog, *ctrld.Logger) {
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
	run.logger.Store(mainLog.Load())

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
	// A slow runner can fire the warning timer late, so poll for the line.
	warned := func() bool { return strings.Contains(logs.String(), "The stop waits for the configuration reload") }
	for deadline := time.Now().Add(2 * time.Second); !warned() && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	if !warned() {
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
	selfUninstallFn = func(*prog, *ctrld.Logger) {
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
			selfUninstallCheck(deviceInvalidErr(), p, discardLogger())
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
	waitForCondition(t, "an uninstall to start again after the first one returned", func() bool {
		selfUninstallCheck(deviceInvalidErr(), p, discardLogger())
		select {
		case <-started:
			return true
		default:
			return false
		}
	})
}
