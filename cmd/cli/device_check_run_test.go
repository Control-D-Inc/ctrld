package cli

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
)

// exitRecorder is an app callback that keeps one object for all runs, so a
// late Exit of an old run reaches it during the next run.
type exitRecorder struct {
	mu    sync.Mutex
	lines []string
}

func (r *exitRecorder) callback() *AppCallback {
	return &AppCallback{Exit: func(line string) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.lines = append(r.lines, line)
	}}
}

func (r *exitRecorder) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.lines...)
}

// stubDeviceCheck sets the platform to mobile or desktop and replaces the
// device fetch with fetch until the test ends. The uninstall fails the test,
// because the real one changes the host and ends the process.
func stubDeviceCheck(t *testing.T, mobile bool, fetch func(context.Context, *controld.ResolverConfigRequest, bool) (*controld.ResolverConfig, error)) {
	t.Helper()
	oldFetch, oldUID, oldIsMobile, oldUninstall := fetchResolverConfig, cdUID, isMobile, selfUninstallFn
	t.Cleanup(func() {
		fetchResolverConfig, cdUID, isMobile, selfUninstallFn = oldFetch, oldUID, oldIsMobile, oldUninstall
	})
	fetchResolverConfig = fetch
	cdUID = "test-uid"
	isMobile = func() bool { return mobile }
	selfUninstallFn = func(*prog, *ctrld.Logger) { t.Error("the device check started the uninstall") }
}

// fetchDeviceInvalid is a device fetch that reports a deleted device.
func fetchDeviceInvalid(context.Context, *controld.ResolverConfigRequest, bool) (*controld.ResolverConfig, error) {
	return nil, deviceInvalidErr()
}

// newDeviceCheckRun returns the prog of one run whose next REFUSED answer
// starts the device check.
func newDeviceCheckRun(callback *AppCallback) *prog {
	p := &prog{
		cfg: &ctrld.Config{}, stopCh: make(chan struct{}), runAbortCh: make(chan struct{}),
		runDone: make(chan struct{}), dnsWatcherStopCh: make(chan struct{}),
		appCallback: callback,
	}
	p.logger.Store(discardLogger())
	close(p.runDone)
	p.canSelfUninstall.Store(true)
	p.refusedQueryCount = selfUninstallMaxQueries + 1
	return p
}

func refusedAnswer() *proxyResponse {
	answer := new(dns.Msg)
	answer.SetRcode(newDnsMsgWithHostname("example.com.", dns.TypeA), dns.RcodeRefused)
	return &proxyResponse{answer: answer}
}

// startDeviceCheck runs the check on its own goroutine, as the DNS handler
// does, and returns a channel that closes when the check returns.
//
// The test does not end before the check returns: the cleanup stops the run
// and waits for the check. Otherwise a check that outlives a failed test sees
// the real globals that stubDeviceCheck puts back. A test that holds the check
// must release it in a cleanup that it registers after this call, because
// cleanups run last in, first out.
func startDeviceCheck(t *testing.T, p *prog) <-chan struct{} {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.doSelfUninstall(refusedAnswer())
	}()
	t.Cleanup(func() {
		if !stopRequested(p.stopCh) {
			close(p.stopCh)
		}
		<-done
	})
	return done
}

// stopRun stops the run the way the stop request and run() do, and
// returns a channel that closes when finishRun returns.
func stopRun(p *prog) <-chan struct{} {
	close(p.stopCh)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		p.finishRun()
	}()
	return finished
}

// platforms are the two kinds of run. Mobile sends a deleted device to Exit,
// and desktop starts the uninstall, which the stub of stubDeviceCheck turns
// into a test failure.
var platforms = []struct {
	name   string
	mobile bool
}{
	{"mobile", true},
	{"desktop", false},
}

// runStops are the two channels that end a run: the stop request of the app
// or the service, and the abort that finishRun sends.
var runStops = []struct {
	name string
	ch   func(*prog) chan struct{}
}{
	{"stop request", func(p *prog) chan struct{} { return p.stopCh }},
	{"run abort", func(p *prog) chan struct{} { return p.runAbortCh }},
}

// The answer of a device check must not act after its run stopped. On mobile
// the app can start the next run as soon as the stop returns, and an app with
// one callback for all runs would then reject the resolver UID of the new run.
func TestDeviceCheckDoesNotActAfterItsRunStopped(t *testing.T) {
	for _, platform := range platforms {
		t.Run(platform.name, func(t *testing.T) {
			entered, release, fetchReturned := make(chan struct{}), make(chan struct{}), make(chan struct{})
			// The fetch ignores its context, like a request stuck in the
			// network, so the stop cannot rely on the cancel to end it.
			stubDeviceCheck(t, platform.mobile, func(context.Context, *controld.ResolverConfigRequest, bool) (*controld.ResolverConfig, error) {
				defer close(fetchReturned)
				close(entered)
				<-release
				return nil, deviceInvalidErr()
			})
			exits := &exitRecorder{}
			runA := newDeviceCheckRun(exits.callback())

			checkDone := startDeviceCheck(t, runA)
			var releaseOnce sync.Once
			releaseFetch := func() { releaseOnce.Do(func() { close(release) }) }
			t.Cleanup(releaseFetch)
			waitNetworkShutdownSignal(t, entered, "the device fetch")
			waitNetworkShutdownSignal(t, stopRun(runA), "finishRun while the fetch is held")

			// The app can now start the next run with the same callback
			// object, so an Exit from here on would land in that run.
			releaseFetch()
			waitNetworkShutdownSignal(t, fetchReturned, "the held fetch to return")
			waitNetworkShutdownSignal(t, checkDone, "the device check to return")

			if lines := exits.got(); len(lines) != 0 {
				t.Fatalf("the device check of a stopped run called Exit: %q", lines)
			}
		})
	}
}

// Each stop of the run cancels the context of the fetch, so a real request
// ends at the stop and does not run on for a run that ended.
func TestDeviceCheckStopCancelsTheFetch(t *testing.T) {
	for _, stop := range runStops {
		t.Run(stop.name, func(t *testing.T) {
			entered, fetchErr, testEnded := make(chan struct{}), make(chan error, 1), make(chan struct{})
			stubDeviceCheck(t, true, func(ctx context.Context, _ *controld.ResolverConfigRequest, _ bool) (*controld.ResolverConfig, error) {
				close(entered)
				// The end of the test also returns, so a fetch that is
				// never cancelled fails the test and does not hang it.
				select {
				case <-ctx.Done():
				case <-testEnded:
				}
				fetchErr <- ctx.Err()
				return nil, ctx.Err()
			})
			run := newDeviceCheckRun(nil)

			startDeviceCheck(t, run)
			t.Cleanup(func() { close(testEnded) })
			waitNetworkShutdownSignal(t, entered, "the device fetch")
			close(stop.ch(run))

			select {
			case err := <-fetchErr:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("fetch context error = %v, want %v", err, context.Canceled)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("the stop of the run did not cancel the device fetch")
			}
		})
	}
}

// A stop can come just after the fetch returned. The answer then belongs to a
// run that ended, so it must not act. The select in fetchDeviceStatus cannot
// force this order, so the test calls the step after the fetch.
func TestDeviceStatusAfterTheStopDoesNotAct(t *testing.T) {
	for _, platform := range platforms {
		for _, stop := range runStops {
			t.Run(platform.name+"/"+stop.name, func(t *testing.T) {
				stubDeviceCheck(t, platform.mobile, fetchDeviceInvalid)
				exits := &exitRecorder{}
				run := newDeviceCheckRun(exits.callback())
				close(stop.ch(run))

				run.selfUninstallMu.Lock()
				run.reportDeviceStatus(deviceInvalidErr(), discardLogger())
				run.selfUninstallMu.Unlock()

				if lines := exits.got(); len(lines) != 0 {
					t.Fatalf("the answer of a stopped run reached Exit: %q", lines)
				}
			})
		}
	}
}

// The 30-minute cool-off after a device check ends with its run. Otherwise it
// keeps the prog of an ended mobile run in memory for that time.
func TestDeviceCheckCoolOffEndsWithTheRun(t *testing.T) {
	for _, stop := range runStops {
		t.Run(stop.name, func(t *testing.T) {
			run := newDeviceCheckRun(nil)
			coolOffDone := make(chan struct{})
			go func() {
				defer close(coolOffDone)
				run.selfUninstallCoolOfPeriod()
			}()

			close(stop.ch(run))
			waitNetworkShutdownSignal(t, coolOffDone, "the cool-off to end with the run")
		})
	}
}

// After finishRun no device check starts, so a late REFUSED answer of the run
// sends no request to the API.
func TestNoDeviceCheckStartsAfterFinishRun(t *testing.T) {
	stubDeviceCheck(t, true, fetchDeviceInvalid)
	run := newDeviceCheckRun(nil)
	waitNetworkShutdownSignal(t, stopRun(run), "finishRun")

	waitNetworkShutdownSignal(t, startDeviceCheck(t, run), "the late device check")

	run.selfUninstallMu.Lock()
	started := run.checkingSelfUninstall
	run.selfUninstallMu.Unlock()
	if started {
		t.Fatal("a device check started after finishRun")
	}
}

// The end of one run must not disable the device check of the next run in
// the same process.
func TestDeviceCheckRunsInTheNextRun(t *testing.T) {
	stubDeviceCheck(t, true, fetchDeviceInvalid)
	exits := &exitRecorder{}
	runA := newDeviceCheckRun(exits.callback())
	waitNetworkShutdownSignal(t, stopRun(runA), "finishRun of run A")

	runB := newDeviceCheckRun(exits.callback())
	waitNetworkShutdownSignal(t, startDeviceCheck(t, runB), "the device check of run B")

	if lines := exits.got(); len(lines) != 1 || lines[0] != deviceInvalidExitLine {
		t.Fatalf("Exit lines of run B = %q, want [%q]", lines, deviceInvalidExitLine)
	}
}

// On mobile the end of the run waits for a check that is already in Exit, so
// the Exit reaches the app before the app can start the next run. A long wait
// writes a warning, because the usual cause is an Exit that waits for the run.
func TestFinishRunWaitsForDeviceCheckInExit(t *testing.T) {
	stubDeviceCheck(t, true, fetchDeviceInvalid)
	logs := captureMainLog(t)
	oldWarning := deviceCheckWaitWarning
	t.Cleanup(func() { deviceCheckWaitWarning = oldWarning })
	deviceCheckWaitWarning = 10 * time.Millisecond
	inExit, leaveExit := make(chan struct{}), make(chan struct{})
	run := newDeviceCheckRun(&AppCallback{Exit: func(string) {
		close(inExit)
		<-leaveExit
	}})
	run.logger.Store(mainLog.Load())

	checkDone := startDeviceCheck(t, run)
	var leaveOnce sync.Once
	leave := func() { leaveOnce.Do(func() { close(leaveExit) }) }
	t.Cleanup(leave)
	waitNetworkShutdownSignal(t, inExit, "the device check to call Exit")
	finished := stopRun(run)
	select {
	case <-finished:
		t.Fatal("finishRun returned while the device check of its run was still in Exit")
	case <-time.After(100 * time.Millisecond):
	}
	// A slow runner can fire the warning timer late, so poll for the line.
	warned := func() bool { return strings.Contains(logs.String(), "The stop waits for the device check") }
	for deadline := time.Now().Add(2 * time.Second); !warned() && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	if !warned() {
		t.Errorf("no warning while the stop waited for Exit; log: %s", logs.String())
	}

	leave()
	waitNetworkShutdownSignal(t, finished, "finishRun after Exit returned")
	waitNetworkShutdownSignal(t, checkDone, "the device check to return")
}

// On desktop the uninstall of a deleted device stops the service, and that
// stop waits for this process to exit. So finishRun must not wait for it.
func TestFinishRunDoesNotWaitForDesktopUninstall(t *testing.T) {
	stubDeviceCheck(t, false, fetchDeviceInvalid)
	inUninstall, leaveUninstall := make(chan struct{}), make(chan struct{})
	selfUninstallFn = func(*prog, *ctrld.Logger) {
		close(inUninstall)
		<-leaveUninstall
	}
	run := newDeviceCheckRun(nil)

	startDeviceCheck(t, run)
	t.Cleanup(func() { close(leaveUninstall) })
	waitNetworkShutdownSignal(t, inUninstall, "the device check to start the uninstall")
	waitNetworkShutdownSignal(t, stopRun(run), "finishRun during the desktop uninstall")
}

// The debug line of the device check comes before the fetch, so the log
// shows a check that waits for the API.
func TestDeviceCheckLogsBeforeTheFetch(t *testing.T) {
	logs := captureMainLog(t)
	loggedFirst := false
	stubDeviceCheck(t, true, func(context.Context, *controld.ResolverConfigRequest, bool) (*controld.ResolverConfig, error) {
		loggedFirst = strings.Contains(logs.String(), "checking device status")
		return &controld.ResolverConfig{}, nil
	})
	run := newDeviceCheckRun(nil)
	run.logger.Store(mainLog.Load())

	waitNetworkShutdownSignal(t, startDeviceCheck(t, run), "the device check")

	if !loggedFirst {
		t.Fatalf("the device check logged after the fetch; log: %s", logs.String())
	}
}
