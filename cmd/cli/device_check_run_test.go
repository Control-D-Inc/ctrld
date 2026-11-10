package cli

import (
	"context"
	"errors"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/controld"
)

const deviceInvalidExitLine = "provisioning failed: stage=api code=API_DEVICE_INVALID (exit 32) http_status=404"

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

// waitForOne waits for the first Exit. A check that started on its own
// goroutine must reach Exit before the test stops the run, or the stop drops
// the answer.
func (r *exitRecorder) waitForOne(t *testing.T) {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); len(r.got()) == 0; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for Exit")
		}
	}
}

func (r *exitRecorder) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.lines...)
}

// stubDeviceCheck sets the platform to mobile or desktop and replaces the
// device fetch with fetch until the test ends. An uninstall fails the test,
// because the real one changes the host and ends the process. The uninstall
// runs on its own goroutine, so the test checks for it at the end, not in
// the stub.
func stubDeviceCheck(t *testing.T, mobile bool, fetch func(context.Context, *controld.ResolverConfigRequest, bool) (*controld.ResolverConfig, error)) {
	t.Helper()
	oldFetch, oldUID, oldIsMobile, oldUninstall := fetchResolverConfig, cdUID, isMobile, selfUninstallFn
	var uninstalled atomic.Bool
	t.Cleanup(func() {
		fetchResolverConfig, cdUID, isMobile, selfUninstallFn = oldFetch, oldUID, oldIsMobile, oldUninstall
		if uninstalled.Load() {
			t.Error("the device check started the uninstall")
		}
	})
	fetchResolverConfig = fetch
	cdUID = "test-uid"
	isMobile = func() bool { return mobile }
	selfUninstallFn = func(*prog, zerolog.Logger) { uninstalled.Store(true) }
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
	close(p.runDone)
	p.canSelfUninstall.Store(true)
	p.refusedQueryCount.Store(selfUninstallMaxQueries + 1)
	return p
}

func refusedAnswer() *dns.Msg {
	answer := new(dns.Msg)
	answer.SetRcode(newDnsMsgWithHostname("example.com.", dns.TypeA), dns.RcodeRefused)
	return answer
}

// startDeviceCheck claims the check and runs it on its own goroutine, as the
// DNS handler does, and returns a channel that closes when the check returns.
//
// The test does not end before the check returns: the cleanup stops the run
// and waits for the check. Otherwise a check that outlives a failed test sees
// the real globals that stubDeviceCheck puts back. A test that holds the check
// must release it in a cleanup that it registers after this call, because
// cleanups run last in, first out.
func startDeviceCheck(t *testing.T, p *prog) <-chan struct{} {
	t.Helper()
	done := make(chan struct{})
	p.checkingSelfUninstall.Store(true)
	go func() {
		defer close(done)
		p.checkDeviceStatus()
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

// The answer of a device check must not reach the app after its run stopped.
// The app can start the next run as soon as the stop returns, and an app with
// one callback for all runs would then reject the resolver UID of the new run.
func TestDeviceCheckDoesNotExitAfterItsRunStopped(t *testing.T) {
	entered, release, fetchReturned := make(chan struct{}), make(chan struct{}), make(chan struct{})
	// The fetch ignores its context, like a request stuck in the network, so
	// the stop cannot rely on the cancel to end it.
	stubDeviceCheck(t, true, func(context.Context, *controld.ResolverConfigRequest, bool) (*controld.ResolverConfig, error) {
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

	// The app can now start the next run with the same callback object, so an
	// Exit from here on would land in that run.
	releaseFetch()
	waitNetworkShutdownSignal(t, fetchReturned, "the held fetch to return")
	waitNetworkShutdownSignal(t, checkDone, "the device check to return")

	if lines := exits.got(); len(lines) != 0 {
		t.Fatalf("the device check of a stopped run called Exit: %q", lines)
	}
}

// The stop of the run cancels the context of the fetch, so a real request
// ends at the stop and does not run on for a run that ended.
func TestDeviceCheckStopCancelsTheFetch(t *testing.T) {
	entered, fetchErr := make(chan struct{}), make(chan error, 1)
	stubDeviceCheck(t, true, func(ctx context.Context, _ *controld.ResolverConfigRequest, _ bool) (*controld.ResolverConfig, error) {
		close(entered)
		<-ctx.Done()
		fetchErr <- ctx.Err()
		return nil, ctx.Err()
	})
	run := newDeviceCheckRun(nil)

	startDeviceCheck(t, run)
	waitNetworkShutdownSignal(t, entered, "the device fetch")
	waitNetworkShutdownSignal(t, stopRun(run), "finishRun")

	select {
	case err := <-fetchErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("fetch context error = %v, want %v", err, context.Canceled)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the stop of the run did not cancel the device fetch")
	}
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

// A stop can come just after the fetch returned. The answer then belongs to a
// run that ended, so it must not reach Exit. The select in fetchDeviceStatus
// cannot force this order, so the test calls the step after the fetch.
func TestDeviceStatusAfterTheStopDoesNotReachExit(t *testing.T) {
	for _, stop := range runStops {
		t.Run(stop.name, func(t *testing.T) {
			stubDeviceCheck(t, true, fetchDeviceInvalid)
			exits := &exitRecorder{}
			run := newDeviceCheckRun(exits.callback())
			close(stop.ch(run))

			run.selfUninstallMu.Lock()
			run.reportDeviceStatus(deviceInvalidErr(), zerolog.Nop())
			run.selfUninstallMu.Unlock()

			if lines := exits.got(); len(lines) != 0 {
				t.Fatalf("the answer of a stopped run reached Exit: %q", lines)
			}
		})
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
	var fetches atomic.Int32
	stubDeviceCheck(t, true, func(context.Context, *controld.ResolverConfigRequest, bool) (*controld.ResolverConfig, error) {
		fetches.Add(1)
		return nil, deviceInvalidErr()
	})
	run := newDeviceCheckRun(nil)
	// Only the step of finishRun that ends the checks. With the stop channels
	// still open, a check that ignored the end would wait for its fetch, so
	// the count below would see it.
	run.endDeviceCheck()

	waitNetworkShutdownSignal(t, startDeviceCheck(t, run), "the late device check")

	if got := fetches.Load(); got != 0 {
		t.Fatalf("a device check after finishRun fetched %d times", got)
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
	if !strings.Contains(logs.String(), "the stop waits for the device check") {
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
	selfUninstallFn = func(*prog, zerolog.Logger) {
		close(inUninstall)
		<-leaveUninstall
	}
	run := newDeviceCheckRun(nil)

	startDeviceCheck(t, run)
	t.Cleanup(func() { close(leaveUninstall) })
	waitNetworkShutdownSignal(t, inUninstall, "the device check to start the uninstall")
	waitNetworkShutdownSignal(t, stopRun(run), "finishRun during the desktop uninstall")
}

const answerGoroutineCreator = "/cmd/cli.(*prog).countAnswerForDeviceCheck in goroutine"

// answerGoroutinesWaitingOnALock counts the goroutines that the DNS handler
// started for an answer and that wait on a mutex.
func answerGoroutinesWaitingOnALock() int {
	waiting := 0
	for _, stack := range strings.Split(allGoroutineStacks(), "\n\n") {
		header, _, _ := strings.Cut(stack, "\n")
		if strings.Contains(header, "[sync.Mutex.Lock") && strings.Contains(stack, answerGoroutineCreator) {
			waiting++
		}
	}
	return waiting
}

// requireAnswerGoroutineCreator fails the test when no goroutine has the
// creator that answerGoroutinesWaitingOnALock looks for. The check that holds
// the fetch has it, so a stale name fails here and does not make the count 0.
func requireAnswerGoroutineCreator(t *testing.T) {
	t.Helper()
	if !strings.Contains(allGoroutineStacks(), answerGoroutineCreator) {
		t.Fatalf("no goroutine was created by %q: update the name", answerGoroutineCreator)
	}
}

// allGoroutineStacks grows the buffer until the dump fits, because
// runtime.Stack cuts the dump at the end of the buffer.
func allGoroutineStacks() string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return string(buf[:n])
		}
		buf = make([]byte, 2*len(buf))
	}
}

// A deleted device makes every answer REFUSED. If the answers that come during
// a device check waited for its fetch, one goroutine would wait for each query
// until the fetch ends.
func TestAnswersDuringDeviceCheckDoNotWaitForTheFetch(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var fetches atomic.Int32
	stubDeviceCheck(t, true, func(context.Context, *controld.ResolverConfigRequest, bool) (*controld.ResolverConfig, error) {
		if fetches.Add(1) == 1 {
			close(entered)
		}
		<-release
		return nil, deviceInvalidErr()
	})
	exits := &exitRecorder{}
	run := newDeviceCheckRun(exits.callback())
	// finishRun waits for the check, so the check ends before the stubs go
	// back. Cleanups run last in, first out: the fetch is released first.
	t.Cleanup(func() {
		if !stopRequested(run.stopCh) {
			<-stopRun(run)
		}
	})
	var releaseOnce sync.Once
	releaseFetch := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseFetch)

	run.countAnswerForDeviceCheck(refusedAnswer())
	waitNetworkShutdownSignal(t, entered, "the device fetch")
	requireAnswerGoroutineCreator(t)

	const answersDuringCheck = 200
	answered := make(chan struct{})
	go func() {
		defer close(answered)
		for range answersDuringCheck {
			run.countAnswerForDeviceCheck(refusedAnswer())
		}
	}()
	waitNetworkShutdownSignal(t, answered, "the answers during the check, which must not wait")
	// A goroutine needs a moment to reach the lock.
	for deadline := time.Now().Add(500 * time.Millisecond); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if waiting := answerGoroutinesWaitingOnALock(); waiting > 0 {
			t.Fatalf("%d of %d answers wait for the device fetch", waiting, answersDuringCheck)
		}
	}

	releaseFetch()
	exits.waitForOne(t)
	waitNetworkShutdownSignal(t, stopRun(run), "finishRun after the fetch")
	if got := fetches.Load(); got != 1 {
		t.Errorf("device fetches = %d, want 1", got)
	}
	if lines := exits.got(); len(lines) != 1 || lines[0] != deviceInvalidExitLine {
		t.Errorf("Exit lines = %q, want [%q]", lines, deviceInvalidExitLine)
	}
}

// The check starts on the first REFUSED answer after more than
// selfUninstallMaxQueries of them, and answers with another code do not count.
func TestDeviceCheckStartsAfterTheRefusedCount(t *testing.T) {
	var fetches atomic.Int32
	stubDeviceCheck(t, true, func(context.Context, *controld.ResolverConfigRequest, bool) (*controld.ResolverConfig, error) {
		fetches.Add(1)
		return nil, deviceInvalidErr()
	})
	exits := &exitRecorder{}
	run := newDeviceCheckRun(exits.callback())
	run.refusedQueryCount.Store(0)
	// finishRun waits for a check in progress, so no check outlives the stubs.
	t.Cleanup(func() { <-stopRun(run) })

	answered := new(dns.Msg)
	answered.SetRcode(newDnsMsgWithHostname("example.com.", dns.TypeA), dns.RcodeSuccess)
	run.countAnswerForDeviceCheck(answered)
	for range selfUninstallMaxQueries + 1 {
		run.countAnswerForDeviceCheck(refusedAnswer())
	}
	if run.checkingSelfUninstall.Load() {
		t.Fatalf("the check started after %d REFUSED answers", selfUninstallMaxQueries+1)
	}

	run.countAnswerForDeviceCheck(refusedAnswer())
	if !run.checkingSelfUninstall.Load() {
		t.Fatalf("the check did not start on REFUSED answer %d", selfUninstallMaxQueries+2)
	}
	exits.waitForOne(t)
	if got := fetches.Load(); got != 1 {
		t.Errorf("device fetches = %d, want 1", got)
	}
}

// The DNS handler serves queries in parallel, so many answers can pass the
// count at the same time. Only one of them starts the check. A second check
// would wait on the lock for the fetch of the first. One burst seldom hits the
// race, so the test runs many bursts.
func TestParallelAnswersStartOneDeviceCheck(t *testing.T) {
	for round := range 20 {
		t.Run(strconv.Itoa(round), testOneBurstStartsOneDeviceCheck)
	}
}

func testOneBurstStartsOneDeviceCheck(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var fetches atomic.Int32
	stubDeviceCheck(t, true, func(context.Context, *controld.ResolverConfigRequest, bool) (*controld.ResolverConfig, error) {
		if fetches.Add(1) == 1 {
			close(entered)
		}
		<-release
		return nil, deviceInvalidErr()
	})
	run := newDeviceCheckRun(nil)
	t.Cleanup(func() { <-stopRun(run) })
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })

	// The answers spin on a flag, not on a channel: a channel wakes them one
	// by one, and the first answer then ends before the next one starts.
	var start atomic.Bool
	var ready, answers sync.WaitGroup
	for range max(2, runtime.GOMAXPROCS(0)-1) {
		ready.Add(1)
		answers.Go(func() {
			answer := refusedAnswer()
			ready.Done()
			for !start.Load() {
			}
			run.countAnswerForDeviceCheck(answer)
		})
	}
	ready.Wait()
	start.Store(true)
	answered := make(chan struct{})
	go func() {
		defer close(answered)
		answers.Wait()
	}()
	waitNetworkShutdownSignal(t, answered, "the answers, which must not wait")
	waitNetworkShutdownSignal(t, entered, "the device fetch")
	requireAnswerGoroutineCreator(t)

	for deadline := time.Now().Add(20 * time.Millisecond); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if waiting := answerGoroutinesWaitingOnALock(); waiting > 0 {
			t.Fatalf("%d more device checks started and wait for the first", waiting)
		}
	}
}

// After the cool-off, the count starts again from 0, so the next check starts
// on the same answer as the first one did.
func TestDeviceCheckCountStartsAgainAfterTheCoolOff(t *testing.T) {
	var fetches atomic.Int32
	// An answer that is not a deleted device: no Exit, and the cool-off runs.
	stubDeviceCheck(t, true, func(context.Context, *controld.ResolverConfigRequest, bool) (*controld.ResolverConfig, error) {
		fetches.Add(1)
		return nil, errors.New("the API is down")
	})
	oldCoolOff := deviceCheckCoolOff
	t.Cleanup(func() { deviceCheckCoolOff = oldCoolOff })
	deviceCheckCoolOff = 10 * time.Millisecond
	run := newDeviceCheckRun(nil)
	t.Cleanup(func() { <-stopRun(run) })

	run.countAnswerForDeviceCheck(refusedAnswer())
	waitForDeviceCheckState(t, "the end of the first cool-off", func() bool {
		return fetches.Load() == 1 && !run.checkingSelfUninstall.Load()
	})

	for range selfUninstallMaxQueries + 1 {
		run.countAnswerForDeviceCheck(refusedAnswer())
	}
	if run.checkingSelfUninstall.Load() {
		t.Fatalf("the second check started after %d REFUSED answers", selfUninstallMaxQueries+1)
	}
	run.countAnswerForDeviceCheck(refusedAnswer())
	// The cleanup puts deviceCheckCoolOff back, so the second cool-off must end
	// first.
	waitForDeviceCheckState(t, "the end of the second cool-off", func() bool {
		return fetches.Load() == 2 && !run.checkingSelfUninstall.Load()
	})
}

func waitForDeviceCheckState(t *testing.T, what string, reached func() bool) {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); !reached(); time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// Only a run with one Control D upstream checks the device. Other runs do not
// count their REFUSED answers.
func TestNoDeviceCheckWithoutOneControlDUpstream(t *testing.T) {
	var fetches atomic.Int32
	stubDeviceCheck(t, true, func(context.Context, *controld.ResolverConfigRequest, bool) (*controld.ResolverConfig, error) {
		fetches.Add(1)
		return nil, deviceInvalidErr()
	})
	run := newDeviceCheckRun(nil)
	run.canSelfUninstall.Store(false)
	run.refusedQueryCount.Store(0)
	t.Cleanup(func() { <-stopRun(run) })

	for range selfUninstallMaxQueries + 8 {
		run.countAnswerForDeviceCheck(refusedAnswer())
	}

	if count := run.refusedQueryCount.Load(); count != 0 {
		t.Errorf("refusedQueryCount = %d, want 0", count)
	}
	if run.checkingSelfUninstall.Load() {
		t.Error("a device check started without one Control D upstream")
	}
	if got := fetches.Load(); got != 0 {
		t.Errorf("device fetches = %d, want 0", got)
	}
}
