package cli

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Control-D-Inc/ctrld"
	"tailscale.com/net/netmon"
)

func guardNetworkShutdownHostMutations(t *testing.T) {
	t.Helper()
	oldReset, oldRemove := recoveryResetDNSFn, removeInterceptDNSTargetFn
	recoveryResetDNSFn = func(*prog, bool, bool) { panic("unexpected recovery DNS reset") }
	// Also fence the first platform boundary inside real resetDNS, so mutation
	// testing a bypassed recoveryResetDNSFn can never touch the test runner's DNS/PF.
	removeInterceptDNSTargetFn = func(*prog, string) { panic("real resetDNS crossed host safety boundary") }
	t.Cleanup(func() { recoveryResetDNSFn, removeInterceptDNSTargetFn = oldReset, oldRemove })
}

func waitNetworkShutdownSignal(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func waitNetworkShutdownGate(t *testing.T, p *prog) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !p.networkActivityClosed() {
		if time.Now().After(deadline) {
			t.Fatal("shutdown did not close admission")
		}
		time.Sleep(time.Millisecond)
	}
}

func assertNetworkShutdownBlocked(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
		t.Fatal("shutdown returned before admitted work finished")
	case <-time.After(20 * time.Millisecond):
	}
}

func TestNetworkShutdownRejectsLateMonitorPublication(t *testing.T) {
	p := &prog{}
	p.logger.Store(mainLog.Load())
	p.closeNetMonitor()
	// A zero monitor is never started or closed: on rejected publication the
	// initializer retains ownership. No OS monitor or DNS policy is installed.
	if p.setNetMonitor(new(netmon.Monitor)) {
		t.Fatal("monitor published after shutdown")
	}
	if p.netMonitor != nil {
		t.Fatal("shutdown retained a monitor")
	}
	if p.beginNetworkActivity() {
		p.netMonitorWG.Done()
		t.Fatal("work admitted after shutdown")
	}
}

func TestNetworkShutdownDrainsCallbacksAndConcurrentClosers(t *testing.T) {
	guardNetworkShutdownHostMutations(t)
	p := &prog{}
	p.logger.Store(mainLog.Load())
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	var calls atomic.Int32
	// Stub the entire callback body before any platform or DNS boundary. This
	// is the same wrapper used by RegisterChangeCallback in production.
	callback := p.networkChangeCallback(func(*netmon.ChangeDelta) {
		calls.Add(1)
		close(entered)
		<-release
		// An admitted callback may try to schedule recovery after Close fenced
		// admission. Neither synchronous nor deferred work may start then.
		p.debounceRecovery(p.networkAcceptedGen.Load())
		p.handleRecovery(RecoveryReasonNetworkChange)
	})
	go callback(nil)
	waitNetworkShutdownSignal(t, entered, "callback admission")

	closed1, closed2 := make(chan struct{}), make(chan struct{})
	go func() { p.closeNetMonitor(); close(closed1) }()
	waitNetworkShutdownGate(t, p)
	go func() { p.closeNetMonitor(); close(closed2) }()
	// Model a callback dispatched by netmon before Close but scheduled later.
	callback(nil)
	assertNetworkShutdownBlocked(t, closed1)
	assertNetworkShutdownBlocked(t, closed2)
	unblock()
	waitNetworkShutdownSignal(t, closed1, "first close")
	waitNetworkShutdownSignal(t, closed2, "second close")
	callback(nil)
	if calls.Load() != 1 || p.recoveryGen.Load() != 0 || p.recoveryDebounceTimer != nil {
		t.Fatalf("late work ran: callbacks=%d recovery=%d timer=%v", calls.Load(), p.recoveryGen.Load(), p.recoveryDebounceTimer)
	}
}

func TestNetworkShutdownCancelsAndDrainsRecovery(t *testing.T) {
	testNetworkShutdownCancelsAndDrainsRecovery(t, func(p *prog) {
		p.handleRecovery(RecoveryReasonRegularFailure)
	})
}

func TestNetworkShutdownDrainsDeferredRecovery(t *testing.T) {
	testNetworkShutdownCancelsAndDrainsRecovery(t, func(p *prog) {
		p.networkChangeCallback(func(*netmon.ChangeDelta) { p.debounceRecovery(p.networkAcceptedGen.Load()) })(nil)
	})
}

func testNetworkShutdownCancelsAndDrainsRecovery(t *testing.T, start func(*prog)) {
	logs := captureDebugMainLog(t)
	stubHeaderSnapshotSources(t)
	guardNetworkShutdownHostMutations(t)
	oldReset, oldIntercept := recoveryResetDNSFn, dnsIntercept
	dnsIntercept = false
	defer func() { recoveryResetDNSFn, dnsIntercept = oldReset, oldIntercept }()
	p := &prog{cfg: &ctrld.Config{}}
	p.logger.Store(mainLog.Load())
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	var resets atomic.Int32
	// resetDNS is the FIRST host-mutating boundary in traditional recovery.
	// Block there; never invoke real resetDNS, setDNS, PF, or NRPT operations.
	recoveryResetDNSFn = func(p *prog, isStart, restoreStatic bool) {
		resets.Add(1)
		p.recoveryCancelMu.Lock()
		cancel := p.recoveryCancel
		p.recoveryCancel = func() { cancel(); close(canceled) }
		p.recoveryCancelMu.Unlock()
		close(entered)
		<-release
	}
	recovered := make(chan struct{})
	go func() { start(p); close(recovered) }()
	waitNetworkShutdownSignal(t, entered, "recovery reset seam")
	closed := make(chan struct{})
	go func() { p.closeNetMonitor(); close(closed) }()
	waitNetworkShutdownSignal(t, canceled, "recovery cancellation")
	assertNetworkShutdownBlocked(t, closed)
	if p.recoveryOwnsState(p.recoveryGen.Load()) {
		t.Fatal("shutdown recovery still owns permission to reapply DNS")
	}
	unblock()
	waitNetworkShutdownSignal(t, closed, "recovery drain")
	waitNetworkShutdownSignal(t, recovered, "recovery return")
	p.handleRecovery(RecoveryReasonRegularFailure)
	p.handleRecovery(RecoveryReasonNetworkChange)
	if resets.Load() != 1 || p.recoveryRunning.Load() || p.recoveryBypass.Load() || p.recoveryCancel != nil {
		t.Fatalf("recovery survived close: resets=%d running=%v bypass=%v", resets.Load(), p.recoveryRunning.Load(), p.recoveryBypass.Load())
	}
	ends := jsonLogEvents(t, logs, "Recovery end")
	if len(ends) != 1 {
		t.Fatalf("recovery end events: got %d, want 1", len(ends))
	}
	wantField(t, ends[0], "outcome", recoveryOutcomeCanceled)
	wantField(t, ends[0], "bypass_active", false)
}

func TestNetworkShutdownCancelsIndefiniteRecoveryWait(t *testing.T) {
	guardNetworkShutdownHostMutations(t)
	oldReset, oldIntercept := recoveryResetDNSFn, dnsIntercept
	dnsIntercept = false
	defer func() { recoveryResetDNSFn, dnsIntercept = oldReset, oldIntercept }()
	p := &prog{cfg: &ctrld.Config{}}
	p.logger.Store(mainLog.Load())
	entered := make(chan struct{})
	recoveryResetDNSFn = func(*prog, bool, bool) { close(entered) }
	recovered := make(chan struct{})
	// An empty upstream map can never recover. Shutdown must cancel that wait
	// without waiting on a mutex held for the recovery's entire lifetime.
	go func() { p.handleRecovery(RecoveryReasonRegularFailure); close(recovered) }()
	waitNetworkShutdownSignal(t, entered, "recovery reset seam")
	closed := make(chan struct{})
	go func() { p.closeNetMonitor(); close(closed) }()
	waitNetworkShutdownSignal(t, closed, "canceled indefinite recovery")
	waitNetworkShutdownSignal(t, recovered, "recovery return")
}

func TestNetworkShutdownStopsDeferredRecovery(t *testing.T) {
	guardNetworkShutdownHostMutations(t)
	p := &prog{}
	p.logger.Store(mainLog.Load())
	p.debounceRecovery(p.networkAcceptedGen.Load())
	p.recoveryDebounceMu.Lock()
	timer := p.recoveryDebounceTimer
	p.recoveryDebounceMu.Unlock()
	if timer == nil {
		t.Fatal("debounce did not schedule recovery")
	}
	p.closeNetMonitor()
	if timer.Stop() {
		t.Fatal("shutdown did not stop pending debounce timer")
	}
	// Model the already-fired timer's call to handleRecovery, which Stop
	// cannot retract, then a callback trying to create another timer.
	p.handleRecovery(RecoveryReasonNetworkChange)
	p.debounceRecovery(p.networkAcceptedGen.Load())
	if p.recoveryDebounceTimer != nil || p.recoveryGen.Load() != 0 {
		t.Fatal("deferred recovery restarted after shutdown")
	}
}

func TestNetworkShutdownRejectsRecoveryAdmittedBeforeClose(t *testing.T) {
	p := &prog{}
	p.logger.Store(mainLog.Load())
	// Pause between handleRecovery's activity admission and beginRecovery.
	if !p.beginNetworkActivity() {
		t.Fatal("initial admission failed")
	}
	closed := make(chan struct{})
	go func() { p.closeNetMonitor(); close(closed) }()
	waitNetworkShutdownGate(t, p)
	_, _, _, ok := p.beginRecovery(RecoveryReasonNetworkChange)
	p.netMonitorWG.Done()
	waitNetworkShutdownSignal(t, closed, "admitted recovery drain")
	if ok || p.recoveryCancel != nil || p.recoveryRunning.Load() {
		t.Fatal("recovery published a new owner after shutdown cancellation")
	}
}

type shutdownTestMonitor struct {
	callback       netmon.ChangeFunc
	starts, closes int
}

func (m *shutdownTestMonitor) Start()       { m.starts++ }
func (m *shutdownTestMonitor) Close() error { m.closes++; return nil }
func (m *shutdownTestMonitor) RegisterChangeCallback(fn netmon.ChangeFunc) func() {
	m.callback = fn
	return func() {}
}
func (*shutdownTestMonitor) IsMajorChangeFrom(*netmon.State, *netmon.State) bool {
	panic("closed callback reached network discovery")
}

func TestNetworkMonitorProductionPublicationAndCallbackFence(t *testing.T) {
	old := newNetworkChangeMonitorFn
	t.Cleanup(func() { newNetworkChangeMonitorFn = old })
	for _, late := range []bool{false, true} {
		p := &prog{}
		p.logger.Store(mainLog.Load())
		m := &shutdownTestMonitor{}
		newNetworkChangeMonitorFn = func(func(string, ...any)) (networkChangeMonitor, error) {
			if late {
				p.closeNetMonitor()
			}
			return m, nil
		}
		if err := p.monitorNetworkChanges(context.Background()); err != nil {
			t.Fatal(err)
		}
		p.closeNetMonitor()
		if m.closes != 1 {
			t.Fatalf("monitor closed %d times", m.closes)
		}
		wantStarts := 1
		if late {
			wantStarts = 0
		}
		if m.starts != wantStarts {
			t.Fatalf("monitor starts=%d want=%d", m.starts, wantStarts)
		}
		// Exercise the callback captured from the actual production registration.
		// Removing its wrapper reaches the panic above, before any OS mutation.
		m.callback(&netmon.ChangeDelta{})
	}
}

func TestFinishRunDrainsNetworkJournalOnAbort(t *testing.T) {
	captureDebugMainLog(t)
	stubHeaderSnapshotSources(t)
	p := &prog{
		cfg: &ctrld.Config{}, stopCh: make(chan struct{}),
		runAbortCh: make(chan struct{}), runDone: make(chan struct{}),
		dnsWatcherStopCh: make(chan struct{}),
	}
	p.logger.Store(mainLog.Load())
	p.newNetworkJournal()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	// The poll is a synthetic first platform boundary, even on Darwin.
	p.dnsConfig = newDNSConfigPoller(func() ([]dnsResolverEntry, error) {
		close(entered)
		<-release
		return nil, nil
	})
	p.waitNetworkJournal = p.startNetworkJournal()
	waitNetworkShutdownSignal(t, entered, "journal poll")
	close(p.runDone)
	done := make(chan struct{})
	go func() { p.finishRun(); close(done) }()
	waitNetworkShutdownSignal(t, p.runAbortCh, "run abort")
	assertNetworkShutdownBlocked(t, done)
	unblock()
	waitNetworkShutdownSignal(t, done, "journal drain on abort")
	if stopRequested(p.stopCh) {
		t.Fatal("finishRun closed the caller-owned stop channel")
	}
}

func TestNetworkShutdownDrainsBeforeOSRestoration(t *testing.T) {
	p := &prog{cfg: &ctrld.Config{}, dnsWatcherStopCh: make(chan struct{})}
	p.logger.Store(mainLog.Load())
	entered, release, restored := make(chan struct{}), make(chan struct{}), make(chan struct{})
	p.onStopped = []func(){func() { close(restored) }}
	go p.networkChangeCallback(func(*netmon.ChangeDelta) { close(entered); <-release })(nil)
	waitNetworkShutdownSignal(t, entered, "callback entry")
	done := make(chan struct{})
	go func() { _ = p.restoreOSState(); close(done) }()
	waitNetworkShutdownGate(t, p)
	assertNetworkShutdownBlocked(t, restored)
	close(release)
	waitNetworkShutdownSignal(t, done, "restoration")
	waitNetworkShutdownSignal(t, restored, "restore hook")
}
