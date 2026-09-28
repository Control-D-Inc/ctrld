package cli

import (
	"sync/atomic"
	"testing"

	"github.com/Control-D-Inc/ctrld"
	"tailscale.com/net/netmon"
)

func TestRestoreOSStateReleasesMutexBeforeCallbackDrain(t *testing.T) {
	p := &prog{cfg: &ctrld.Config{}, dnsWatcherStopCh: make(chan struct{})}
	p.logger.Store(mainLog.Load())
	entered, resume, callbackDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var startupCalls, restoreCalls atomic.Int32
	p.onStopped = []func(){func() {
		select {
		case <-callbackDone:
		default:
			t.Error("OS restoration ran before the callback drained")
		}
		restoreCalls.Add(1)
	}}
	go p.networkChangeCallback(func(*netmon.ChangeDelta) {
		close(entered)
		<-resume
		// This callback was admitted before shutdown. It must be able to take
		// osStateMu and observe the closed startup gate while shutdown joins it.
		if p.startOSState(func() { startupCalls.Add(1) }) {
			t.Error("startup was permitted after restoration began")
		}
		close(callbackDone)
	})(nil)
	waitNetworkShutdownSignal(t, entered, "callback entry")
	restored := make(chan struct{})
	go func() {
		if err := p.restoreOSState(); err != nil {
			t.Error(err)
		}
		close(restored)
	}()
	waitNetworkShutdownGate(t, p)
	close(resume)
	waitNetworkShutdownSignal(t, callbackDone, "callback acquiring osStateMu")
	waitNetworkShutdownSignal(t, restored, "OS restoration")
	if err := p.restoreOSState(); err != nil {
		t.Fatal(err)
	}
	if startupCalls.Load() != 0 || restoreCalls.Load() != 1 {
		t.Fatalf("startup calls=%d, restore calls=%d", startupCalls.Load(), restoreCalls.Load())
	}
}
