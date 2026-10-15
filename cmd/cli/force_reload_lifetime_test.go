package cli

import (
	"testing"
	"time"

	"github.com/Control-D-Inc/ctrld"
)

func TestForceFetchingAPIDrainsBeforeRestoration(t *testing.T) {
	old := cdUID
	cdUID = "testuid"
	t.Cleanup(func() { cdUID = old })
	p := &prog{cfg: &ctrld.Config{}, stopCh: make(chan struct{}), runAbortCh: make(chan struct{}), apiForceReloadCh: make(chan struct{})}
	p.logger.Store(mainLog.Load())
	// Pause the admitted producer after delivery, before it reads cooldown
	// configuration. Shutdown must join it even though the consumer is done.
	p.mu.Lock()
	locked := true
	defer func() {
		if locked {
			p.mu.Unlock()
		}
	}()
	p.forceFetchingAPI("testuid.verify.controld.com")
	select {
	case <-p.apiForceReloadCh:
	case <-time.After(time.Second):
		t.Fatal("force-reload producer did not send")
	}
	closed := make(chan struct{})
	go func() { p.closeNetMonitor(); close(closed) }()
	waitNetworkShutdownGate(t, p)
	assertNetworkShutdownBlocked(t, closed)
	p.mu.Unlock()
	locked = false
	waitNetworkShutdownSignal(t, closed, "force-reload producer drain")
	// Service restoration precedes closing stopCh, so that channel alone
	// cannot cancel the producer's send or cooldown while restoration joins it.
	if stopRequested(p.stopCh) || stopRequested(p.runAbortCh) {
		t.Fatal("network shutdown closed a caller-owned lifetime channel")
	}
	p.forceFetchingAPI("testuid.verify.controld.com")
	select {
	case <-p.apiForceReloadCh:
		t.Fatal("shutdown admitted a late force-reload producer")
	default:
	}
}
