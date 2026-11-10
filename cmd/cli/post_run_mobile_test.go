package cli

import (
	"context"
	"slices"
	"strings"
	"testing"

	"gitlab.int.windscribe.com/controld/clients/ctrld.git"
	"gitlab.int.windscribe.com/controld/clients/ctrld.git/internal/mobile"
)

// On iOS the app owns the DNS settings of the device. postRun must only
// build the OS resolver, from the nameservers of the app.
func TestPostRunMobileLeavesDeviceDNSAlone(t *testing.T) {
	oldService, oldReset, oldInit := runningAsService, resetDNSFn, initializeOsResolverWithSystemNameserversFn
	oldMode, oldSource := interceptMode, interceptModeSource
	t.Cleanup(func() {
		runningAsService, resetDNSFn, initializeOsResolverWithSystemNameserversFn = oldService, oldReset, oldInit
		interceptMode, interceptModeSource = oldMode, oldSource
		ctrld.SetAppNameservers(context.Background(), nil)
	})
	stubIOS(t)
	runningAsService = func() bool { return true }
	interceptMode, interceptModeSource = "", ""
	resetDNSFn = func(*prog, bool, bool) { t.Error("postRun reset the DNS settings of the device") }
	initializeOsResolverWithSystemNameserversFn = ctrld.InitializeOsResolverWithSystemNameserversReason
	ctrld.SetAppNameservers(context.Background(), []string{"192.168.255.53"})

	p := &prog{cfg: &ctrld.Config{}, csSetDnsDone: make(chan struct{}, 1)}
	p.logger.Store(mainLog.Load())
	p.postRun()

	if interceptModeSource != "" {
		t.Errorf("postRun set the DNS of the device (intercept mode source %q)", interceptModeSource)
	}
	if got := ctrld.OsResolverNameservers(); !slices.Contains(got, "192.168.255.53:53") {
		t.Errorf("OS resolver nameservers = %v, want the app nameserver", got)
	}
	select {
	case <-p.csSetDnsDone:
	default:
		t.Error("postRun did not signal the control server")
	}
}

// Outside iOS, postRun still owns the DNS of the device: it resets the DNS
// and then points it at ctrld.
func TestPostRunDesktopSetsDeviceDNS(t *testing.T) {
	oldService, oldReset, oldSet, oldInit := runningAsService, resetDNSFn, setDNSFn, initializeOsResolverWithSystemNameserversFn
	oldIsIOS := mobile.IsIOS
	t.Cleanup(func() {
		runningAsService, resetDNSFn, setDNSFn, initializeOsResolverWithSystemNameserversFn = oldService, oldReset, oldSet, oldInit
		mobile.IsIOS = oldIsIOS
	})
	mobile.IsIOS = func() bool { return false }
	runningAsService = func() bool { return true }
	var steps []string
	resetDNSFn = func(*prog, bool, bool) { steps = append(steps, "reset") }
	setDNSFn = func(_ *prog, nss []string) { steps = append(steps, "set "+strings.Join(nss, ",")) }
	initializeOsResolverWithSystemNameserversFn = func(context.Context, bool, string) ([]string, []string) {
		return []string{"192.0.2.53:53"}, []string{"192.0.2.53"}
	}

	p := &prog{cfg: &ctrld.Config{}, csSetDnsDone: make(chan struct{}, 1)}
	p.logger.Store(mainLog.Load())
	p.postRun()

	if want := []string{"reset", "set 192.0.2.53"}; !slices.Equal(steps, want) {
		t.Errorf("postRun steps = %q, want %q", steps, want)
	}
}
