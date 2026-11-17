package cli

import (
	"slices"
	"testing"

	"github.com/Control-D-Inc/ctrld"
)

// On iOS the app owns the DNS settings of the device. postRun must only
// build the OS resolver, from the nameservers of the app.
func TestPostRunMobileLeavesDeviceDNSAlone(t *testing.T) {
	oldService, oldReset, oldInit := runningAsService, resetDNSFn, initializeOsResolverWithSystemNameserversFn
	oldMode, oldSource := interceptMode, interceptModeSource
	t.Cleanup(func() {
		runningAsService, resetDNSFn, initializeOsResolverWithSystemNameserversFn = oldService, oldReset, oldInit
		interceptMode, interceptModeSource = oldMode, oldSource
		ctrld.SetAppNameservers(nil)
	})
	stubIOS(t)
	runningAsService = func() bool { return true }
	interceptMode, interceptModeSource = "", ""
	resetDNSFn = func(*prog, bool, bool) { t.Error("postRun reset the DNS settings of the device") }
	initializeOsResolverWithSystemNameserversFn = ctrld.InitializeOsResolverWithSystemNameserversReason
	ctrld.SetAppNameservers([]string{"192.168.255.53"})

	p := &prog{cfg: &ctrld.Config{}, csSetDnsDone: make(chan struct{}, 1)}
	p.postRun()

	if interceptModeSource != "" {
		t.Errorf("postRun set the DNS of the device (intercept mode source %q)", interceptModeSource)
	}
	if got := ctrld.OsResolverNameservers(); !slices.Contains(got, "192.168.255.53:53") {
		t.Errorf("OS resolver nameservers = %v, want the app nameserver", got)
	}
	if _, open := <-p.csSetDnsDone; !open {
		t.Error("postRun did not signal the control server")
	}
}
