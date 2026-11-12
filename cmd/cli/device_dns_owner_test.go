package cli

import (
	"errors"
	"net"
	"slices"
	"testing"

	"github.com/Control-D-Inc/ctrld"
)

// platform is the kind of run that a device DNS test acts as.
type platform int

const (
	desktop platform = iota
	android
	ios
)

func stubPlatform(t *testing.T, kind platform) {
	t.Helper()
	switch kind {
	case ios:
		stubIOS(t)
	case android:
		old := isMobile
		isMobile = func() bool { return true }
		t.Cleanup(func() { isMobile = old })
	}
}

// On iOS the app owns the DNS settings of the device, so a recovery must not
// remove them or apply them again. Elsewhere, the recovery still does both.
// Android keeps the earlier behavior.
func TestRecoveryDeviceDNSOwnership(t *testing.T) {
	const reapplied = "Upstream \"" + recoveredUpstreamName + "\" recovered; re-applying DNS settings"
	const recovered = "Upstream \"" + recoveredUpstreamName + "\" recovered"
	tests := []struct {
		name          string
		platform      platform
		reason        RecoveryReason
		wantEvents    []string
		wantRecovered string
	}{
		{"iOS upstream failure", ios, RecoveryReasonRegularFailure, nil, recovered},
		{"iOS network change", ios, RecoveryReasonNetworkChange, nil, recovered},
		{"Android upstream failure", android, RecoveryReasonRegularFailure, []string{"reset", "setDNS"}, reapplied},
		{"upstream failure", desktop, RecoveryReasonRegularFailure, []string{"reset", "setDNS"}, reapplied},
		{"network change", desktop, RecoveryReasonNetworkChange, []string{"reset", "setDNS"}, reapplied},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stubPlatform(t, tc.platform)
			h := newStandardRecoveryHarness(t)

			h.prog.handleRecovery(tc.reason)

			var got []string
			for _, e := range h.snapshot() {
				if e == "reset" || e == "setDNS" {
					got = append(got, e)
				}
			}
			if !slices.Equal(got, tc.wantEvents) {
				t.Fatalf("device DNS changes = %v, want %v (all events: %v)", got, tc.wantEvents, h.snapshot())
			}
			oneRecoveryEvent(t, h.logs, tc.wantRecovered)
			end := oneRecoveryEvent(t, h.logs, recoveryEndMessage)
			wantField(t, end, "outcome", recoveryOutcomeCompleted)
		})
	}
}

// On iOS the stop hook must leave the DNS settings of the device alone.
// Elsewhere, it still resets them and restores the saved static DNS.
func TestStopDeviceDNSOwnership(t *testing.T) {
	tests := []struct {
		name       string
		platform   platform
		wantEvents []string
	}{
		{"iOS", ios, nil},
		{"Android", android, []string{"reset", "restore static"}},
		{"desktop", desktop, []string{"reset", "restore static"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stubPlatform(t, tc.platform)
			oldReset, oldInterfaces := resetDNSFn, restoreSavedStaticDNSInterfacesFn
			t.Cleanup(func() { resetDNSFn, restoreSavedStaticDNSInterfacesFn = oldReset, oldInterfaces })
			var got []string
			resetDNSFn = func(_ *prog, isStart, restoreStatic bool) {
				if isStart || !restoreStatic {
					t.Errorf("resetDNS(isStart=%t, restoreStatic=%t), want (false, true)", isStart, restoreStatic)
				}
				got = append(got, "reset")
			}
			restoreSavedStaticDNSInterfacesFn = func(string, string, func(*net.Interface) error) {
				got = append(got, "restore static")
			}

			p := &prog{}
			p.restoreDeviceDNSOnStop()

			if !slices.Equal(got, tc.wantEvents) {
				t.Fatalf("device DNS changes = %v, want %v", got, tc.wantEvents)
			}
		})
	}
}

// On iOS, setDNS and resetDNS must change nothing, so that a future caller
// cannot change the DNS settings of the device either. With intercept_mode =
// "dns" in the config, setDNS used to turn on the process-wide dnsIntercept
// and try to start the DNS intercept.
func TestDeviceDNSSinksOnIOS(t *testing.T) {
	stubIOS(t)
	oldMode, oldSource, oldDNS, oldHard := interceptMode, interceptModeSource, dnsIntercept, hardIntercept
	oldStart, oldRemove := startDNSInterceptFn, removeInterceptDNSTargetFn
	t.Cleanup(func() {
		interceptMode, interceptModeSource, dnsIntercept, hardIntercept = oldMode, oldSource, oldDNS, oldHard
		startDNSInterceptFn, removeInterceptDNSTargetFn = oldStart, oldRemove
	})
	interceptMode, interceptModeSource, dnsIntercept, hardIntercept = "", "", false, false
	startDNSInterceptFn = func(*prog) error {
		t.Error("setDNS started the DNS intercept")
		return errors.New("DNS intercept is not available in this test")
	}
	removeInterceptDNSTargetFn = func(*prog, string) { t.Error("a DNS change removed the intercept DNS target") }

	p := &prog{cfg: &ctrld.Config{Service: ctrld.ServiceConfig{InterceptMode: "dns"}}}
	p.setDNS([]string{"192.168.10.1"})
	p.resetDNS(false, true)

	if dnsIntercept || interceptMode != "" {
		t.Errorf("setDNS changed the intercept mode: dnsIntercept=%t, interceptMode=%q", dnsIntercept, interceptMode)
	}
}
