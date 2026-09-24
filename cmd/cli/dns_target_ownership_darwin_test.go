//go:build darwin

package cli

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestInterceptDNSTargetOwnershipPersistenceBeforeMutation(t *testing.T) {
	h := newInterceptTargetHarness(t)
	h.nativeCLAT = true
	h.dhcpErr = errors.New("no DHCPv4")
	h.dns["Wi-Fi"] = []string{"2001:db8::53"}
	h.statePath = filepath.Join(t.TempDir(), "absent", "ownership")
	p := newInterceptTargetProg()
	p.cfg.Listener["0"].IP = "127.0.0.9"
	p.cfg.Listener["0"].Port = 5353
	p.ensureInterceptDNSTarget([]string{})
	if len(h.setCalls) != 0 || p.interceptDNSTargetService != "" || !slices.Equal(h.dns["Wi-Fi"], []string{"2001:db8::53"}) {
		t.Fatalf("persistence failure mutated DNS: calls=%v dns=%v owner=%s", h.setCalls, h.dns["Wi-Fi"], p.interceptDNSTargetService)
	}
}

func TestInterceptDNSTargetExternalEditInvalidatesBackup(t *testing.T) {
	h := newInterceptTargetHarness(t)
	p := newInterceptTargetProg()
	p.cfg.Listener["0"].IP = "127.0.0.9"
	p.cfg.Listener["0"].Port = 5353
	p.ensureInterceptDNSTarget([]string{})
	target := p.interceptDNSTargetValue()
	if !slices.Equal(h.dns["Wi-Fi"], []string{target}) {
		t.Fatal("listener-aware target not installed")
	}
	backup := savedStaticDnsSettingsFilePath(&net.Interface{Name: "Wi-Fi"})
	if err := os.WriteFile(backup, []byte("2001:db8::old"), 0600); err != nil {
		t.Fatal(err)
	}
	external := []string{"2001:db8::54"}
	h.dns["Wi-Fi"] = slices.Clone(external)
	for range 2 {
		p.ensureInterceptDNSTarget([]string{})
	}
	if !slices.Equal(h.dns["Wi-Fi"], external) || len(h.setCalls) != 1 {
		t.Fatal("reconciliation overwrote external DNS")
	}
	p.removeInterceptDNSTarget("stop")
	oldEach, oldRestore := restoreSavedStaticDNSInterfacesFn, restoreSavedStaticDNSRestoreFn
	t.Cleanup(func() { restoreSavedStaticDNSInterfacesFn, restoreSavedStaticDNSRestoreFn = oldEach, oldRestore })
	restoreSavedStaticDNSInterfacesFn = func(_, _ string, f func(*net.Interface) error) { _ = f(&net.Interface{Name: "Wi-Fi"}) }
	restoreSavedStaticDNSRestoreFn = func(*net.Interface) error { t.Fatal("full stop sweep replayed stale DNS"); return nil }
	restoreSavedStaticDNS("", false)
	if _, err := os.Stat(backup); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale backup remains available to stop sweep: %v", err)
	}
	if !slices.Equal(h.dns["Wi-Fi"], external) {
		t.Fatal("stop overwrote external DNS")
	}
}

func TestInterceptDNSTargetFailedOwnershipClearRetainsState(t *testing.T) {
	h := newInterceptTargetHarness(t)
	p := newInterceptTargetProg()
	p.ensureInterceptDNSTarget([]string{})
	if err := os.Remove(h.statePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(h.statePath, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.statePath, "busy"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	p.removeInterceptDNSTarget("stop")
	if p.interceptDNSTargetService != "Wi-Fi" {
		t.Fatal("failed ownership clear reported completed cleanup")
	}
}

func TestInterceptDNSTargetTrackedValueIsNotActualDNS(t *testing.T) {
	for _, port := range []int{53, 5353} {
		t.Run(fmt.Sprint(port), func(t *testing.T) {
			logs := captureDebugMainLog(t)
			h := newInterceptTargetHarness(t)
			p := newInterceptTargetProg()
			p.cfg.Listener["0"].IP = "127.0.0.9"
			p.cfg.Listener["0"].Port = port
			p.ensureInterceptDNSTarget([]string{})
			h.dns["Wi-Fi"] = nil
			p.ensureInterceptDNSTarget([]string{})
			event := oneRecoveryEvent(t, logs, dnsTargetFailedMessage)
			wantField(t, event, "stage", "owned_target_changed")
			if len(h.setCalls) != 1 || len(h.dns["Wi-Fi"]) != 0 {
				t.Fatal("reinstalled after external clear")
			}
		})
	}
}

func TestInterceptDNSTargetFailedCleanupGuardsFullSweep(t *testing.T) {
	h := newInterceptTargetHarness(t)
	p := newInterceptTargetProg()
	p.ensureInterceptDNSTarget([]string{})
	backup := savedStaticDnsSettingsFilePath(&net.Interface{Name: "Wi-Fi"})
	if err := os.WriteFile(backup, []byte("2001:db8::53"), 0600); err != nil {
		t.Fatal(err)
	}
	h.resetErr = errors.New("reset failed")
	p.removeInterceptDNSTarget("stop")
	oldEach, oldRestore := restoreSavedStaticDNSInterfacesFn, restoreSavedStaticDNSRestoreFn
	t.Cleanup(func() { restoreSavedStaticDNSInterfacesFn, restoreSavedStaticDNSRestoreFn = oldEach, oldRestore })
	restoreSavedStaticDNSInterfacesFn = func(_, _ string, f func(*net.Interface) error) { _ = f(&net.Interface{Name: "Wi-Fi"}) }
	restoreSavedStaticDNSRestoreFn = func(*net.Interface) error { t.Fatal("sweep bypassed failed guarded cleanup"); return nil }
	restoreSavedStaticDNS("", true)
	if _, err := os.Stat(backup); err != nil {
		t.Fatal("failed cleanup lost backup:", err)
	}
	if p.interceptDNSTargetService != "Wi-Fi" {
		t.Fatal("failed cleanup lost state")
	}
}

func TestInterceptDNSTargetStaticRestoreSkipIsNotFailure(t *testing.T) {
	for _, state := range []string{`{"service":"Wi-Fi","value":"127.0.0.53"}`, `invalid ownership`} {
		t.Run(state, func(t *testing.T) {
			h := newInterceptTargetHarness(t)
			logs := captureDebugMainLog(t)
			if err := os.WriteFile(h.statePath, []byte(state), 0600); err != nil {
				t.Fatal(err)
			}
			backup := savedStaticDnsSettingsFilePath(&net.Interface{Name: "Wi-Fi"})
			const savedDNS = "2001:db8::53"
			if err := os.WriteFile(backup, []byte(savedDNS), 0600); err != nil {
				t.Fatal(err)
			}
			oldEach, oldRestore := restoreSavedStaticDNSInterfacesFn, restoreSavedStaticDNSRestoreFn
			t.Cleanup(func() { restoreSavedStaticDNSInterfacesFn, restoreSavedStaticDNSRestoreFn = oldEach, oldRestore })
			calls := 0
			restoreSavedStaticDNSInterfacesFn = func(_, _ string, f func(*net.Interface) error) {
				calls++
				if err := f(&net.Interface{Name: "Wi-Fi"}); err != nil {
					t.Fatalf("ownership skip reported as restore failure: %v", err)
				}
			}
			restoreSavedStaticDNSRestoreFn = func(*net.Interface) error {
				t.Fatal("ownership skip restored DNS")
				return nil
			}
			restoreSavedStaticDNS("", true)
			if calls != 1 {
				t.Fatalf("interface sweeps=%d, want 1", calls)
			}
			event := oneRecoveryEvent(t, logs, "Saved static DNS restore skipped on interface Wi-Fi: intercept target cleanup is pending or ownership is unreadable")
			wantField(t, event, "level", "debug")
			if data, err := os.ReadFile(backup); err != nil || string(data) != savedDNS {
				t.Fatalf("ownership skip changed backup: %q, %v", data, err)
			}
			if data, err := os.ReadFile(h.statePath); err != nil || string(data) != state {
				t.Fatalf("ownership skip changed state: %q, %v", data, err)
			}
		})
	}
}
