package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"

	"tailscale.com/net/netmon"
)

// Test_logIfaceLookupFailure is a regression test for issue-608: a macOS
// upgrade that succeeded still printed
//
//	ERR could not get interface error="interface not found" iface=en5
//
// because the DNS cleanup after the upgrade logged every interface-lookup
// failure at error level, including the interface it had been bound to simply
// being gone.
//
// This covers the helper's own branching. The conditions it must tell apart
// are exercised through the real code in Test_netInterfaceLookupOutcomes and
// Test_resetDNSForRunningIfaceFailures.
func Test_logIfaceLookupFailure(t *testing.T) {
	for _, tc := range []struct {
		name      string
		skipping  string
		err       error
		wantLevel string
		wantMsg   string
	}{
		{
			name:      "the previous interface is gone",
			skipping:  "DNS restoration",
			err:       errInterfaceNotFound,
			wantLevel: "debug",
			wantMsg:   "Skipping DNS restoration: previous interface is no longer present",
		},
		{
			name:      "the missing interface is reported through a wrapped error",
			skipping:  "DNS restoration",
			err:       fmt.Errorf("looking up %q: %w", "en5", errInterfaceNotFound),
			wantLevel: "debug",
			wantMsg:   "Skipping DNS restoration: previous interface is no longer present",
		},
		{
			// The caller names the work it skipped, so the helper stays usable
			// outside the DNS reset path.
			name:      "another caller names its own work",
			skipping:  "interface snapshot",
			err:       errInterfaceNotFound,
			wantLevel: "debug",
			wantMsg:   "Skipping interface snapshot: previous interface is no longer present",
		},
		{
			// What patchNetIfaceName reports for an interface that does exist.
			name:      "the lookup failed for another reason",
			skipping:  "DNS restoration",
			err:       fmt.Errorf("patching interface name: %w", os.ErrPermission),
			wantLevel: "error",
			wantMsg:   "Could not get interface",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf syncBuffer
			logger := newTestJSONLogger(&buf).With().Str("iface", "en5")

			logIfaceLookupFailure(logger, tc.skipping, tc.err)

			entry := soleLogEntry(t, buf.String())
			if got := entry["level"]; got != tc.wantLevel {
				t.Errorf("level = %v, want %q (line: %s)", got, tc.wantLevel, strings.TrimSpace(buf.String()))
			}
			if got := entry["message"]; got != tc.wantMsg {
				t.Errorf("message = %v, want %q", got, tc.wantMsg)
			}
			if got := entry["iface"]; got != "en5" {
				t.Errorf("iface = %v, want %q: the diagnostic must name the interface", got, "en5")
			}
			if tc.wantLevel == "error" {
				if got := entry["error"]; got == nil {
					t.Error("error field missing: a genuine failure must keep its cause")
				}
			} else if got, ok := entry["error"]; ok {
				t.Errorf("error = %v, want no error field on an expected skip", got)
			}
		})
	}
}

// Test_netInterfaceLookupOutcomes pins which lookup failures netInterface may
// report as a missing interface. Only that error is quiet downstream, so an
// enumeration that never ran must not be reported as one: the host may well
// still have the interface.
func Test_netInterfaceLookupOutcomes(t *testing.T) {
	errEnumerate := errors.New("route socket closed")

	t.Run("enumeration failed", func(t *testing.T) {
		stubForeachInterface(t, func(fn func(netmon.Interface, []netip.Prefix)) error {
			return errEnumerate
		})

		iface, err := netInterface("en5")

		if iface != nil {
			t.Errorf("iface = %v, want nil", iface)
		}
		if !errors.Is(err, errEnumerate) {
			t.Errorf("err = %v, want it to keep the enumeration cause %v", err, errEnumerate)
		}
		if errors.Is(err, errInterfaceNotFound) {
			t.Error("a failed enumeration must not report the interface as missing: " +
				"the caller would then skip DNS restoration on an interface that still exists")
		}
	})

	t.Run("enumeration ran and the interface is absent", func(t *testing.T) {
		stubForeachInterface(t, func(fn func(netmon.Interface, []netip.Prefix)) error {
			fn(netmon.Interface{Interface: &net.Interface{Index: 1, Name: "en0"}}, nil)
			return nil
		})

		iface, err := netInterface("en5")

		if iface != nil {
			t.Errorf("iface = %v, want nil", iface)
		}
		if !errors.Is(err, errInterfaceNotFound) {
			t.Errorf("err = %v, want errInterfaceNotFound", err)
		}
	})
}

// Test_resetDNSForRunningIfaceFailures drives the real cleanup path and asserts
// how each outcome is reported: the interface being gone is a debug skip, while
// a failure to restore DNS on an interface that does exist stays an error. The
// OS boundaries are stubbed, so no host DNS or NetworkManager state is touched.
func Test_resetDNSForRunningIfaceFailures(t *testing.T) {
	errRestore := errors.New("permission denied")

	t.Run("the previous interface is gone", func(t *testing.T) {
		buf := captureJSONMainLog(t)
		// The real lookup over an enumeration that does not list the
		// interface, which is what an upgrade sees after the adapter ctrld
		// was bound to went away.
		stubForeachInterface(t, func(fn func(netmon.Interface, []netip.Prefix)) error {
			fn(netmon.Interface{Interface: &net.Interface{Index: 1, Name: "en0"}}, nil)
			return nil
		})
		stubDNSResetBoundaries(t, func(iface *net.Interface, nameservers []string) error {
			t.Fatalf("setDNS called for a missing interface: %v", nameservers)
			return nil
		}, func(iface *net.Interface) error {
			t.Fatal("resetDNS called for a missing interface")
			return nil
		})

		p := &prog{runningIface: "en5"}
		p.logger.Store(mainLog.Load())
		if got := p.resetDNSForRunningIface(false, true); got != nil {
			t.Errorf("resetDNSForRunningIface returned %v, want nil for a missing interface", got)
		}

		entry := findLogEntry(t, buf.String(), "previous interface is no longer present")
		if got := entry["level"]; got != "debug" {
			t.Errorf("level = %v, want %q: a missing interface must not make a successful upgrade look broken",
				got, "debug")
		}
		if got := entry["iface"]; got != "en5" {
			t.Errorf("iface = %v, want %q", got, "en5")
		}
	})

	t.Run("restoring the saved static config failed", func(t *testing.T) {
		buf := captureJSONMainLog(t)
		iface := stubExistingIface(t)
		savedStaticNameserversFn = func(*net.Interface) []string { return []string{"192.0.2.1"} }
		called := false
		stubDNSResetBoundaries(t, func(i *net.Interface, nameservers []string) error {
			called = true
			return errRestore
		}, func(i *net.Interface) error {
			t.Fatal("resetDNS called although a saved static config exists")
			return nil
		})

		p := &prog{runningIface: iface.Name}
		p.logger.Store(mainLog.Load())
		p.resetDNSForRunningIface(false, true)

		if !called {
			t.Fatal("setDNS was never called: the saved static config was not restored")
		}
		entry := findLogEntry(t, buf.String(), "Failed to restore static DNS config")
		if got := entry["level"]; got != "error" {
			t.Errorf("level = %v, want %q: the interface exists and its DNS was left wrong",
				got, "error")
		}
		if got := entry["error"]; got != errRestore.Error() {
			t.Errorf("error = %v, want %q", got, errRestore)
		}
	})

	t.Run("resetting to DHCP failed", func(t *testing.T) {
		buf := captureJSONMainLog(t)
		iface := stubExistingIface(t)
		// No saved static config, so the cleanup falls back to DHCP.
		called := false
		stubDNSResetBoundaries(t, func(i *net.Interface, nameservers []string) error {
			t.Fatalf("setDNS called without a saved static config: %v", nameservers)
			return nil
		}, func(i *net.Interface) error {
			called = true
			return errRestore
		})

		p := &prog{runningIface: iface.Name}
		p.logger.Store(mainLog.Load())
		p.resetDNSForRunningIface(false, true)

		if !called {
			t.Fatal("resetDNS was never called: the interface was not reset to DHCP")
		}
		entry := findLogEntry(t, buf.String(), "Failed to reset DNS to DHCP")
		if got := entry["level"]; got != "error" {
			t.Errorf("level = %v, want %q: the interface exists and its DNS was left wrong",
				got, "error")
		}
		if got := entry["error"]; got != errRestore.Error() {
			t.Errorf("error = %v, want %q", got, errRestore)
		}
	})
}

// stubForeachInterface replaces the host interface enumeration for one test.
func stubForeachInterface(t *testing.T, fn func(func(netmon.Interface, []netip.Prefix)) error) {
	t.Helper()
	old := foreachInterface
	foreachInterface = fn
	t.Cleanup(func() { foreachInterface = old })
}

// stubDNSResetBoundaries replaces the parts of the DNS reset path that change
// host state: the DNS setters and the NetworkManager restore.
func stubDNSResetBoundaries(t *testing.T, set func(*net.Interface, []string) error, reset func(*net.Interface) error) {
	t.Helper()
	oldSet, oldReset, oldNM := setIfaceDNSFn, resetIfaceDNSFn, restoreNetworkManagerFn
	setIfaceDNSFn, resetIfaceDNSFn, restoreNetworkManagerFn = set, reset, func(*prog) error { return nil }
	t.Cleanup(func() {
		setIfaceDNSFn, resetIfaceDNSFn, restoreNetworkManagerFn = oldSet, oldReset, oldNM
	})
}

// stubExistingIface makes the lookup report an interface that is present.
func stubExistingIface(t *testing.T) *net.Interface {
	t.Helper()
	iface := &net.Interface{Index: 1, Name: "ctrld-test0"}
	oldSaved := savedStaticNameserversFn
	savedStaticNameserversFn = func(*net.Interface) []string { return nil }
	t.Cleanup(func() { savedStaticNameserversFn = oldSaved })
	old := netInterfaceFn
	netInterfaceFn = func(name string) (*net.Interface, error) {
		if name != iface.Name {
			return nil, errInterfaceNotFound
		}
		return iface, nil
	}
	t.Cleanup(func() { netInterfaceFn = old })
	return iface
}

// soleLogEntry decodes the single JSON log line in out.
func soleLogEntry(t *testing.T, out string) map[string]any {
	t.Helper()
	entries := logEntries(t, out)
	if len(entries) != 1 {
		t.Fatalf("want exactly one log line, got %d:\n%s", len(entries), out)
	}
	return entries[0]
}

// findLogEntry returns the one log line whose message contains want.
func findLogEntry(t *testing.T, out, want string) map[string]any {
	t.Helper()
	var found []map[string]any
	for _, entry := range logEntries(t, out) {
		if msg, _ := entry["message"].(string); strings.Contains(msg, want) {
			found = append(found, entry)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one log line containing %q, got %d:\n%s", want, len(found), out)
	}
	return found[0]
}

// logEntries decodes the JSON log lines in out.
func logEntries(t *testing.T, out string) []map[string]any {
	t.Helper()
	out = strings.TrimSpace(out)
	if out == "" {
		t.Fatal("no log output")
	}
	var entries []map[string]any
	for _, line := range strings.Split(out, "\n") {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("decoding log line %q: %v", line, err)
		}
		entries = append(entries, entry)
	}
	return entries
}
