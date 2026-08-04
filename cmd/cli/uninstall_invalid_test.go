package cli

import "testing"

// Test_ensureRunningIfaceForInvalidUninstall is a regression test for issue-556:
// after a reboot, the invalid-device self-uninstall path could run before the
// running interface was known. Because resetDNS (via resetDNSForRunningIface)
// silently skips DNS restoration when p.runningIface is empty, the OS was left
// pointed at ctrld's local listener with no internet after the service was
// removed. ensureRunningIfaceForInvalidUninstall must populate p.runningIface
// before resetDNS runs.
func Test_ensureRunningIfaceForInvalidUninstall(t *testing.T) {
	// preRun mutates the package-level iface global; restore it after the test.
	origIface := iface
	t.Cleanup(func() { iface = origIface })

	// newService needs the package service config; it is safe to build here
	// because ensureRunningIfaceForInvalidUninstall only queries the (absent)
	// control socket via runningIface, which returns nil when ctrld is not
	// running, and performs no DNS or service mutation.
	s, err := newService(&prog{}, svcConfig)
	if err != nil {
		t.Fatalf("newService: %v", err)
	}

	t.Run("iface flag already resolved but not yet copied", func(t *testing.T) {
		iface = "eth-test"
		p := &prog{}

		// Precondition mirrors the buggy post-reboot state: an empty running
		// interface would make resetDNS skip restoration entirely.
		if p.runningIface != "" {
			t.Fatalf("precondition: runningIface = %q, want empty", p.runningIface)
		}

		ensureRunningIfaceForInvalidUninstall(p, s)

		if p.runningIface == "" {
			t.Fatal("runningIface still empty after prepare: resetDNS would skip DNS " +
				"restoration and leave the OS pointed at ctrld's local listener")
		}
		if p.runningIface != "eth-test" {
			t.Fatalf("runningIface = %q, want the resolved iface %q", p.runningIface, "eth-test")
		}
	})

	t.Run("iface unset falls back to auto-detected interface", func(t *testing.T) {
		iface = ""
		p := &prog{}

		ensureRunningIfaceForInvalidUninstall(p, s)

		// With iface unset the prep resolves "auto" to the default interface
		// (defaultIfaceName never returns empty on the supported platforms), so
		// resetDNS has a concrete interface to restore.
		if p.runningIface == "" {
			t.Fatal("runningIface still empty after prepare with iface unset: " +
				"resetDNS would skip DNS restoration")
		}
	})
}
