package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

// Test_logIfaceLookupFailure is a regression test for issue-608: a macOS
// upgrade that succeeded still printed
//
//	ERR could not get interface error="interface not found" iface=en5
//
// because the DNS cleanup after the upgrade logged every interface-lookup
// failure at error level, including the interface it had been bound to simply
// being gone. Only that positively identified condition may be downgraded.
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
			name:      "the lookup failed for another reason",
			skipping:  "DNS restoration",
			err:       fmt.Errorf("patching interface name: %w", os.ErrPermission),
			wantLevel: "error",
			wantMsg:   "could not get interface",
		},
		{
			// A restoration failure reaches the same logger, and must stay
			// visible: the interface exists and its DNS was left wrong.
			name:      "restoring DNS on an existing interface failed",
			skipping:  "DNS restoration",
			err:       fmt.Errorf("failed to restore static DNS config on interface %q: %w", "en0", os.ErrPermission),
			wantLevel: "error",
			wantMsg:   "could not get interface",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf syncBuffer
			logger := zerolog.New(&buf).With().Str("iface", "en5").Logger()

			logIfaceLookupFailure(&logger, tc.skipping, tc.err)

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

// Test_resetDNSForRunningIfaceMissingIface drives the real cleanup path with an
// interface that does not exist, which is what an upgrade sees after the
// adapter ctrld was bound to went away. It changes no DNS settings: the lookup
// fails before any restoration runs.
func Test_resetDNSForRunningIfaceMissingIface(t *testing.T) {
	level := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	t.Cleanup(func() { zerolog.SetGlobalLevel(level) })

	old := mainLog.Load()
	var buf syncBuffer
	logger := zerolog.New(&buf)
	mainLog.Store(&logger)
	t.Cleanup(func() { mainLog.Store(old) })

	// A name no host assigns, so netInterface reports it as missing rather
	// than restoring DNS on a real adapter.
	p := &prog{runningIface: "ctrld-absent-iface0"}

	if got := p.resetDNSForRunningIface(false, true); got != nil {
		t.Errorf("resetDNSForRunningIface returned %v, want nil for a missing interface", got)
	}

	entry := soleLogEntry(t, buf.String())
	if got := entry["level"]; got != "debug" {
		t.Errorf("level = %v, want %q: a missing interface must not make a successful upgrade look broken (line: %s)",
			got, "debug", strings.TrimSpace(buf.String()))
	}
	if got := entry["iface"]; got != p.runningIface {
		t.Errorf("iface = %v, want %q", got, p.runningIface)
	}
}

// soleLogEntry decodes the single JSON log line in out.
func soleLogEntry(t *testing.T, out string) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 1 || lines[0] == "" {
		t.Fatalf("want exactly one log line, got %d:\n%s", len(lines), out)
	}
	var entry map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("decoding log line %q: %v", lines[0], err)
	}
	return entry
}
