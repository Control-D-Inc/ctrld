package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Control-D-Inc/ctrld/internal/mobile"
)

// fakeHostTools puts fakes of the system tools that ctrld can start on macOS
// first in PATH. Each one writes a marker file, so a test can find a tool
// that ctrld started.
func fakeHostTools(t *testing.T) (marker string) {
	t.Helper()
	dir := t.TempDir()
	marker = filepath.Join(dir, "started")
	tools := []string{
		"scutil", "ipconfig", "networksetup", "stat", "dscl", "system_profiler",
		"route", "uname", "ubnt-device-info", "arp", "ndp", "lsof", "pfctl",
		"ifconfig", "killall", "dscacheutil",
	}
	for _, tool := range tools {
		script := "#!/bin/sh\necho " + tool + " >> " + marker + "\n"
		if err := os.WriteFile(filepath.Join(dir, tool), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return marker
}

// stubIOS makes every package of ctrld act as it does in an iOS app.
func stubIOS(t *testing.T) {
	t.Helper()
	oldIsIOS, oldIsMobile := mobile.IsIOS, isMobile
	mobile.IsIOS = func() bool { return true }
	isMobile = func() bool { return true }
	t.Cleanup(func() { mobile.IsIOS, isMobile = oldIsIOS, oldIsMobile })
}

func requireNoHostTools(t *testing.T, marker string) {
	t.Helper()
	if started, err := os.ReadFile(marker); err == nil {
		t.Fatalf("ctrld started system tools on mobile:\n%s", started)
	}
}
