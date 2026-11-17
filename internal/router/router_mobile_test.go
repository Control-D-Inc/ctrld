package router

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Control-D-Inc/ctrld/internal/mobile"
)

func TestIOSNameStartsNoTools(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "started")
	for _, tool := range []string{"uname", "ubnt-device-info"} {
		script := "#!/bin/sh\necho " + tool + " >> " + marker + "\n"
		if err := os.WriteFile(filepath.Join(dir, tool), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	oldIsIOS, oldPlatform := mobile.IsIOS, routerPlatform.Load()
	mobile.IsIOS = func() bool { return true }
	routerPlatform.Store(nil)
	t.Cleanup(func() {
		mobile.IsIOS = oldIsIOS
		routerPlatform.Store(oldPlatform)
	})

	if got := Name(); got != osName {
		t.Errorf("Name() = %q, want %q", got, osName)
	}
	if started, err := os.ReadFile(marker); err == nil {
		t.Fatalf("ctrld started system tools on iOS:\n%s", started)
	}
}
