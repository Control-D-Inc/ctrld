package controld

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIOSHostnameStartsNoScutil(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "started")
	if err := os.WriteFile(filepath.Join(dir, "scutil"), []byte("#!/bin/sh\necho scutil >> "+marker+"\necho FakeName\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	oldIsIOS := isIOS
	isIOS = func() bool { return true }
	t.Cleanup(func() { isIOS = oldIsIOS })

	want, _ := os.Hostname()
	if got, _ := preferredHostname(); got != want {
		t.Errorf("preferredHostname() = %q, want %q", got, want)
	}
	if hints := hostnameHints(); len(hints) != 1 || hints["os.Hostname"] != want {
		t.Errorf("hostnameHints() = %v, want only os.Hostname", hints)
	}
	if started, err := os.ReadFile(marker); err == nil {
		t.Fatalf("ctrld started scutil on iOS:\n%s", started)
	}
}
