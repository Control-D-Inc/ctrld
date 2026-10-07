//go:build unix

package clientinfo

import (
	"os"
	"path/filepath"
	"testing"
)

func Test_ubiosDiscover_refreshDevices_usesExecutableMongo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mongo")
	const script = `#!/bin/sh
printf '%s\n' '{"mac":"00:00:00:00:00:01","name":"device 1"}'
`
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}

	ud := &ubiosDiscover{mongoPath: path}
	if err := ud.refreshDevices(); err != nil {
		t.Fatalf("refreshDevices() error = %v", err)
	}
	if got := ud.LookupHostnameByMac("00:00:00:00:00:01"); got != "device 1" {
		t.Fatalf("LookupHostnameByMac() = %q, want %q", got, "device 1")
	}
}
