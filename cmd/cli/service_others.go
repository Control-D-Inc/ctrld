//go:build !windows

package cli

import (
	"os"
)

func hasElevatedPrivilege() (bool, error) {
	return os.Geteuid() == 0, nil
}

func openLogFile(path string, flags int) (*os.File, error) {
	return os.OpenFile(path, flags, os.FileMode(0o600))
}

// hasLocalDnsServerRunning reports whether we are on Windows and having Dns server running.
func hasLocalDnsServerRunning() bool { return false }

func ConfigureWindowsServiceFailureActions(serviceName string) error { return nil }

func isRunningOnDomainControllerWindows() (bool, int) { return false, 0 }
