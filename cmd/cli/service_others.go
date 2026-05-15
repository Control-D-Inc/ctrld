//go:build !windows

package cli

import (
	"os"
)

// hasElevatedPrivilege checks if the current process has elevated privileges
func hasElevatedPrivilege() (bool, error) {
	return os.Geteuid() == 0, nil
}

// openLogFile opens a log file with the specified flags
func openLogFile(path string, flags int) (*os.File, error) {
	return os.OpenFile(path, flags, os.FileMode(0o600))
}

// ConfigureWindowsServiceFailureActions is a no-op on non-Windows platforms
func ConfigureWindowsServiceFailureActions(serviceName string) error { return nil }
