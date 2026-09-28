//go:build !windows

package cli

import (
	"os"
	"syscall"
)

// hasElevatedPrivilege checks if the current process has elevated privileges
func hasElevatedPrivilege() (bool, error) {
	return os.Geteuid() == 0, nil
}

// openLogFile opens a log file. It refuses a symlink, because ctrld often
// writes its logs as root into a directory that other users can write.
func openLogFile(path string, flags int) (*os.File, error) {
	return os.OpenFile(path, flags|syscall.O_NOFOLLOW, os.FileMode(0o600))
}

// ConfigureWindowsServiceFailureActions is a no-op on non-Windows platforms
func ConfigureWindowsServiceFailureActions(serviceName string) error { return nil }
