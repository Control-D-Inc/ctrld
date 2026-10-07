//go:build !windows

package cli

import (
	"os"
	"syscall"
)

func hasElevatedPrivilege() (bool, error) {
	return os.Geteuid() == 0, nil
}

// openLogFile opens a log file. It refuses a symlink, because ctrld often
// writes its logs as root into a directory that other users can write.
func openLogFile(path string, flags int) (*os.File, error) {
	return os.OpenFile(path, flags|syscall.O_NOFOLLOW, os.FileMode(0o600))
}

// hasLocalDnsServerRunning reports whether we are on Windows and having Dns server running.
func hasLocalDnsServerRunning() bool { return false }

func ConfigureWindowsServiceFailureActions(serviceName string) error { return nil }

func isRunningOnDomainControllerWindows() (bool, int) { return false, 0 }
