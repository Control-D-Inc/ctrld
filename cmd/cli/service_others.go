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
