//go:build !windows

package cli

import (
	"os"
)

func hasElevatedPrivilege() (bool, error) {
	return os.Geteuid() == 0, nil
}
