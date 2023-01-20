//go:build !windows

package main

import (
	"os"
)

func hasElevatedPrivilege() (bool, error) {
	return os.Geteuid() == 0, nil
}
