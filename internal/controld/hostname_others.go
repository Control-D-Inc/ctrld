//go:build !darwin

package controld

import "os"

// preferredHostname returns the system hostname on non-Darwin platforms.
func preferredHostname() (string, error) {
	return os.Hostname()
}
