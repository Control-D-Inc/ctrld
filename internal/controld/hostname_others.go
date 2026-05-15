//go:build !darwin

package controld

import "os"

// preferredHostname returns the system hostname on non-Darwin platforms.
func preferredHostname() (string, error) {
	return os.Hostname()
}

// hostnameHints returns available hostname sources for diagnostic purposes.
func hostnameHints() map[string]string {
	hints := make(map[string]string)
	if h, err := os.Hostname(); err == nil {
		hints["os.Hostname"] = h
	}
	return hints
}
