//go:build !darwin && !windows

package cli

import (
	"errors"
	"os"
)

// errServiceFlagsUnsupported is returned by the service-argument helpers on
// platforms that do not store service arguments in a file ctrld can rewrite.
var errServiceFlagsUnsupported = errors.New("modifying service flags is not supported on this platform; use intercept_mode in config instead")

// serviceConfigFileExists checks common service config file locations on Linux.
func serviceConfigFileExists() bool {
	// systemd unit file
	if _, err := os.Stat("/etc/systemd/system/ctrld.service"); err == nil {
		return true
	}
	// SysV init script
	if _, err := os.Stat("/etc/init.d/ctrld"); err == nil {
		return true
	}
	return false
}

// appendServiceFlag is not yet implemented on this platform.
// Linux services (systemd) store args in unit files; intercept mode
// should be set via the config file (intercept_mode) on these platforms.
func appendServiceFlag(flag string) error {
	return errServiceFlagsUnsupported
}

// verifyServiceRegistration is a no-op on this platform.
func verifyServiceRegistration() error {
	return nil
}

// removeServiceFlag is not yet implemented on this platform.
func removeServiceFlag(flag string) error {
	return errServiceFlagsUnsupported
}
