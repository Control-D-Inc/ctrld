//go:build windows

package cli

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/svc/mgr"
)

// serviceConfigFileExists returns true if the ctrld Windows service is registered.
func serviceConfigFileExists() bool {
	m, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer m.Disconnect()
	s, err := m.OpenService(ctrldServiceName)
	if err != nil {
		return false
	}
	s.Close()
	return true
}

// appendServiceFlag appends a CLI flag (e.g., "--intercept-mode") to the installed
// Windows service's BinPath arguments. This is used when upgrading an existing
// installation to intercept mode without losing the existing --cd flag.
//
// The function is idempotent: if the flag already exists, it's a no-op.
func appendServiceFlag(flag string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Windows SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ctrldServiceName)
	if err != nil {
		return fmt.Errorf("failed to open service %q: %w", ctrldServiceName, err)
	}
	defer s.Close()

	config, err := s.Config()
	if err != nil {
		return fmt.Errorf("failed to read service config: %w", err)
	}

	// Check exact arguments so a short mode such as "off" is not confused with
	// an unrelated path or value.
	if binaryPathArgumentPresent(config.BinaryPathName, flag) {
		mainLog.Load().Debug().Msgf("Service flag %q already present in BinPath, skipping", flag)
		return nil
	}

	// Append the flag to BinPath.
	config.BinaryPathName = strings.TrimSpace(config.BinaryPathName) + " " + flag

	if err := s.UpdateConfig(config); err != nil {
		return fmt.Errorf("failed to update service config with %q: %w", flag, err)
	}

	mainLog.Load().Info().Msgf("Appended %q to service BinPath", flag)
	return nil
}

// verifyServiceRegistration opens the Windows Service Control Manager and verifies
// that the ctrld service is correctly registered: logs the BinaryPathName, checks
// that --intercept-mode is present if expected, and verifies SERVICE_AUTO_START.
func verifyServiceRegistration() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Windows SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ctrldServiceName)
	if err != nil {
		return fmt.Errorf("failed to open service %q: %w", ctrldServiceName, err)
	}
	defer s.Close()

	config, err := s.Config()
	if err != nil {
		return fmt.Errorf("failed to read service config: %w", err)
	}

	mainLog.Load().Debug().Msgf("Service registry: BinaryPathName = %q", config.BinaryPathName)

	// If intercept mode is set, verify the flag is present in BinPath.
	if interceptMode == "off" || interceptMode == "dns" || interceptMode == "hard" {
		if !strings.Contains(config.BinaryPathName, "--intercept-mode") {
			return fmt.Errorf("service registry: --intercept-mode flag missing from BinaryPathName (expected mode %q)", interceptMode)
		}
		mainLog.Load().Debug().Msgf("Service registry: --intercept-mode flag present in BinaryPathName")
	}

	// Verify auto-start. mgr.StartAutomatic == 2 == SERVICE_AUTO_START.
	if config.StartType != mgr.StartAutomatic {
		return fmt.Errorf("service registry: StartType is %d, expected SERVICE_AUTO_START (%d)", config.StartType, mgr.StartAutomatic)
	}

	return nil
}

// removeServiceFlag removes both "--flag value" and "--flag=value" forms from the
// installed Windows service's BinPath. The function is idempotent.
func removeServiceFlag(flag string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Windows SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ctrldServiceName)
	if err != nil {
		return fmt.Errorf("failed to open service %q: %w", ctrldServiceName, err)
	}
	defer s.Close()

	config, err := s.Config()
	if err != nil {
		return fmt.Errorf("failed to read service config: %w", err)
	}

	updatedPath, removed := removeBinaryPathFlag(config.BinaryPathName, flag)
	if !removed {
		mainLog.Load().Debug().Msgf("Service flag %q not present in BinPath, skipping removal", flag)
		return nil
	}
	config.BinaryPathName = updatedPath

	if err := s.UpdateConfig(config); err != nil {
		return fmt.Errorf("failed to update service config: %w", err)
	}

	mainLog.Load().Info().Msgf("Removed %q from service BinPath", flag)
	return nil
}

func binaryPathArgumentPresent(binaryPath, argument string) bool {
	for _, part := range strings.Fields(binaryPath) {
		if part == argument {
			return true
		}
	}
	return false
}

func removeBinaryPathFlag(binaryPath, flag string) (string, bool) {
	parts := strings.Fields(binaryPath)
	newParts := make([]string, 0, len(parts))
	removed := false
	for i := 0; i < len(parts); i++ {
		switch {
		case parts[i] == flag:
			removed = true
			if i+1 < len(parts) && !strings.HasPrefix(parts[i+1], "-") {
				i++
			}
		case strings.HasPrefix(parts[i], flag+"="):
			removed = true
		default:
			newParts = append(newParts, parts[i])
		}
	}
	return strings.Join(newParts, " "), removed
}
