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

	// Check if flag already present (idempotent).
	if strings.Contains(config.BinaryPathName, flag) {
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
	if interceptMode == "dns" || interceptMode == "hard" {
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

// removeServiceFlag removes a CLI flag (and its value, if present) from the installed
// Windows service's BinPath. For example, removing "--intercept-mode" also removes
// the following "dns" or "hard" value. The function is idempotent.
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

	if !strings.Contains(config.BinaryPathName, flag) {
		mainLog.Load().Debug().Msgf("Service flag %q not present in BinPath, skipping removal", flag)
		return nil
	}

	// Split BinPath into parts, find and remove the flag + its value (if any).
	parts := strings.Fields(config.BinaryPathName)
	var newParts []string
	for i := 0; i < len(parts); i++ {
		if parts[i] == flag {
			// Skip the flag. Also skip the next part if it's a value (not a flag).
			if i+1 < len(parts) && !strings.HasPrefix(parts[i+1], "-") {
				i++ // skip value too
			}
			continue
		}
		newParts = append(newParts, parts[i])
	}
	config.BinaryPathName = strings.Join(newParts, " ")

	if err := s.UpdateConfig(config); err != nil {
		return fmt.Errorf("failed to update service config: %w", err)
	}

	mainLog.Load().Info().Msgf("Removed %q from service BinPath", flag)
	return nil
}
