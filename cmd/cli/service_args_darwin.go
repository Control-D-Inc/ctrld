//go:build darwin

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const launchdPlistPath = launchdPlistFile

// serviceConfigFileExists returns true if the launchd plist for ctrld exists on disk.
// This is more reliable than checking launchctl status, which may report "not found"
// if the service was unloaded but the plist file still exists.
func serviceConfigFileExists() bool {
	_, err := os.Stat(launchdPlistPath)
	return err == nil
}

// appendServiceFlag appends a CLI flag (e.g., "--intercept-mode") to the installed
// service's launch arguments. This is used when upgrading an existing installation
// to intercept mode without losing the existing --cd flag and other arguments.
//
// On macOS, this modifies the launchd plist named after ctrldServiceName
// using PlistBuddy for exact array reads and writes.
//
// The function is idempotent: if the flag already exists, it's a no-op.
func appendServiceFlag(flag string) error {
	// Read current ProgramArguments from plist.
	out, err := exec.Command("/usr/libexec/PlistBuddy", "-c", "Print :ProgramArguments", launchdPlistPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to read plist ProgramArguments: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	// Check exact array entries. A substring match can confuse a mode such as "off"
	// with an unrelated path or argument and leave the flag without its value.
	if serviceArgumentPresent(out, flag) {
		mainLog.Load().Debug().Msgf("Service flag %q already present in plist, skipping", flag)
		return nil
	}

	// Use PlistBuddy to append the flag to ProgramArguments array.
	// PlistBuddy is more reliable than "defaults" for array manipulation.
	addCmd := exec.Command(
		"/usr/libexec/PlistBuddy",
		"-c", fmt.Sprintf("Add :ProgramArguments: string %s", flag),
		launchdPlistPath,
	)
	if out, err := addCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to append %q to plist ProgramArguments: %w (output: %s)", flag, err, strings.TrimSpace(string(out)))
	}

	mainLog.Load().Info().Msgf("Appended %q to service launch arguments", flag)
	return nil
}

// verifyServiceRegistration is a no-op on macOS (launchd plist verification not needed).
func verifyServiceRegistration() error {
	return nil
}

// removeServiceFlag removes both "--flag value" and "--flag=value" forms from the
// installed service's launch arguments.
//
// The function is idempotent: if the flag doesn't exist, it's a no-op.
func removeServiceFlag(flag string) error {
	// Read current ProgramArguments to find the index.
	out, err := exec.Command("/usr/libexec/PlistBuddy", "-c", "Print :ProgramArguments", launchdPlistPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to read plist ProgramArguments: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	// Parse the PlistBuddy output to find the flag's index.
	// PlistBuddy prints arrays as:
	//   Array {
	//       /path/to/ctrld
	//       run
	//       --cd=xxx
	//       --intercept-mode
	//       dns
	//   }
	lines := strings.Split(string(out), "\n")
	var entries []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "Array {" || trimmed == "}" || trimmed == "" {
			continue
		}
		entries = append(entries, trimmed)
	}

	index, hasValue := serviceFlagPosition(entries, flag)

	if index < 0 {
		mainLog.Load().Debug().Msgf("Service flag %q not present in plist, skipping removal", flag)
		return nil
	}

	// Delete a separate value first. An inline --flag=value entry is one array item.
	if hasValue {
		delVal := exec.Command(
			"/usr/libexec/PlistBuddy",
			"-c", fmt.Sprintf("Delete :ProgramArguments:%d", index+1),
			launchdPlistPath,
		)
		if out, err := delVal.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to remove value for %q from plist: %w (output: %s)", flag, err, strings.TrimSpace(string(out)))
		}
	}

	// Delete the flag itself.
	delCmd := exec.Command(
		"/usr/libexec/PlistBuddy",
		"-c", fmt.Sprintf("Delete :ProgramArguments:%d", index),
		launchdPlistPath,
	)
	if out, err := delCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to remove %q from plist ProgramArguments: %w (output: %s)", flag, err, strings.TrimSpace(string(out)))
	}

	mainLog.Load().Info().Msgf("Removed %q from service launch arguments", flag)
	return nil
}

func serviceArgumentPresent(out []byte, argument string) bool {
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == argument {
			return true
		}
	}
	return false
}

func serviceFlagPosition(entries []string, flag string) (index int, hasValue bool) {
	for i, entry := range entries {
		switch {
		case entry == flag:
			return i, i+1 < len(entries) && !strings.HasPrefix(entries[i+1], "-")
		case strings.HasPrefix(entry, flag+"="):
			return i, false
		}
	}
	return -1, false
}
