//go:build darwin

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const launchdPlistPath = "/Library/LaunchDaemons/ctrld.plist"

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
// On macOS, this modifies the launchd plist at /Library/LaunchDaemons/ctrld.plist
// using the "defaults" command, which is the standard way to edit plists.
//
// The function is idempotent: if the flag already exists, it's a no-op.
func appendServiceFlag(flag string) error {
	// Read current ProgramArguments from plist.
	out, err := exec.Command("defaults", "read", launchdPlistPath, "ProgramArguments").CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to read plist ProgramArguments: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	// Check if the flag is already present (idempotent).
	args := string(out)
	if strings.Contains(args, flag) {
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

// removeServiceFlag removes a CLI flag (and its value, if the next argument is not
// a flag) from the installed service's launch arguments. For example, removing
// "--intercept-mode" also removes the following "dns" or "hard" value argument.
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

	index := -1
	for i, entry := range entries {
		if entry == flag {
			index = i
			break
		}
	}

	if index < 0 {
		mainLog.Load().Debug().Msgf("Service flag %q not present in plist, skipping removal", flag)
		return nil
	}

	// Check if the next entry is a value (not a flag). If so, delete it first
	// (deleting by index shifts subsequent entries down, so delete value before flag).
	hasValue := index+1 < len(entries) && !strings.HasPrefix(entries[index+1], "-")
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
