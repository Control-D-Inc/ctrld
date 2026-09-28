//go:build darwin

package ctrld

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
)

// DiscoverMainUser attempts to find the primary user on macOS systems.
// This is designed to work reliably under RMM deployments where traditional
// environment variables and session detection may not be available.
//
// Priority chain (deterministic, lowest UID wins among candidates):
// 1. Console user from stat -f %Su /dev/console
// 2. Active console session user via scutil
// 3. First user with UID >= 501 from dscl (standard macOS user range)
func DiscoverMainUser(ctx context.Context) string {
	logger := LoggerFromCtx(ctx).Debug()

	// Method 1: Check console owner via stat
	logger.Msg("attempting to discover user via console stat")
	if user := getConsoleUser(ctx); user != "" && user != "root" {
		logger.Str("method", "stat").Str("user", user).Msg("found user via console stat")
		return user
	}

	// Method 2: Check active console session via scutil
	logger.Msg("attempting to discover user via scutil ConsoleUser")
	if user := getScutilConsoleUser(ctx); user != "" && user != "root" {
		logger.Str("method", "scutil").Str("user", user).Msg("found user via scutil ConsoleUser")
		return user
	}

	// Method 3: Find lowest UID >= 501 from directory services
	logger.Msg("attempting to discover user via dscl directory scan")
	if user := getLowestRegularUser(ctx); user != "" {
		logger.Str("method", "dscl").Str("user", user).Msg("found user via dscl scan")
		return user
	}

	logger.Msg("all user discovery methods failed")
	return "unknown"
}

// getConsoleUser uses stat to find the owner of /dev/console
func getConsoleUser(ctx context.Context) string {
	cmd := exec.CommandContext(ctx, "stat", "-f", "%Su", "/dev/console")
	out, err := cmd.Output()
	if err != nil {
		LoggerFromCtx(ctx).Debug().Err(err).Msg("failed to stat /dev/console")
		return ""
	}
	return strings.TrimSpace(string(out))
}

// getScutilConsoleUser uses scutil to get the current console user
func getScutilConsoleUser(ctx context.Context) string {
	cmd := exec.CommandContext(ctx, "scutil", "-r", "ConsoleUser")
	out, err := cmd.Output()
	if err != nil {
		LoggerFromCtx(ctx).Debug().Err(err).Msg("failed to get ConsoleUser via scutil")
		return ""
	}
	
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Name :") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				return strings.TrimSpace(parts[2])
			}
		}
	}
	return ""
}

// getLowestRegularUser finds the user with the lowest UID >= 501
func getLowestRegularUser(ctx context.Context) string {
	// Get list of all users with UID >= 501
	cmd := exec.CommandContext(ctx, "dscl", ".", "list", "/Users", "UniqueID")
	out, err := cmd.Output()
	if err != nil {
		LoggerFromCtx(ctx).Debug().Err(err).Msg("failed to list users via dscl")
		return ""
	}

	var candidates []struct {
		name string
		uid  int
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}

		username := fields[0]
		uidStr := fields[1]
		
		uid, err := strconv.Atoi(uidStr)
		if err != nil {
			continue
		}

		// Only consider regular users (UID >= 501 on macOS)
		if uid >= 501 {
			candidates = append(candidates, struct {
				name string
				uid  int
			}{username, uid})
		}
	}

	if len(candidates) == 0 {
		return ""
	}

	// Find the candidate with the lowest UID (deterministic choice)
	lowestUID := candidates[0].uid
	result := candidates[0].name
	
	for _, candidate := range candidates[1:] {
		if candidate.uid < lowestUID {
			lowestUID = candidate.uid
			result = candidate.name
		}
	}

	return result
}