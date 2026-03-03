//go:build linux

package ctrld

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// DiscoverMainUser attempts to find the primary user on Linux systems.
// This is designed to work reliably under RMM deployments where traditional
// environment variables and session detection may not be available.
//
// Priority chain (deterministic, lowest UID wins among candidates):
// 1. Active users from loginctl list-users
// 2. Parse /etc/passwd for users with UID >= 1000, prefer admin group members
// 3. Fallback to lowest UID >= 1000 from /etc/passwd
func DiscoverMainUser(ctx context.Context) string {
	logger := ProxyLogger.Load().Debug()

	// Method 1: Check active users via loginctl
	logger.Msg("attempting to discover user via loginctl")
	if user := getLoginctlUser(ctx); user != "" {
		logger.Str("method", "loginctl").Str("user", user).Msg("found user via loginctl")
		return user
	}

	// Method 2: Parse /etc/passwd and find admin users first
	logger.Msg("attempting to discover user via /etc/passwd with admin preference")
	if user := getPasswdUserWithAdminPreference(ctx); user != "" {
		logger.Str("method", "passwd+admin").Str("user", user).Msg("found admin user via /etc/passwd")
		return user
	}

	// Method 3: Fallback to lowest UID >= 1000 from /etc/passwd
	logger.Msg("attempting to discover user via /etc/passwd lowest UID")
	if user := getLowestPasswdUser(ctx); user != "" {
		logger.Str("method", "passwd").Str("user", user).Msg("found user via /etc/passwd")
		return user
	}

	logger.Msg("all user discovery methods failed")
	return "unknown"
}

// getLoginctlUser uses loginctl to find active users
func getLoginctlUser(ctx context.Context) string {
	cmd := exec.CommandContext(ctx, "loginctl", "list-users", "--no-legend")
	out, err := cmd.Output()
	if err != nil {
		ProxyLogger.Load().Debug().Err(err).Msg("failed to run loginctl list-users")
		return ""
	}

	var candidates []struct {
		name string
		uid  int
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		uidStr := fields[0]
		username := fields[1]

		uid, err := strconv.Atoi(uidStr)
		if err != nil {
			continue
		}

		// Only consider regular users (UID >= 1000 on Linux)
		if uid >= 1000 {
			candidates = append(candidates, struct {
				name string
				uid  int
			}{username, uid})
		}
	}

	if len(candidates) == 0 {
		return ""
	}

	// Return user with lowest UID (deterministic choice)
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

// getPasswdUserWithAdminPreference parses /etc/passwd and prefers admin group members
func getPasswdUserWithAdminPreference(ctx context.Context) string {
	users := parsePasswdFile()
	if len(users) == 0 {
		return ""
	}

	var adminUsers []struct {
		name string
		uid  int
	}
	var regularUsers []struct {
		name string
		uid  int
	}

	// Separate admin and regular users
	for _, user := range users {
		if isUserInAdminGroups(ctx, user.name) {
			adminUsers = append(adminUsers, user)
		} else {
			regularUsers = append(regularUsers, user)
		}
	}

	// Prefer admin users, then regular users
	candidates := adminUsers
	if len(candidates) == 0 {
		candidates = regularUsers
	}

	if len(candidates) == 0 {
		return ""
	}

	// Return user with lowest UID (deterministic choice)
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

// getLowestPasswdUser returns the user with lowest UID >= 1000 from /etc/passwd
func getLowestPasswdUser(ctx context.Context) string {
	users := parsePasswdFile()
	if len(users) == 0 {
		return ""
	}

	// Return user with lowest UID (deterministic choice)
	lowestUID := users[0].uid
	result := users[0].name
	
	for _, user := range users[1:] {
		if user.uid < lowestUID {
			lowestUID = user.uid
			result = user.name
		}
	}

	return result
}

// parsePasswdFile parses /etc/passwd and returns users with UID >= 1000
func parsePasswdFile() []struct {
	name string
	uid  int
} {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		ProxyLogger.Load().Debug().Err(err).Msg("failed to open /etc/passwd")
		return nil
	}
	defer file.Close()

	var users []struct {
		name string
		uid  int
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}

		username := fields[0]
		uidStr := fields[2]

		uid, err := strconv.Atoi(uidStr)
		if err != nil {
			continue
		}

		// Only consider regular users (UID >= 1000 on Linux)
		if uid >= 1000 {
			users = append(users, struct {
				name string
				uid  int
			}{username, uid})
		}
	}

	return users
}

// isUserInAdminGroups checks if a user is in common admin groups
func isUserInAdminGroups(ctx context.Context, username string) bool {
	adminGroups := []string{"sudo", "wheel", "admin"}
	
	for _, group := range adminGroups {
		cmd := exec.CommandContext(ctx, "groups", username)
		out, err := cmd.Output()
		if err != nil {
			continue
		}
		
		if strings.Contains(string(out), group) {
			return true
		}
	}
	
	return false
}