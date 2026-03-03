//go:build windows

package ctrld

import (
	"context"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	kernel32                         = windows.NewLazySystemDLL("kernel32.dll")
	wtsapi32                         = windows.NewLazySystemDLL("wtsapi32.dll")
	procGetConsoleWindow             = kernel32.NewProc("GetConsoleWindow")
	procWTSGetActiveConsoleSessionId = wtsapi32.NewProc("WTSGetActiveConsoleSessionId")
	procWTSQuerySessionInformation   = wtsapi32.NewProc("WTSQuerySessionInformationW")
	procWTSFreeMemory                = wtsapi32.NewProc("WTSFreeMemory")
)

const (
	WTSUserName = 5
)

// DiscoverMainUser attempts to find the primary user on Windows systems.
// This is designed to work reliably under RMM deployments where traditional
// environment variables and session detection may not be available.
//
// Priority chain (deterministic, lowest RID wins among candidates):
// 1. Active console session user via WTSGetActiveConsoleSessionId
// 2. Registry ProfileList scan for Administrators group members
// 3. Fallback to lowest RID from ProfileList
func DiscoverMainUser(ctx context.Context) string {
	logger := ProxyLogger.Load().Debug()

	// Method 1: Check active console session
	logger.Msg("attempting to discover user via active console session")
	if user := getActiveConsoleUser(ctx); user != "" {
		logger.Str("method", "console").Str("user", user).Msg("found user via active console session")
		return user
	}

	// Method 2: Scan registry for admin users
	logger.Msg("attempting to discover user via registry with admin preference")
	if user := getRegistryUserWithAdminPreference(ctx); user != "" {
		logger.Str("method", "registry+admin").Str("user", user).Msg("found admin user via registry")
		return user
	}

	// Method 3: Fallback to lowest RID from registry
	logger.Msg("attempting to discover user via registry lowest RID")
	if user := getLowestRegistryUser(ctx); user != "" {
		logger.Str("method", "registry").Str("user", user).Msg("found user via registry")
		return user
	}

	logger.Msg("all user discovery methods failed")
	return "unknown"
}

// getActiveConsoleUser gets the username of the active console session
func getActiveConsoleUser(ctx context.Context) string {
	// Guard against missing WTS procedures (e.g., Windows Server Core).
	if err := procWTSGetActiveConsoleSessionId.Find(); err != nil {
		ProxyLogger.Load().Debug().Err(err).Msg("WTSGetActiveConsoleSessionId not available, skipping console session check")
		return ""
	}
	sessionId, _, _ := procWTSGetActiveConsoleSessionId.Call()
	if sessionId == 0xFFFFFFFF { // Invalid session
		ProxyLogger.Load().Debug().Msg("no active console session found")
		return ""
	}

	var buffer uintptr
	var bytesReturned uint32

	if err := procWTSQuerySessionInformation.Find(); err != nil {
		ProxyLogger.Load().Debug().Err(err).Msg("WTSQuerySessionInformationW not available")
		return ""
	}
	ret, _, _ := procWTSQuerySessionInformation.Call(
		0, // WTS_CURRENT_SERVER_HANDLE
		sessionId,
		uintptr(WTSUserName),
		uintptr(unsafe.Pointer(&buffer)),
		uintptr(unsafe.Pointer(&bytesReturned)),
	)

	if ret == 0 {
		ProxyLogger.Load().Debug().Msg("failed to query session information")
		return ""
	}
	defer procWTSFreeMemory.Call(buffer)

	// Convert buffer to string
	username := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(buffer)))
	if username == "" {
		return ""
	}

	return username
}

// getRegistryUserWithAdminPreference scans registry profiles and prefers admin users
func getRegistryUserWithAdminPreference(ctx context.Context) string {
	profiles := getRegistryProfiles()
	if len(profiles) == 0 {
		return ""
	}

	var adminProfiles []registryProfile
	var regularProfiles []registryProfile

	// Separate admin and regular users
	for _, profile := range profiles {
		if isUserInAdministratorsGroup(profile.username) {
			adminProfiles = append(adminProfiles, profile)
		} else {
			regularProfiles = append(regularProfiles, profile)
		}
	}

	// Prefer admin users, then regular users
	candidates := adminProfiles
	if len(candidates) == 0 {
		candidates = regularProfiles
	}

	if len(candidates) == 0 {
		return ""
	}

	// Return user with lowest RID (deterministic choice)
	lowestRID := candidates[0].rid
	result := candidates[0].username

	for _, candidate := range candidates[1:] {
		if candidate.rid < lowestRID {
			lowestRID = candidate.rid
			result = candidate.username
		}
	}

	return result
}

// getLowestRegistryUser returns the user with lowest RID from registry
func getLowestRegistryUser(ctx context.Context) string {
	profiles := getRegistryProfiles()
	if len(profiles) == 0 {
		return ""
	}

	// Return user with lowest RID (deterministic choice)
	lowestRID := profiles[0].rid
	result := profiles[0].username

	for _, profile := range profiles[1:] {
		if profile.rid < lowestRID {
			lowestRID = profile.rid
			result = profile.username
		}
	}

	return result
}

type registryProfile struct {
	username string
	rid      uint32
	sid      string
}

// getRegistryProfiles scans the registry ProfileList for user profiles
func getRegistryProfiles() []registryProfile {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		ProxyLogger.Load().Debug().Err(err).Msg("failed to open ProfileList registry key")
		return nil
	}
	defer key.Close()

	subkeys, err := key.ReadSubKeyNames(-1)
	if err != nil {
		ProxyLogger.Load().Debug().Err(err).Msg("failed to read ProfileList subkeys")
		return nil
	}

	var profiles []registryProfile

	for _, subkey := range subkeys {
		// Only process SIDs that start with S-1-5-21 (domain/local user accounts)
		if !strings.HasPrefix(subkey, "S-1-5-21-") {
			continue
		}

		profileKey, err := registry.OpenKey(key, subkey, registry.QUERY_VALUE)
		if err != nil {
			continue
		}

		profileImagePath, _, err := profileKey.GetStringValue("ProfileImagePath")
		profileKey.Close()
		if err != nil {
			continue
		}

		// Extract username from profile path (e.g., C:\Users\username)
		pathParts := strings.Split(profileImagePath, `\`)
		if len(pathParts) == 0 {
			continue
		}
		username := pathParts[len(pathParts)-1]

		// Extract RID from SID (last component after final hyphen)
		sidParts := strings.Split(subkey, "-")
		if len(sidParts) == 0 {
			continue
		}
		ridStr := sidParts[len(sidParts)-1]
		rid, err := strconv.ParseUint(ridStr, 10, 32)
		if err != nil {
			continue
		}

		// Only consider regular users (RID >= 1000, excludes built-in accounts).
		// rid == 500 is the default Administrator account (DOMAIN_USER_RID_ADMIN).
		// See: https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
		if rid == 500 || rid >= 1000 {
			profiles = append(profiles, registryProfile{
				username: username,
				rid:      uint32(rid),
				sid:      subkey,
			})
		}
	}

	return profiles
}

// isUserInAdministratorsGroup checks if a user is in the Administrators group
func isUserInAdministratorsGroup(username string) bool {
	// Open the user account
	usernamePtr, err := syscall.UTF16PtrFromString(username)
	if err != nil {
		return false
	}

	var userSID *windows.SID
	var domain *uint16
	var userSIDSize, domainSize uint32
	var use uint32

	// First call to get buffer sizes
	err = windows.LookupAccountName(nil, usernamePtr, userSID, &userSIDSize, domain, &domainSize, &use)
	if err != nil && err != windows.ERROR_INSUFFICIENT_BUFFER {
		return false
	}

	// Allocate buffers and make actual call
	userSID = (*windows.SID)(unsafe.Pointer(&make([]byte, userSIDSize)[0]))
	domain = (*uint16)(unsafe.Pointer(&make([]uint16, domainSize)[0]))

	err = windows.LookupAccountName(nil, usernamePtr, userSID, &userSIDSize, domain, &domainSize, &use)
	if err != nil {
		return false
	}

	// Check if user is member of Administrators group (S-1-5-32-544)
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false
	}

	// Open user token (this is a simplified check)
	var token windows.Token
	err = windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		return false
	}
	defer token.Close()

	// Check group membership
	member, err := token.IsMember(adminSID)
	if err != nil {
		return false
	}

	return member
}
