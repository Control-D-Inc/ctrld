package ctrld

import (
	"context"
	"os"
	"os/user"

	"github.com/cuonglm/osinfo"

	"github.com/Control-D-Inc/ctrld/internal/system"
)

const (
	metadataOsKey                = "os"
	metadataChassisTypeKey       = "chassis_type"
	metadataChassisVendorKey     = "chassis_vendor"
	metadataUsernameKey          = "username"
	metadataDomainOrWorkgroupKey = "domain_or_workgroup"
	metadataDomainKey            = "domain"
)

var (
	chassisType   string
	chassisVendor string
)

// SystemMetadata collects system and user-related SystemMetadata and returns it as a map.
func SystemMetadata(ctx context.Context) map[string]string {
	m := make(map[string]string)
	oi := osinfo.New()
	m[metadataOsKey] = oi.String()
	if chassisType == "" && chassisVendor == "" {
		if ci, err := system.GetChassisInfo(); err == nil {
			chassisType, chassisVendor = ci.Type, ci.Vendor
		}
	}
	m[metadataChassisTypeKey] = chassisType
	m[metadataChassisVendorKey] = chassisVendor
	m[metadataUsernameKey] = currentLoginUser(ctx)
	m[metadataDomainOrWorkgroupKey] = partOfDomainOrWorkgroup(ctx)
	domain, err := system.GetActiveDirectoryDomain()
	if err != nil {
		ProxyLogger.Load().Debug().Err(err).Msg("Failed to get active directory domain name")
	}
	m[metadataDomainKey] = domain

	return m
}

// currentLoginUser attempts to find the actual login user, even if the process is running as root.
func currentLoginUser(ctx context.Context) string {
	// 1. Check SUDO_USER: This is the most reliable way to find the original user
	// when a script is run via 'sudo'.
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		return sudoUser
	}

	// 2. Check general user login variables. LOGNAME is often preferred over USER.
	if logName := os.Getenv("LOGNAME"); logName != "" {
		return logName
	}

	// 3. Fallback to USER variable.
	if userEnv := os.Getenv("USER"); userEnv != "" {
		return userEnv
	}

	// 4. Final fallback: Use the standard library function to get the *effective* user.
	// This will return "root" if the process is running as root.
	currentUser, err := user.Current()
	if err != nil {
		// Handle error gracefully, returning a placeholder
		ProxyLogger.Load().Debug().Err(err).Msg("Failed to get current user")
		return "unknown"
	}

	return currentUser.Username
}
