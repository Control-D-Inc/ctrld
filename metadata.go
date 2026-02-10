package ctrld

import (
	"context"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"

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
	// On Darwin 26.2+, sudo no longer preserves SUDO_USER, LOGNAME, USER etc., so we cannot
	// rely on environment variables when running under sudo. See CVE-2025-43416.
	// We use the logname(1) command on Unix, which reports the login name from the session
	// (e.g. utmp); there is no portable syscall equivalent in Go, so we exec logname.
	if runtime.GOOS != "windows" {
		if name := runLogname(ctx); name != "" {
			return name
		}
	}

	// Fallback: env vars (still set on older systems or when not using sudo)
	if u := os.Getenv("SUDO_USER"); u != "" {
		return u
	}
	if u := os.Getenv("LOGNAME"); u != "" {
		return u
	}
	if u := os.Getenv("USER"); u != "" {
		return u
	}

	currentUser, err := user.Current()
	if err != nil {
		ProxyLogger.Load().Debug().Err(err).Msg("Failed to get current user")
		return "unknown"
	}
	return currentUser.Username
}

// runLogname runs the logname(1) command and returns the trimmed output, or "" on failure.
func runLogname(ctx context.Context) string {
	cmd := exec.CommandContext(ctx, "logname")
	out, err := cmd.Output()
	if err != nil {
		ProxyLogger.Load().Debug().Err(err).Msg("Failed to run logname")
		return ""
	}
	return strings.TrimSpace(string(out))
}
