package ctrld

import (
	"context"

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

// username discovery modes for systemMetadata.
const (
	usernameNone    = iota // omit username
	usernameSession        // username only from an active login session
	usernameFull           // username with account-list fallbacks, or "unknown"
)

var (
	discoverMainUserFn    = DiscoverMainUser
	discoverSessionUserFn = discoverSessionUser
)

// SystemMetadata collects full system metadata including username discovery.
// Use for initial provisioning, where full device identification is needed.
func SystemMetadata(ctx context.Context) map[string]string {
	return systemMetadata(ctx, usernameFull)
}

// SystemMetadataStartup collects the metadata for the first managed check-in of
// each daemon start. The daemon usually starts at boot, before anyone logs in,
// so username is sent only when an active login session provides it. Otherwise
// the key is omitted and the API keeps the stored value instead of replacing it
// with an account-list guess or "unknown".
func SystemMetadataStartup(ctx context.Context) map[string]string {
	return systemMetadata(ctx, usernameSession)
}

// SystemMetadataRuntime collects system metadata without username discovery.
// Use for runtime API calls (config reload, self-uninstall check, deactivation
// pin refresh) to avoid repeated user enumeration that can trigger EDR alerts.
func SystemMetadataRuntime(ctx context.Context) map[string]string {
	return systemMetadata(ctx, usernameNone)
}

func systemMetadata(ctx context.Context, usernameMode int) map[string]string {
	logger := LoggerFromCtx(ctx)
	m := make(map[string]string)
	oi := osinfo.New()
	m[metadataOsKey] = oi.String()
	if chassisType == "" && chassisVendor == "" {
		ci, err := system.GetChassisInfo()
		if err != nil {
			logger.Debug().Err(err).Msg("Failed to get chassis info")
		} else {
			chassisType, chassisVendor = ci.Type, ci.Vendor
		}
	}
	m[metadataChassisTypeKey] = chassisType
	m[metadataChassisVendorKey] = chassisVendor
	switch usernameMode {
	case usernameFull:
		m[metadataUsernameKey] = discoverMainUserFn(ctx)
	case usernameSession:
		if user := discoverSessionUserFn(ctx); user != "" {
			m[metadataUsernameKey] = user
		}
	}
	m[metadataDomainOrWorkgroupKey] = partOfDomainOrWorkgroup(ctx)
	domain, err := system.GetActiveDirectoryDomain()
	if err != nil {
		logger.Debug().Err(err).Msg("Failed to get active directory domain name")
	}
	m[metadataDomainKey] = domain

	return m
}
