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

// SystemMetadata collects full system metadata including username discovery.
// Use for initial provisioning and first-run config validation where full
// device identification is needed.
func SystemMetadata(ctx context.Context) map[string]string {
	return systemMetadata(ctx, true)
}

// SystemMetadataRuntime collects system metadata without username discovery.
// Use for runtime API calls (config reload, self-uninstall check, deactivation
// pin refresh) to avoid repeated user enumeration that can trigger EDR alerts.
func SystemMetadataRuntime(ctx context.Context) map[string]string {
	return systemMetadata(ctx, false)
}

func systemMetadata(ctx context.Context, includeUsername bool) map[string]string {
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
	if includeUsername {
		m[metadataUsernameKey] = DiscoverMainUser(ctx)
	}
	m[metadataDomainOrWorkgroupKey] = partOfDomainOrWorkgroup(ctx)
	domain, err := system.GetActiveDirectoryDomain()
	if err != nil {
		logger.Debug().Err(err).Msg("Failed to get active directory domain name")
	}
	m[metadataDomainKey] = domain

	return m
}
