package ctrld

import (
	"context"
	"sync"

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
	// chassisMu guards chassisType and chassisVendor. Read them with chassisValues.
	chassisMu     sync.Mutex
	chassisType   string
	chassisVendor string
)

// getChassisInfoFn is system.GetChassisInfo. Tests replace it.
var getChassisInfoFn = system.GetChassisInfo

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
	m := make(map[string]string)
	m[metadataOsKey] = OSVersion()
	if isMobile() {
		return mobileMetadata(m)
	}
	m[metadataChassisTypeKey], m[metadataChassisVendorKey] = chassisValues()
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
		ProxyLogger.Load().Debug().Err(err).Msg("Failed to get active directory domain name")
	}
	m[metadataDomainKey] = domain

	return m
}

// chassisValues returns the cached chassis type and vendor. It looks them up
// while both are empty, so a failed lookup, or one that returns two empty
// values, is tried again on the next call. A result with one empty value is
// kept.
// Several goroutines call systemMetadata, so the mutex guards the cache. It is
// held during the lookup, so the lookup runs at most once at a time.
func chassisValues() (kind, vendor string) {
	chassisMu.Lock()
	defer chassisMu.Unlock()
	if chassisType == "" && chassisVendor == "" {
		ci, err := getChassisInfoFn()
		if err != nil {
			ProxyLogger.Load().Debug().Err(err).Msg("Failed to get chassis info")
			return chassisType, chassisVendor
		}
		chassisType, chassisVendor = ci.Type, ci.Vendor
	}
	return chassisType, chassisVendor
}

// mobileMetadata completes m without the host values. Each of them starts a
// system tool on iOS, and an iOS app has no login user. With no username key,
// the API keeps the value that it has.
func mobileMetadata(m map[string]string) map[string]string {
	m[metadataChassisTypeKey] = ""
	m[metadataChassisVendorKey] = ""
	m[metadataDomainOrWorkgroupKey] = "false"
	m[metadataDomainKey] = ""
	return m
}
