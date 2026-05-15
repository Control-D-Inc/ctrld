# Username Detection in ctrld

## Overview

The ctrld client needs to detect the primary user of a system for telemetry and configuration purposes. This is particularly challenging in RMM (Remote Monitoring and Management) deployments where traditional session-based detection methods fail.

## The Problem

In traditional desktop environments, username detection is straightforward using environment variables like `$USER`, `$LOGNAME`, or `$SUDO_USER`. However, RMM deployments present unique challenges:

- **No active login session**: RMM agents often run as system services without an associated user session
- **Missing environment variables**: Common user environment variables are not available in service contexts
- **Root/SYSTEM execution**: The ctrld process may run with elevated privileges, masking the actual user

## Solution Approach

ctrld implements a multi-tier, deterministic username detection system through the `DiscoverMainUser()` function with platform-specific implementations:

### Key Principles

1. **Deterministic selection**: No randomness - always returns the same result for the same system state
2. **Priority chain**: Multiple detection methods with clear fallback order
3. **Lowest UID/RID wins**: Among multiple candidates, select the user with the lowest identifier (typically the first user created)
4. **Fast execution**: All operations complete in <100ms using local system resources
5. **Debug logging**: Each decision point logs its rationale for troubleshooting

## Platform-Specific Implementation

### macOS (`discover_user_darwin.go`)

**Detection chain:**
1. **Console owner** (`stat -f %Su /dev/console`) - Most reliable for active GUI sessions
2. **scutil ConsoleUser** - Alternative session detection via System Configuration framework
3. **Directory Services scan** (`dscl . list /Users UniqueID`) - Scan all users with UID ≥ 501, select lowest

**Rationale**: macOS systems typically have a primary user who owns the console. Service contexts can still access device ownership information.

### Linux (`discover_user_linux.go`)

**Detection chain:**
1. **loginctl active users** (`loginctl list-users`) - systemd's session management
2. **Admin user preference** - Parse `/etc/passwd` for UID ≥ 1000, prefer sudo/wheel/admin group members
3. **Lowest UID fallback** - From `/etc/passwd`, select user with UID ≥ 1000 and lowest UID

**Rationale**: Linux systems may have multiple regular users. Prioritize users in administrative groups as they're more likely to be primary system users.

### Windows (`discover_user_windows.go`)

**Detection chain:**
1. **Active console session** (`WTSGetActiveConsoleSessionId` + `WTSQuerySessionInformation`) - Direct Windows API for active user
2. **Registry admin preference** - Scan `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`, prefer Administrators group members
3. **Lowest RID fallback** - From ProfileList, select user with RID ≥ 1000 and lowest RID

**Rationale**: Windows has well-defined APIs for session management. Registry ProfileList provides a complete view of all user accounts when no active session exists.

### Other Platforms (`discover_user_others.go`)

Returns `"unknown"` - placeholder for unsupported platforms.

## Implementation Details

### Error Handling

- Individual detection methods log failures at Debug level and continue to next method
- Only final failure (all methods failed) is noteworthy
- Graceful degradation ensures the system continues operating with `"unknown"` user

### Performance Considerations

- Registry/file parsing uses native Go where possible
- External command execution limited to necessary cases
- No network calls or blocking operations
- Timeout context honored for all operations

### Security

- No privilege escalation required
- Read-only operations on system resources
- No user data collected beyond username
- Respects system access controls

## Testing Scenarios

This implementation addresses these common RMM scenarios:

1. **Windows Service context**: No interactive user session, service running as SYSTEM
2. **Linux systemd service**: No login session, running as root daemon
3. **macOS LaunchDaemon**: No GUI user context, running as root
4. **Multi-user systems**: Multiple valid candidates, deterministic selection
5. **Minimalist systems**: Limited user accounts, fallback to available options

## Metadata Submission Strategy

System metadata (OS, chassis, username, domain) is sent to the Control D API via POST `/utility`. To avoid duplicate submissions and minimize EDR-triggering user discovery, ctrld uses a tiered approach:

### When metadata is sent

| Scenario | Metadata sent? | Username included? |
|---|---|---|
| `ctrld start` with `--cd-org` (provisioning via `cdUIDFromProvToken`) | ✅ Full | ✅ Yes |
| `ctrld run` startup (config validation / processCDFlags) | ✅ Lightweight | ❌ No |
| Runtime config reload (`doReloadApiConfig`) | ✅ Lightweight | ❌ No |
| Runtime self-uninstall check | ✅ Lightweight | ❌ No |
| Runtime deactivation pin refresh | ✅ Lightweight | ❌ No |

Username is only collected and sent once — during initial provisioning via `cdUIDFromProvToken()`. All other API calls use `SystemMetadataRuntime()` which omits username discovery entirely.

### Runtime metadata (`SystemMetadataRuntime`)

Runtime API calls (config reload, self-uninstall check, deactivation pin refresh) use `SystemMetadataRuntime()` which includes OS and chassis info but **skips username discovery**. This avoids:

- **EDR false positives**: Repeated user enumeration (registry scans, WTS queries, loginctl calls) can trigger endpoint detection and response alerts
- **Unnecessary work**: Username is unlikely to change while the service is running

## Migration Notes

The previous `currentLoginUser()` function has been replaced by `DiscoverMainUser()` with these changes:

- **Removed dependencies**: No longer uses `logname(1)`, environment variables as primary detection
- **Added platform specificity**: Separate files for each OS with optimized detection logic  
- **Improved RMM compatibility**: Designed specifically for service/daemon contexts
- **Maintained compatibility**: Returns same format (string username or "unknown")

## Future Extensions

This architecture allows easy addition of new platforms by creating additional `discover_user_<os>.go` files following the same interface pattern.