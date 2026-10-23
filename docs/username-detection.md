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
| `ctrld-client start` with `--cd-org` (provisioning via `cdUIDFromProvToken`) | ✅ Full | ✅ Yes |
| `ctrld-client run` managed startup (`processCDFlags`) | ✅ Full | ⚠️ Only from an active login session |
| Mobile library start (`RunMobile` → `processCDFlags`) | ✅ Full | ❌ No (see below) |
| `ctrld-client start --cd` install validation (`doValidateCdRemoteConfig`) | ✅ Lightweight | ❌ No |
| `ctrld-client restart` configuration validation (`doValidateCdRemoteConfig`) | ✅ Lightweight | ❌ No |
| Runtime config reload (`doReloadApiConfig`) | ✅ Lightweight | ❌ No |
| Runtime self-uninstall check | ✅ Lightweight | ❌ No |
| Runtime deactivation pin refresh | ✅ Lightweight | ❌ No |

Provisioning runs the full `DiscoverMainUser` chain. Each managed daemon start runs only the active-session part of that chain (`SystemMetadataStartup`): the console user on macOS, the active console session on Windows, or an active `loginctl` user on Linux. The daemon usually starts at boot, before anyone logs in. When no session user is found, the start omits `username`, and the API keeps the stored value instead of replacing it with an account-list guess or `"unknown"`. Full daemon-start metadata also includes the supported hostname hints. Periodic, forced, self-uninstall, deactivation-PIN, and install/restart validation requests use `SystemMetadataRuntime()` and omit username discovery and hostname hints.

A `--cd-org` install therefore sends two full snapshots: the token exchange (`cdUIDFromProvToken`), then the first check-in of the daemon that `start` launches with `--cd=<uid>`. Full discovery runs for the first and session discovery for the second. The API merges metadata objects, so the second snapshot does not erase fields from the first.

The mobile library starts through `processCDFlags` too. iOS builds use `GOOS=darwin`, but the `stat` and `scutil` commands that macOS session discovery runs are not available, and Android has no `loginctl` session. Session discovery on mobile finds no user, so the mobile start omits `username`.

### Host metadata wire contract (version 1)

Every managed `/utility` request body carries `uid`, an optional `client_id`, and `metadata`. `metadata` is a JSON object of string values, or `null` when the caller supplies none. `UpdateCustomLastFailed` sends `null`, which the API treats as metadata omitted. All resolver-config callers supply metadata.

Columns: **Provisioning** is the `--cd-org` token exchange; **Start** is the first check-in of each managed daemon start; **Runtime** is every other request in the table above.

| Key | Source | Platforms | Provisioning | Start | Runtime | Value when the source is unavailable |
|---|---|---|---|---|---|---|
| `os` | `osinfo` | All | ✅ | ✅ | ✅ | Always present |
| `chassis_type` | `system.GetChassisInfo` (macOS model identifier) | All | ✅ | ✅ | ✅ | `""` |
| `chassis_vendor` | `system.GetChassisInfo` (`Apple Inc.` on macOS) | All | ✅ | ✅ | ✅ | `""` |
| `username` | Provisioning: `DiscoverMainUser`. Start: active login session only | All | ✅ | ⚠️ Session user only | ❌ | Provisioning: `"unknown"`. Start: key omitted |
| `domain_or_workgroup` | Windows domain-join status | Windows; `"false"` elsewhere | ✅ | ✅ | ✅ | `"false"` |
| `domain` | Active Directory domain | Windows; `""` elsewhere | ✅ | ✅ | ✅ | `""` |
| `hostname_ComputerName` | `scutil --get ComputerName` | macOS only | ✅ | ✅ | ❌ | Key omitted |
| `hostname_LocalHostName` | `scutil --get LocalHostName` | macOS only | ✅ | ✅ | ❌ | Key omitted |
| `hostname_HostName` | `scutil --get HostName` | macOS only | ✅ | ✅ | ❌ | Key omitted |
| `hostname_os.Hostname` | `os.Hostname()` | All | ✅ | ✅ | ❌ | Key omitted |

The API accepts only these ten keys. It ignores unknown keys, non-string values, and any value longer than 255 bytes, field by field, without failing the request. An omitted key keeps the stored value and a present empty string clears it. The server side of this contract is [`docs/ctrld-utility-host-metadata.md` in controld-api](https://gitlab.int.windscribe.com/controld/backend/api/-/blob/master/docs/ctrld-utility-host-metadata.md). Bump the version above when a key, its platforms, or its unavailable value changes.

### Runtime metadata (`SystemMetadataRuntime`)

Runtime API calls (config reload, self-uninstall check, deactivation pin refresh, install/restart validation) use `SystemMetadataRuntime()` which includes OS and chassis info but **skips username discovery**. This avoids:

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