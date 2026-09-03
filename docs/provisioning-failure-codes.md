# Provisioning failure codes

When ctrld hits a terminal failure during provisioning, it reports the same
stable code on three surfaces:

- **Result file** — `provision_result.json` in the ctrld home directory
  (next to the persisted internal `ctrld.log`). JSON with `stage`, `code`,
  `exit_code`, `message`, and for listener failures a bounded
  `detail.attempts` list of `{addr, proto, os_error}`. Written atomically,
  removed on the next successful provisioning. Never contains provision
  tokens, resolver/device IDs, or configuration contents.
- **Output line** — one fixed-format line on the CLI output:
  `provisioning failed: stage=<stage> code=<CODE> (exit <N>)`.
  Installer or MDM wrappers can extract exactly this line (fixed charset:
  `stage=[a-z]* code=[A-Z_]* (exit [0-9]*)`) into their own logs without
  risking token leakage from other output.
- **Exit code** — stage-scoped: input 20–29, bootstrap 30–39,
  listener 40–49, service 50–59. This does not change other existing
  exit-code contracts: `ctrld-client status` still exits 0–3, and an invalid
  deactivation pin still exits 126.

A customer or administrator only needs to report the code (or the whole
output line). The table below is the maintained support mapping; it must
stay in sync with `cmd/cli/provision_result.go` and changes in the same MR.

## Codes

For every code below, first run `sudo ctrld-client diag` (`sudo ctrld-client diag --json`
gives a paste-safe, machine-readable copy). Get that output before you do
anything else. The command needs no running service. Without root, the
last-provisioning-result and service-state sections report permission
denied, so run it with `sudo`. It repeats the same stage, code, and message
the customer already reported.
The **Next action / evidence** column lists what to look at next.

| Code | Stage | Exit | Failure scenario | Next action / evidence |
|---|---|---|---|---|
| `PROVISION_TOKEN_MALFORMED` | input | 21 | The `--cd-org` value is not a provisioning code: it is empty, too short, too long, or it contains whitespace or control characters. ctrld checks this before any network call. A missing `org-v1-` prefix is not this code. That case only logs a warning, because legacy codes can lack the prefix. | Make sure that the provisioning code was copied in full, with no extra whitespace. The result file never echoes the value. |
| `CUSTOM_HOSTNAME_INVALID` | input | 22 | The `--custom-hostname` value fails ctrld's own hostname rule (`validHostname`): it is not 3 to 64 characters, or it is not in RFC1123 hostname format. ctrld checks this before any network call. The API itself does not reject a bad hostname during provisioning. When ControlD registers the device name, it folds or strips characters like space, `+`, and `.`. Because of this, a value ctrld accepts can still register under an adjusted name. That case only logs a notice, not a failure. | Fix `--custom-hostname` following the message: it names the offending characters and the allowed format. |
| `INTERCEPT_MODE_INVALID` | input | 23 | The `--intercept-mode` value is not one of `off`, `dns`, or `hard`. ctrld checks this before it installs the service. | Re-run with a valid `--intercept-mode` value. |
| `INVALID_FLAG_COMBINATION` | input | 24 | `--cd` or `--cd-org` is used together with `--nextdns`, or `--proto` is set to anything other than `doh`/`doh3` while `--cd` is in play. ctrld checks this before any network call or service install. | Re-run without the conflicting flag, or fix the invalid value. The message names the exact flags involved. |
| `API_UNREACHABLE` | bootstrap | 30 | The Control D API could not be reached or answered with a retryable error (network failure, proxy interference, 5xx, timeout) and retries ran out. The service manager may retry the service later. | Make sure that the device has network access to `api.controld.com` (DNS, proxy, firewall, captive portal). `ctrld-client diag`'s `api_reachability` block already ran this same probe. Ask whether other TLS traffic works. |
| `API_REJECTED` | bootstrap | 31 | The API answered and permanently rejected the configuration (4xx other than 408/429): bad or revoked token, malformed request. ctrld exits without burning service-manager restarts because retrying cannot change the answer. This is also the fallback for the four `TOKEN_*` codes below. Those codes need the API response to carry `error.metadata.reason`. An API deployment that does not yet populate that field reports every provisioning-code rejection as `API_REJECTED` instead. | Verify the provision token / org configuration in the Control D dashboard. Re-push after fixing credentials. Evidence: HTTP status in the result file `message`. |
| `API_DEVICE_INVALID` | bootstrap | 32 | The API reports the device/resolver no longer exists (error code 40402). When the daemon's own bootstrap preflight discovers this, it self-uninstalls, because the identity is gone server-side. The direct `--cd <uid>` install path (`ctrld-client start --cd`) can also hit this code before the service exists. On that path there is nothing to uninstall yet. | Confirm the device was deleted or re-provisioned in the dashboard; re-provision with a current token. No local evidence needed beyond the code. |
| `TOKEN_INVALID` | bootstrap | 33 | The API rejected the `--cd-org` provisioning code with reason `token_invalid`: the code is not recognized. This code needs the deployed API to send `error.metadata.reason: "token_invalid"`. See `API_REJECTED` above for the fallback when it does not. | Make sure that the code is correct. Re-enter it exactly as given. |
| `TOKEN_EXPIRED` | bootstrap | 34 | The API rejected the `--cd-org` provisioning code with reason `token_expired`. This has the same API-reason dependency as `TOKEN_INVALID`. | Get a new provisioning code from your administrator. |
| `TOKEN_LIMIT_REACHED` | bootstrap | 35 | The API rejected the `--cd-org` provisioning code with reason `token_limit_reached`: it reached its device limit. This has the same API-reason dependency as `TOKEN_INVALID`. | Free up a device slot or use a different provisioning code. |
| `TOKEN_DISABLED` | bootstrap | 36 | The API rejected the `--cd-org` provisioning code with reason `token_disabled`: the code was invalidated. This has the same API-reason dependency as `TOKEN_INVALID`. | Download a profile from an active provisioning code. |
| `LISTENER_BIND_FAILED` | listener | 41 | No listen address could be bound after all fallbacks (configured address, 0.0.0.0:53, localhost:53, random) were exhausted. `detail.attempts` records each tried address with the UDP/TCP OS error, e.g. `address already in use` (another DNS service owns the port) or `can't assign requested address` (address not on any interface). | Read `detail.attempts`: `address already in use` → find the process owning the port (`sudo lsof -i :53 -nP`); `can't assign requested address` → the configured IP is not present on the device. Then fix the conflict or the listener config. |
| `LISTENER_CONFIGURED_ADDR_UNAVAILABLE` | listener | 42 | An explicitly configured listener address could not be bound and configuration checks forbid falling back to another address, or (macOS intercept mode) the required explicit address is unavailable. | The configured `ip:port` in the listener config is wrong for this device or occupied. Verify the address exists on an interface and nothing else binds it; correct the config rather than expecting fallback. |
| `SERVICE_INSTALL_FAILED` | service | 51 | The OS service manager refused to install the service (launchd/systemd/SCM registration failed). | Check OS-level constraints: permissions/elevation, MDM policy blocking daemon installation, corrupted previous install. Evidence: result file `message` (service manager error), plus `launchctl print system/ctrld-client` / `systemctl status ctrld-client` / SCM state. |
| `SERVICE_START_FAILED` | service | 52 | The service installed but the service manager could not start it. | Check the service manager's own log for the start error, then the ctrld home dir `ctrld.log`. Often permissions or a binary quarantined by security tooling. |
| `SERVICE_SELFCHECK_FAILED` | service | 53 | The service started but never became healthy: no fresher failure was reported by the daemon, and the post-install DNS self-check failed. On a fresh install or an upgrade, the just-installed service is rolled back (uninstalled). A restart of an already installed service keeps that service installed. If the daemon itself recorded a more specific failure (e.g. a listener code), that code is reported instead of this one. | Ask for the drained service log printed by `ctrld-client start` and the result file. If the service was running but unreachable, check host firewall rules intercepting DNS to the listener. |
| `UNCLASSIFIED` | service | 59 | This code covers terminal failures on the provisioning boundary that predate a dedicated code. Examples include a config unmarshal, and a file-system or environment failure such as writing the config file, reading `socketDir`, or respawning as a daemon. Other examples are a service-argument update failing mid-upgrade, and a DNS-intercept failure the interface-DNS fallback cannot safely take over from. Every one of these used to be a bare crash with nothing to read. Now they all persist a result file. | Read the result file `message`: it names the specific operation that failed and the underlying OS error. When you report it, treat this the same as any other stage-scoped failure. |

The macOS installer script (`scripts/pkg/postinstall`) emits the package rows
below, not ctrld itself, before ctrld ever runs. They only ever exit 1 (the
script's own exit code), and they never appear in `provision_result.json`.
The same script also reuses `PROVISION_TOKEN_MALFORMED` and
`CUSTOM_HOSTNAME_INVALID` from the table above, for its own pre-flight
checks on the managed-prefs `ProvisionToken`/`CustomHostname` values. It
uses the same rule, and also logs it as `stage=package (exit 1)`. So those
two codes can appear with either stage, depending on which side rejected
the value.

| `PROFILE_PREFS_MISSING` | package | 1 | The MDM configuration profile (managed prefs domain `com.controld.ctrld`) has no `ProvisionToken`, or the value is empty. This shows up after the postinstall script's wait loop ends: 12 attempts, 10 seconds apart, about 2 minutes. | Scope the `com.controld.ctrld` configuration profile to the device. If the profile is already on the device, set its `ProvisionToken` value. Then reinstall the package, or run `sudo ctrld-client start --cd-org=<token>` by hand. |
| `INTERCEPT_MODE_INVALID` | package | 1 | On a fresh install, the profile's `InterceptMode` is set, but it is not one of the managed-prefs values (empty, `standard`, `intercept-dns`). A fresh install fails visibly, instead of silently falling back, because a managed deployment must not provision into an unintended mode. On an upgrade, the same bad value only logs a warning and keeps the existing service mode. So a bad profile edit cannot break an already-working fleet. | Fix `InterceptMode` in the profile to one of the allowed values. Then reinstall the package. |
| `SERVICE_RELOAD_FAILED` | package | 1 | An upgrade reused the existing service mode (no managed `InterceptMode` override), and `launchctl load` on the installed plist failed. | Run `sudo launchctl load /Library/LaunchDaemons/ctrld-client.plist` by hand, and read the error it gives. |
| `TEMP_FILE_UNAVAILABLE` | package | 1 | The script failed to create the private temp file it uses to capture ctrld's output (`/tmp` or `TMPDIR` is full or unwritable). Because ctrld never runs, the script has no diagnostics to add. | Free space in `/tmp` or `TMPDIR`, or fix its permissions. Then reinstall the package. |

## Customer-visible message shape

Every failure shows the same two-part shape: the fixed identifier line, then
one free-text line specific to the code. Neither part ever contains the
provision token, the resolver/device ID, or config contents.

- **Input stage** — names the offending flag or value and the rule it
  broke. For example: `--cd-org provisioning code is malformed: must be
  6-64 characters with no whitespace or control characters`. For
  `CUSTOM_HOSTNAME_INVALID`, the message names the specific offending
  characters and the allowed format.
- **Bootstrap, `TOKEN_*`** — one fixed sentence per code (see the table
  above). For example: `the provisioning code has expired; get a new
  provisioning code from your administrator`.
- **Bootstrap, `API_UNREACHABLE`/`API_REJECTED`/`API_DEVICE_INVALID`** —
  When the failure surfaces during a running install's periodic resolver
  refresh, the message is `ControlD API rejected this configuration (HTTP
  status <n>)`. When it surfaces during the initial provisioning call, the
  message is `provision token exchange failed: <err>` or `failed to fetch
  resolver config: <err>`. Neither ever includes the request or response
  body.
- **Listener** — names the address or addresses tried. `detail.attempts` in
  the result file carries the OS error for each address and protocol.
- **Service** — For `SERVICE_INSTALL_FAILED` or `SERVICE_START_FAILED`, the
  message is `<task> failed: <err>` (`<task>` is `Install` or `Start`).
  When the daemon itself reported no fresher failure, `SERVICE_SELFCHECK_FAILED`
  shows one of three messages, depending on what the self-check saw. When
  there is no error and the service is not running, the message is `ctrld
  service did not pass its post-start self-check`. When the test query
  itself errored, the message is `An error occurred while performing test
  query: <err>`. When the service was running but the query silently
  failed, the message is `ctrld service was running, but a DNS query could
  not be sent to its listener; check firewall rules
  blocking/intercepting/redirecting DNS queries`.
- **Package** — the plain-language second line the installer script logs
  right after the identifier line. Each package row's *Next action* cell
  above quotes this line verbatim, because the script has no separate
  result file to carry it.

## Where each code surfaces

- **Every ctrld-native code** (every row above except `package`): the CLI
  output / persisted `ctrld.log`, `provision_result.json`, and `ctrld-client diag`
  (which reads that same file).
- **Package-stage codes** (`PROFILE_PREFS_MISSING`, `SERVICE_RELOAD_FAILED`,
  `TEMP_FILE_UNAVAILABLE`, the package's own `INTERCEPT_MODE_INVALID` check
  on the managed-prefs value, and the package pre-flight's reused
  `PROVISION_TOKEN_MALFORMED` and `CUSTOM_HOSTNAME_INVALID`): only
  `/var/log/install.log`. ctrld never ran, so no result file exists yet.
  `sudo ctrld-client diag` run right after this reports "none recorded" for the last
  provisioning result. That is still useful: it shows that the package
  script's own gate rejected the profile before ctrld had a chance to run.
- **Any ctrld-native code can also reach `/var/log/install.log`.** The
  postinstall script invokes ctrld in two cases: to provision on a fresh
  install, or to reapply a managed intercept mode on an upgrade. Either
  time, it greps ctrld's own identifier line out of the captured output.
  It re-logs that line, and appends `(ctrld exit <n>)`. So a bootstrap or
  listener code, not only the three package-only codes, can appear in the
  MDM install log. Right after any installer-script failure, it also
  appends a fresh `sudo ctrld-client diag` run, each line prefixed `diag:`.

## Reading the result file

macOS and Linux (default service home is `/etc/controld`):

```sh
sudo cat /etc/controld/provision_result.json
```

On Windows the file sits next to `ctrld-client.exe` in the install directory. A
custom `homedir` config moves it accordingly; routers and mobile use their
platform home directory.

The file sits in the same directory as the persisted internal log
(`ctrld.log`) for the user the service runs as. On a healthy install the
file is absent.

## Support: `ctrld-client diag`

Run `sudo ctrld-client diag` (or `sudo ctrld-client diag --json`) to collect the facts
support needs for a provisioning ticket, in one copy-paste-safe command. It
collects the client version and the MDM-managed preferences (macOS only,
the token reported only as present or absent, an empty value counts as
absent). It also collects the last provisioning result, the service state,
and whether the Control D API is reachable. It needs no config. It also
runs without root, but then the last-provisioning-result and the
service-state sections report permission denied, and the text report names
the step that gets the rights it needs. Even when it finds a failure, it
still exits 0: that failure is part of the report, not a command failure.
It never asks for or prints the provisioning token itself.

The `provision_result.status` field in the JSON report is one of `none`
(no result file), `recorded`, `untrusted` (a file that fails the contract
check), `unreadable` (permission denied), or `corrupt` (a file that could
not be parsed).

## Rules for maintainers

- Codes are append-only once released. Never rename, renumber, or reuse a
  code or exit number; add a new one and note the deprecation here.
- API rejection reasons are append-only too: `tokenFailureCodeForReason`
  maps a fixed set of `error.metadata.reason` strings to their `TOKEN_*`
  code. An unrecognized or absent reason falls back to `API_REJECTED` (see
  `apiFailureCode`). So a new reason string does nothing until both a
  matching code and a row here exist.
- Every code added in `cmd/cli/provision_result.go` needs a row here in the
  same MR. Tests enforce the code/stage/exit maps and that this table has
  exactly one `stage != package` row per ctrld code. The `package` rows
  belong to `scripts/pkg/postinstall` and are not part of that count.
- Detail must stay bounded and free of secrets: the constructor strips the
  provision token and cd UID and caps sizes; do not bypass it.
