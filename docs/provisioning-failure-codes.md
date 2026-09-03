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
  listener 40–49, service 50–59. Unrelated existing contracts are
  unchanged (`ctrld-client status` exits 0–3; invalid deactivation pin exits 126).

A customer or administrator only needs to report the code (or the whole
output line). The table below is the maintained support mapping; it must
stay in sync with `cmd/cli/provision_result.go` and changes in the same MR.

## Codes

| Code | Stage | Exit | Failure scenario | Next action / evidence |
|---|---|---|---|---|
| `PROVISION_TOKEN_MALFORMED` | input | 21 | The `--cd-org` value is clearly not a provisioning code: explicitly empty, too short, too long, or containing whitespace or control characters. Checked before any network call. A missing `org-v1-` prefix is not this code — that only logs a warning, since legacy codes may lack it. | Check the provisioning code was copied in full, with no extra whitespace. The result file never echoes the value. |
| `CUSTOM_HOSTNAME_INVALID` | input | 22 | The `--custom-hostname` value fails ctrld's own hostname rule (`validHostname`): not 3–64 characters, or not RFC1123 hostname format. Checked before any network call. The API itself does not reject a bad hostname during provisioning — ControlD folds/strips characters like space, `+`, and `.` when it registers the device name, so a value ctrld accepts may still register under an adjusted name (logged as a notice, not a failure). | Fix `--custom-hostname` per the message: it names the offending character(s) and the allowed format. |
| `INTERCEPT_MODE_INVALID` | input | 23 | The `--intercept-mode` value is not one of `off`, `dns`, or `hard`. Checked before installing the service. | Re-run with a valid `--intercept-mode` value. |
| `INVALID_FLAG_COMBINATION` | input | 24 | `--cd`/`--cd-org` used together with `--nextdns`, or `--proto` set to anything other than `doh`/`doh3` once `--cd` is in play. Checked before any network call or service install. | Re-run without the conflicting flag, or fix the invalid value. The message names the exact flags involved. |
| `API_UNREACHABLE` | bootstrap | 30 | The Control D API could not be reached or answered with a retryable error (network failure, proxy interference, 5xx, timeout) and retries ran out. The service manager may retry the service later. | Check the device's network path to `api.controld.com` (DNS, proxy, firewall, captive portal). Ask for the result file's `message` and whether other TLS traffic works. |
| `API_REJECTED` | bootstrap | 31 | The API answered and permanently rejected the configuration (4xx other than 408/429): bad or revoked token, malformed request. ctrld exits without burning service-manager restarts because retrying cannot change the answer. | Verify the provision token / org configuration in the Control D dashboard. Re-push after fixing credentials. Evidence: HTTP status in the result file `message`. |
| `API_DEVICE_INVALID` | bootstrap | 32 | The API reports the device/resolver no longer exists (error code 40402). When the daemon's own bootstrap preflight discovers this, it self-uninstalls because the identity is gone server-side. The direct `--cd <uid>` install path (`ctrld-client start --cd`) can also hit this code, before the service exists; there is nothing to uninstall yet on that path. | Confirm the device was deleted or re-provisioned in the dashboard; re-provision with a current token. No local evidence needed beyond the code. |
| `TOKEN_INVALID` | bootstrap | 33 | The API rejected the `--cd-org` provisioning code with reason `token_invalid`: the code is not recognized. | Check the code and re-enter it exactly as given. |
| `TOKEN_EXPIRED` | bootstrap | 34 | The API rejected the `--cd-org` provisioning code with reason `token_expired`. | Get a new provisioning code from your administrator. |
| `TOKEN_LIMIT_REACHED` | bootstrap | 35 | The API rejected the `--cd-org` provisioning code with reason `token_limit_reached`: it has reached its device limit. | Free up a device slot or use a different provisioning code. |
| `TOKEN_DISABLED` | bootstrap | 36 | The API rejected the `--cd-org` provisioning code with reason `token_disabled`: the code was invalidated. | Download a profile from an active provisioning code. |
| `LISTENER_BIND_FAILED` | listener | 41 | No listen address could be bound after all fallbacks (configured address, 0.0.0.0:53, localhost:53, random) were exhausted. `detail.attempts` records each tried address with the UDP/TCP OS error, e.g. `address already in use` (another DNS service owns the port) or `can't assign requested address` (address not on any interface). | Read `detail.attempts`: `address already in use` → find the process owning the port (`sudo lsof -i :53 -nP`); `can't assign requested address` → the configured IP is not present on the device. Then fix the conflict or the listener config. |
| `LISTENER_CONFIGURED_ADDR_UNAVAILABLE` | listener | 42 | An explicitly configured listener address could not be bound and configuration checks forbid falling back to another address, or (macOS intercept mode) the required explicit address is unavailable. | The configured `ip:port` in the listener config is wrong for this device or occupied. Verify the address exists on an interface and nothing else binds it; correct the config rather than expecting fallback. |
| `SERVICE_INSTALL_FAILED` | service | 51 | The OS service manager refused to install the service (launchd/systemd/SCM registration failed). | Check OS-level constraints: permissions/elevation, MDM policy blocking daemon installation, corrupted previous install. Evidence: result file `message` (service manager error), plus `launchctl print system/ctrld-client` / `systemctl status ctrld-client` / SCM state. |
| `SERVICE_START_FAILED` | service | 52 | The service installed but the service manager could not start it. | Check the service manager's own log for the start error, then the ctrld home dir `ctrld.log`. Often permissions or a binary quarantined by security tooling. |
| `SERVICE_SELFCHECK_FAILED` | service | 53 | The service started but never became healthy: no fresher failure was reported by the daemon, and the post-install DNS self-check failed. On a fresh install or an upgrade, the just-installed service is rolled back (uninstalled). A restart of an already installed service keeps that service installed. If the daemon itself recorded a more specific failure (e.g. a listener code), that code is reported instead of this one. | Ask for the drained service log printed by `ctrld-client start` and the result file. If the service was running but unreachable, check host firewall rules intercepting DNS to the listener. |
| `UNCLASSIFIED` | service | 59 | A terminal failure on the provisioning boundary that predates a dedicated code: a config unmarshal, a file-system or environment failure (writing the config file, reading `socketDir`, respawning as a daemon), a service-argument update failing mid-upgrade, or a DNS-intercept failure the interface-DNS fallback cannot safely take over from. Every one of these used to be a bare crash with nothing to read; now they all persist a result file. | Read the result file `message`: it names the specific operation that failed and the underlying OS error. Treat this the same as any other stage-scoped failure when reporting it. |

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
support needs for a provisioning ticket in one copy-paste-safe command:
client version, MDM-managed preferences (macOS only, token reported as
present/absent only, an empty value counts as absent), the last
provisioning result, service state, and whether the Control D API is
reachable. It needs no config and always exits 0. A failure it finds is
part of the report, not a command failure. It also runs without root, but
then the last-provisioning-result and the service-state sections report
permission denied. Never asks for or prints the provisioning
token itself.

## Rules for maintainers

- Codes are append-only once released. Never rename, renumber, or reuse a
  code or exit number; add a new one and note the deprecation here.
- Every code added in `cmd/cli/provision_result.go` needs a row here in the
  same MR. Tests enforce the code/stage/exit maps and that this table has
  exactly one row per code.
- Detail must stay bounded and free of secrets: the constructor strips the
  provision token and cd UID and caps sizes; do not bypass it.
