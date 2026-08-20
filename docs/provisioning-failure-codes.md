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
- **Exit code** — stage-scoped: bootstrap 30–39, listener 40–49,
  service 50–59. Unrelated existing contracts are unchanged
  (`ctrld status` exits 0–3; invalid deactivation pin exits 126).

A customer or administrator only needs to report the code (or the whole
output line). The table below is the maintained support mapping; it must
stay in sync with `cmd/cli/provision_result.go` and changes in the same MR.

## Codes

| Code | Stage | Exit | Failure scenario | Next action / evidence |
|---|---|---|---|---|
| `API_UNREACHABLE` | bootstrap | 30 | The Control D API could not be reached or answered with a retryable error (network failure, proxy interference, 5xx, timeout) and retries ran out. The service manager may retry the service later. | Check the device's network path to `api.controld.com` (DNS, proxy, firewall, captive portal). Ask for the result file's `message` and whether other TLS traffic works. |
| `API_REJECTED` | bootstrap | 31 | The API answered and permanently rejected the configuration (4xx other than 408/429): bad or revoked token, malformed request. ctrld exits without burning service-manager restarts because retrying cannot change the answer. | Verify the provision token / org configuration in the Control D dashboard. Re-push after fixing credentials. Evidence: HTTP status in the result file `message`. |
| `API_DEVICE_INVALID` | bootstrap | 32 | The API reports the device/resolver no longer exists (error code 40402). ctrld self-uninstalls its service because the identity is gone server-side. | Confirm the device was deleted or re-provisioned in the dashboard; re-provision with a current token. No local evidence needed beyond the code. |
| `LISTENER_BIND_FAILED` | listener | 41 | No listen address could be bound after all fallbacks (configured address, 0.0.0.0:53, localhost:53, port 5354, random) were exhausted. `detail.attempts` records each tried address with the UDP/TCP OS error, e.g. `address already in use` (another DNS service owns the port) or `can't assign requested address` (address not on any interface). | Read `detail.attempts`: `address already in use` → find the process owning the port (`sudo lsof -i :53 -nP`); `can't assign requested address` → the configured IP is not present on the device. Then fix the conflict or the listener config. |
| `LISTENER_CONFIGURED_ADDR_UNAVAILABLE` | listener | 42 | An explicitly configured listener address could not be bound and configuration checks forbid falling back to another address, or (macOS intercept mode) the required explicit address is unavailable. | The configured `ip:port` in the listener config is wrong for this device or occupied. Verify the address exists on an interface and nothing else binds it; correct the config rather than expecting fallback. |
| `SERVICE_INSTALL_FAILED` | service | 51 | The OS service manager refused to install the service (launchd/systemd/SCM registration failed). | Check OS-level constraints: permissions/elevation, MDM policy blocking daemon installation, corrupted previous install. Evidence: result file `message` (service manager error), plus `launchctl print system/ctrld` / `systemctl status ctrld` / SCM state. |
| `SERVICE_START_FAILED` | service | 52 | The service installed but the service manager could not start it. | Check the service manager's own log for the start error, then the ctrld home dir `ctrld.log`. Often permissions or a binary quarantined by security tooling. |
| `SERVICE_SELFCHECK_FAILED` | service | 53 | The service started but never became healthy: no fresher failure was reported by the daemon, and the post-install DNS self-check failed. The just-installed service is rolled back (uninstalled). If the daemon itself recorded a more specific failure (e.g. a listener code), that code is reported instead of this one. | Ask for the drained service log printed by `ctrld start` and the result file. If the service was running but unreachable, check host firewall rules intercepting DNS to the listener. |

## Reading the result file

macOS and Linux (default service home is `/etc/controld`):

```sh
sudo cat /etc/controld/provision_result.json
```

On Windows the file sits next to `ctrld.exe` in the install directory. A
custom `homedir` config moves it accordingly; routers and mobile use their
platform home directory.

The file sits in the same directory as the persisted internal log
(`ctrld.log`) for the user the service runs as. On a healthy install the
file is absent.

## Rules for maintainers

- Codes are append-only once released. Never rename, renumber, or reuse a
  code or exit number; add a new one and note the deprecation here.
- Every code added in `cmd/cli/provision_result.go` needs a row here in the
  same MR. Tests enforce the code/stage/exit maps and that this table has
  exactly one row per code.
- Detail must stay bounded and free of secrets: the constructor strips the
  provision token and cd UID and caps sizes; do not bypass it.
