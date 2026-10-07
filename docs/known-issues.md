# Known Issues

This document outlines known issues with ctrld and their current status, workarounds, and recommendations.

## macOS (Darwin) Issues

### Self-Upgrade Issue on Darwin 15.5

**Issue**: ctrld self-upgrading functionality may not work on macOS Darwin 15.5.

**Status**: Under investigation

**Description**: Users on macOS Darwin 15.5 may experience issues when ctrld attempts to perform automatic self-upgrades. The upgrade process would be triggered, but ctrld won't be upgraded.

**Workarounds**:
1. **Recommended**: Upgrade your macOS system to Darwin 15.6 or later, which has been tested and verified to work correctly with ctrld self-upgrade functionality.
2. **Alternative**: Run `ctrld upgrade prod` directly to manually upgrade ctrld to the latest version on Darwin 15.5.

**Affected Versions**: ctrld v1.4.2 and later on macOS Darwin 15.5

**Last Updated**: 05/09/2025

---

## Merlin Issues

### Daemon Crashing on `Ctrl+C`

**Issue**: `ctrld` daemon terminates unexpectedly after stopping a log tailing command. This typically occurs when running the daemon and the log viewer within the same SSH session on ASUSWRT-Merlin routers.

**Description**

The issue is caused by `Signal Propagation` within a shared `Process Group (PGID)`.

Steps to reproduce:

1. You start the daemon manually: `ctrld start --cd=<uid>`.
2. You view internal logs in the same terminal: `ctrld log tail`.
3. You press `Ctrl+C` to stop viewing logs.
4. The `ctrld` daemon service stops immediately along with the log command.

When you execute commands sequentially in a single interactive SSH session on Merlin, the shell often assigns them to the same Process Group. In Linux, the `SIGINT` signal (triggered by `Ctrl+C`) is not just sent to the foreground application, but is frequently propagated to every process belonging to that specific process group.

Because the `ctrld` daemon remains "attached" to the terminal session's process group, it "hears" the interrupt signal intended for the `log tail` command and shuts down.

**Workarounds**:

To isolate the signals, avoid running the log viewer in the same window as the daemon:
* **Window A:** Start the daemon and leave it running.
* **Window B:** Open a new SSH connection to run `ctrld log tail`.
Because Window B has a different **Session ID** and **Process Group ID**, pressing `Ctrl+C` in Window B will not affect the process in Window A.

## Windows Issues

### VPN `block-outside-dns` Breaks DNS When Using ctrld in DNS Mode

**Issue**: VPN software that uses OpenVPN's `block-outside-dns` directive installs WFP (Windows Filtering Platform) block filters that prevent DNS queries from reaching ctrld's loopback listener.

**Status**: Fixed in v1.5.1

**Description**: When a VPN connects with `block-outside-dns` enabled, OpenVPN adds WFP filters that block all DNS traffic to non-tunnel interfaces — including loopback (`127.0.0.1`). Since ctrld's NRPT catch-all rule routes DNS through the Windows DNS Client to `127.0.0.1:53`, the WFP block filters prevent DNS Client from reaching ctrld, causing all DNS queries to time out.

This affects any VPN client that implements `block-outside-dns` via WFP, including:
- OpenVPN GUI (community)
- Securepoint SSL VPN
- Any OpenVPN-based client that honors the `block-outside-dns` push directive

**Fix**: ctrld now proactively adds WFP "hard permit" filters for DNS to localhost at startup. These use `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT` to override block decisions from any other WFP sublayer, ensuring the NRPT → loopback path is always available regardless of VPN state. See `docs/dns-intercept-mode.md` for technical details.

**Affected Versions**: ctrld ≤ v1.5.0 in `dns` intercept mode on Windows

**Last Updated**: 04/28/2026

---

### DNS Stalls for Up to ~100 Seconds After Start, and the Install Rolls Back

**Issue**: On Windows in `dns` intercept mode, a freshly started ctrld can leave every query unanswered for a minute or more. The start self-check fails in the meantime and rolls the install back (`SERVICE_SELFCHECK_FAILED`, exit 53). This happens with `ctrld start --config <file>` and also with `ctrld start --cd <uid>`.

**Status**: Fixed on the `v1.0` branch in `c40cc8d7`, not yet released. v1.5.7 is affected.

**Description**: The first DoH request sets up the upstream transport, and that setup calls `ctrld.HasIPv6()`. In the affected versions `HasIPv6()` also started a Tailscale `netmon` monitor inside its `sync.Once`. Building the monitor's first interface state calls `getPACWindows`, which asks WinHTTP for proxy auto-discovery (WPAD). WPAD discovery resolves names through the Windows DNS Client. NRPT already sends those lookups to ctrld, and ctrld cannot answer until the same `sync.Once` returns. So every DNS request waits behind proxy discovery, and proxy discovery waits on DNS, until WinHTTP's own timeouts expire. Then all pending queries complete at once.

It is a race between WinHTTP's proxy discovery and ctrld installing its NRPT rule:

- If discovery finishes before the rule is in place, nothing happens.
- With `--cd`, `HasIPv6()` is first called during the API fetch, only about 75 to 95 ms before the NRPT rule becomes active. That window is too short wherever discovery is slow, so `--cd` installs are affected too.
- With `--config`, nothing calls `HasIPv6()` before the rule, so the stall is near-certain.
- A network where the proxy-discovery lookups are answered quickly outside ctrld avoids it. On a domain member, for example, the AD domain's names go to the domain controller through the auto-added AD split rule.
- How long the stall lasts depends on how long WinHTTP's discovery takes on that network.

A goroutine dump from an affected build (`ecf7955e`) taken during the stall shows the DoH transport setup blocked in the syscall, with 111 DNS request goroutines parked in `sync.Once` behind it:

```
UpstreamConfig.dohTransport → ensureSetupTransport (sync.Once)
  → SetupTransport → ctrld.HasIPv6 (sync.Once)
    → netmon.New → netmon.GetState → getPACWindows   [Windows syscall]
```

While the stall lasts, ctrld opens no connection to its upstream, although the network and the upstream both answer normally. Windows' certificate service lookups (`ctldl.windowsupdate.com`, Sectigo/USERTrust OCSP and CRL hosts) also queue in ctrld, but they are a consequence of the stall, not its cause. Warming Windows' certificate state before the start does not prevent it.

**Fix**: `c40cc8d7` ("put the network state of the host in the log journal") removed the monitor from `HasIPv6()`. The process's one network monitor now reports IPv6 state through `SetIPv6Available`, and `HasIPv6()` only runs a bounded IPv6 check. On master (2.0) the same change arrived with `c5ad04ab`.

**Workarounds** (affected versions):
1. **Recommended**: Add `--skip_self_checks` so the service is not rolled back. DNS then recovers by itself once WinHTTP's proxy discovery times out, after about 100 seconds in the QA lab.
2. **Alternative**: Retry the install. Whether it stalls depends on how quickly proxy discovery finishes, so a second attempt can succeed.
3. Take a build with `c40cc8d7` once one is released.

**Reproduction** (ctrld-qa lab, workgroup endpoint on the simulated home network):

- `config-file-upstream-ready` starts ctrld from a local config and requires Control D resolution within 20 seconds.
  - It fails on every build that has the monitor in `HasIPv6()`: 10 of 10 runs, on the v1.5.7 release and tag, `ecf7955e`, and 2.0 commits before `c5ad04ab`.
  - It passes on every build without the monitor: 9 of 9 runs, on `c40cc8d7`, the `v1.0` tip `cc849871`, and master from `6dcdddc2`.
- `smoke-lifecycle` is a normal `--cd` install.
  - The v1.5.7 release failed its start self-check in 4 of 4 runs, each with the same signature: `HasIPv6()` 75 to 95 ms before the NRPT rule, then no upstream reply until the rollback.
  - The `v1.0` tip `cc849871` passed.
- On the domain-joined endpoint, `--cd` installs pass.

**Affected Versions**: ctrld ≤ v1.5.7 on Windows, `dns` intercept mode. Near-certain with `--config`; with `--cd`, it depends on how quickly WinHTTP proxy discovery finishes on the network.

**Last Updated**: 09/30/2026

---

## Contributing to Known Issues

If you encounter an issue not listed here, please:

1. Check the [GitHub Issues](https://github.com/Control-D-Inc/ctrld/issues) to see if it's already reported
2. If not reported, create a new issue with:
   - Detailed description of the problem
   - Steps to reproduce
   - Expected vs actual behavior
   - System information (OS, version, architecture)
   - ctrld version

## Issue Status Legend

- **Under investigation**: Issue is confirmed and being analyzed
- **Workaround available**: Temporary solution exists while permanent fix is developed
- **Fixed**: Issue has been resolved in a specific version
- **Won't fix**: Issue is acknowledged but will not be addressed due to technical limitations or design decisions
