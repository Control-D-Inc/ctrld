# Windows DNS Intercept — Technical Reference

## Overview

On Windows, DNS intercept mode uses a two-layer architecture:

- **`dns` mode (default)**: NRPT only — graceful DNS routing via the Windows DNS Client service
- **`hard` mode**: NRPT + WFP — full enforcement with kernel-level block filters

`dns` mode avoids ctrld's outbound block filters and therefore degrades more gracefully when owned NRPT is removed. Resolution still depends on the active NRPT target being reachable; an administrator-owned GP catch-all intentionally remains fail-closed if its loopback listener is stopped.

## Architecture: dns vs hard Mode

```
┌─────────────────────────────────────────────────────────────────┐
│              dns mode (NRPT + loopback WFP protect)             │
│                                                                 │
│  App DNS query → DNS Client service → NRPT lookup               │
│     → "." catch-all matches → forward to 127.0.0.1 (ctrld)    │
│                                                                 │
│  Loopback WFP protect: 4 hard-permit filters (port 53 to       │
│  localhost, CLEAR_ACTION_RIGHT) prevent third-party VPN WFP     │
│  blocks (e.g., OpenVPN block-outside-dns) from breaking NRPT.   │
│                                                                 │
│  Owned rule missing → restore; GP missing → owned fallback     │
│  GP rule + dead listener remains intentionally fail-closed      │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                     hard mode (NRPT + WFP)                      │
│                                                                 │
│  App DNS query → DNS Client service → NRPT → 127.0.0.1 (ctrld)│
│                                                                 │
│  Bypass attempt (raw 8.8.8.8:53) → WFP BLOCK filter            │
│  VPN DNS on private IP → WFP subnet PERMIT filter → allowed    │
│                                                                 │
│  NRPT route is established before WFP starts                    │
│  WFP failure rolls back only ctrld-owned NRPT; GP is untouched  │
└─────────────────────────────────────────────────────────────────┘
```

## NRPT (Name Resolution Policy Table)

### What It Does

NRPT is a Windows feature (originally for DirectAccess) that tells the DNS Client
service to route queries matching specific namespace patterns to specific DNS servers.
ctrld adds a catch-all rule that routes ALL DNS to `127.0.0.1`:

| Registry Value | Type | Value | Purpose |
|---|---|---|---|
| `Name` | REG_MULTI_SZ | `.` | Namespace (`.` = catch-all) |
| `GenericDNSServers` | REG_SZ | `127.0.0.1` | Target DNS server |
| `ConfigOptions` | REG_DWORD | `0x8` | Standard DNS resolution |
| `Version` | REG_DWORD | `0x2` | NRPT rule version 2 |
| `Comment` | REG_SZ | `` | Empty (matches PowerShell behavior) |
| `DisplayName` | REG_SZ | `` | Empty (matches PowerShell behavior) |
| `IPSECCARestriction` | REG_SZ | `` | Empty (matches PowerShell behavior) |

### Registry Paths — GP vs Local (Critical)

Windows NRPT has two registry paths with **all-or-nothing** precedence:

| Path | Name | Mode |
|---|---|---|
| `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig` | **GP path** | Group Policy mode |
| `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig` | **Local path** | Local/service store mode |

**Precedence rule**: If ANY rules exist in the GP path (from IT policy, VPN, MDM,
or our own earlier builds), DNS Client enters "GP mode" and **ignores ALL local-path
rules entirely**. This is not per-rule — it's a binary switch.

**Consequence**: On non-domain-joined (WORKGROUP) machines, `RefreshPolicyEx` is
unreliable. If we write to the GP path, DNS Client enters GP mode but the rules
never activate — resulting in `Get-DnsClientNrptPolicy` returning empty even though
`Get-DnsClientNrptRule` shows the rule in registry.

ctrld uses an adaptive strategy (matching [Tailscale's approach](https://github.com/tailscale/tailscale/blob/main/net/dns/nrpt_windows.go)) when it owns NRPT:

1. **Always write to the local path** using a deterministic GUID key name
   (`{B2E9A3C1-7F4D-4A8E-9D6B-5C1E0F3A2B8D}`). This is the baseline that works
   on all non-domain machines.
2. **Check if other software has GP NRPT rules** (`otherGPRulesExist()`). If
   foreign GP rules are present (IT policy, VPN), DNS Client is already in GP mode
   and our local rule would be invisible — so we also write to the GP path.
3. **If no foreign GP rules exist**, clean any stale ctrld GP rules and delete
   the empty GP parent key. This ensures DNS Client stays in "local mode" where
   the local-path rule activates immediately via `paramchange`.

### Adopting an Organization-Owned GP Catch-All

Before applying that ctrld-owned strategy, service startup looks for a non-ctrld GP child with exactly `Name=["."]` and one `GenericDNSServers` value equal to the actual listener IP. The registry match is only an ownership candidate: ctrld sends its unique DNS Client probe before any NRPT write and re-reads the same child afterward.

Intercept state stays unpublished while that happens. Startup publishes nothing until it has fully succeeded, which is why the probe and heal flows take the state as an argument instead of reading the published field — publishing early would expose a half-built `wfpState`, with no engine handle and filter IDs still being assigned, to callers such as the VPN DNS exemption path. The one deliberate exception is hard mode when WFP setup fails while GP-managed NRPT is verified routing: that state is published so the health monitor can keep retrying WFP, and the service start is still reported as failed.

When the rule remains unchanged and the probe arrives, Group Policy owns NRPT:

- the startup adapter reset is skipped;
- no ctrld NRPT key is created;
- `RefreshPolicyEx`, Dnscache `paramchange`, and cache flush are not used for that policy;
- shutdown/uninstall leave the GP child untouched.

A matching GP child that remains present but fails its probe is reported as ineffective and is not rewritten. If the child disappears, ctrld activates its normal owned fallback. A GP catch-all that instead changes to another resolver is reported as a conflict; ctrld does not create a second ambiguous catch-all. If the matching rule later returns, ctrld probes first, removes only its deterministic fallback keys, signals the ownership transition once, and resumes observing Group Policy.

**Deployment ordering:** apply the GPO before starting ctrld to guarantee adapter DNS is never reset. Remove/unlink it before intentionally stopping or uninstalling ctrld. A GP catch-all still targeting loopback with no listener running is a deliberate fail-closed state and will break DNS.

### Reproducing the Empty GP Parent Case

This is a production code reference, so the temporary repro script is not kept in
the repository. For MR !942 review, the test script and exact before/after steps
are posted in the MR discussion. The scenario to compare is:

1. Run the same approved PowerShell repro script against a pre-fix build and this
   branch with the same ctrld config.
2. Create an empty GP NRPT parent key while ctrld is running in DNS intercept mode.
3. Confirm pre-fix logs can spend policy refresh/paramchange retries while the GP
   parent remains empty.
4. Confirm post-fix logs clean the empty GP parent, send one NRPT-change signal,
   and re-probe before normal retries.

### VPN Coexistence

NRPT uses most-specific-match. VPN NRPT rules for specific domains (e.g.,
`*.corp.local` → `10.20.30.1`) take priority over ctrld's `.` catch-all.
This means VPN split DNS works naturally — VPN-specific domains go to VPN DNS,
everything else goes to ctrld. No exemptions or special handling needed.

### DNS Client Notification

After writing NRPT rules, DNS Client must be notified to reload:

1. **`paramchange`**: `sc control dnscache paramchange` — signals DNS Client to
   re-read configuration. Works for local-path rules on most machines.
2. **`RefreshPolicyEx`**: `RefreshPolicyEx(bMachine=TRUE, dwOptions=RP_FORCE)` from
   `userenv.dll` — triggers GP refresh for GP-path rules. Unreliable on non-domain
   machines (WORKGROUP). Fallback: `gpupdate /target:computer /force`.
3. **DNS cache flush**: `DnsFlushResolverCache` from `dnsapi.dll` or `ipconfig /flushdns`
   — clears stale cached results from before NRPT was active.

### DNS Cache Flush

After NRPT changes, stale DNS cache entries could bypass the new routing. ctrld flushes:

1. **Primary**: `DnsFlushResolverCache` from `dnsapi.dll`
2. **Fallback**: `ipconfig /flushdns` (subprocess)

### Known Limitation: nslookup

`nslookup.exe` implements its own DNS resolver and does NOT use the Windows DNS Client
service. It ignores NRPT entirely. Use `Resolve-DnsName` (PowerShell) or `ping` to
verify DNS resolution through NRPT. This is a well-known Windows behavior.

## WFP (Windows Filtering Platform) — hard Mode Only

### Filter Stack

```
┌─────────────────────────────────────────────────────────────────┐
│  Sublayer: "ctrld DNS Intercept" (weight 0xFFFF — max priority) │
│                                                                 │
│  ┌─ Permit Filters (weight 10) ─────────────────────────────┐   │
│  │  • IPv4/UDP to 127.0.0.1:53     → PERMIT                │   │
│  │  • IPv4/TCP to 127.0.0.1:53     → PERMIT                │   │
│  │  • IPv6/UDP to ::1:53           → PERMIT                │   │
│  │  • IPv6/TCP to ::1:53           → PERMIT                │   │
│  │  • RFC1918 + CGNAT subnets:53   → PERMIT (VPN DNS)      │   │
│  │  • VPN DNS exemptions (dynamic) → PERMIT                │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌─ Block Filters (weight 1) ───────────────────────────────┐   │
│  │  • All IPv4/UDP to *:53         → BLOCK                  │   │
│  │  • All IPv4/TCP to *:53         → BLOCK                  │   │
│  │  • All IPv6/UDP to *:53         → BLOCK                  │   │
│  │  • All IPv6/TCP to *:53         → BLOCK                  │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                 │
│  Filter evaluation: higher weight wins → permits checked first  │
└─────────────────────────────────────────────────────────────────┘
```

### Why WFP Can't Work Alone

WFP operates at the connection authorization layer (`FWPM_LAYER_ALE_AUTH_CONNECT`).
It can only **block** or **permit** connections — it **cannot redirect** them.
Redirection requires kernel-mode callout drivers (`FwpsCalloutRegister` in
`fwpkclnt.lib`) using `FWPM_LAYER_ALE_CONNECT_REDIRECT_V4/V6`, which are not
accessible from userspace.

Without NRPT, WFP blocks outbound DNS but doesn't tell applications where to send
queries instead — they just see DNS failures. This is why `hard` mode requires NRPT
to be active first, and why WFP is rolled back if NRPT setup fails.

### Sublayer Priority

Weight `0xFFFF` (maximum) ensures ctrld's filters take priority over any other WFP
sublayers from VPN software, endpoint security, or Windows Defender Firewall.

### RFC1918 + CGNAT Subnet Permits

Static permit filters for private IP ranges (10.0.0.0/8, 172.16.0.0/12,
192.168.0.0/16, 100.64.0.0/10) allow VPN DNS servers on private IPs to work
without dynamic per-server exemptions. This covers Tailscale MagicDNS
(100.100.100.100), corporate VPN DNS (10.x.x.x), and similar.

### VPN DNS Exemption Updates

When `vpnDNSManager.Refresh()` discovers VPN DNS servers on public IPs:

1. Delete all existing VPN permit filters (by stored IDs)
2. For each VPN DNS server IP:
   - IPv4: `addWFPPermitIPFilter()` on `ALE_AUTH_CONNECT_V4`
   - IPv6: `addWFPPermitIPv6Filter()` on `ALE_AUTH_CONNECT_V6`
   - Both UDP and TCP for each IP
3. Store new filter IDs for next cleanup cycle

**In `dns` mode, VPN DNS exemptions are skipped** — there are no ctrld WFP block
filters to exempt from. The loopback WFP protect filters only permit localhost
DNS; VPN DNS traffic goes through the tunnel interface and is already permitted
by the VPN's own WFP rules.

### Session Lifecycle

**Startup (hard mode):**
```
1. Adopt a proven matching GP catch-all, or install ctrld-owned NRPT
2. FwpmEngineOpen0() with RPC_C_AUTHN_DEFAULT (0xFFFFFFFF)
3. Delete stale sublayer (crash recovery)
4. FwpmSubLayerAdd0() — weight 0xFFFF
5. Add 4 localhost permit filters
6. Add 4 block filters
7. Add RFC1918 + CGNAT subnet permits
8. Start ownership-aware NRPT/WFP health monitor
```

**Startup (dns mode):**
```
1. Adopt a proven matching GP catch-all, or install ctrld-owned NRPT
2. Activate loopback WFP protect (4 hard-permit filters for localhost DNS)
3. Start ownership-aware NRPT health monitor
```

**Shutdown:**
```
1. Stop NRPT health monitor
2. Remove + signal only ctrld-owned NRPT; leave GP-managed policy untouched
3. Clean up ctrld WFP filters, sublayer, and engine session
```

**Crash Recovery:**
On startup, `cleanupStaleDNSInterceptState()` calls `FwpmSubLayerDeleteByKey0` to
remove any stale sublayer from a previous unclean shutdown (the deterministic GUID
ensures we only ever target our own). It opens a **non-dynamic** session, because a
dynamic one cannot delete objects that were not added in a dynamic session — which is
what a build predating session-scoped ownership leaves behind.

Whether deleting the sublayer also removes the filters inside it is **not documented**
either way, and is unresolved (see the note on `cleanupStaleDNSInterceptState`). If it
does not, the call returns `FWP_E_IN_USE` and the orphaned filters need deleting first;
that case is logged as a warning rather than reported as a successful cleanup, so it is
visible in a support log instead of silently leaving enforcement active.

Since every current build uses a dynamic session, the OS removes ctrld's filters when
the process dies, so this recovery path only matters for state left by an older build.

## NRPT Probe and Auto-Heal

### The Problem: Async GP Refresh Race

`RefreshPolicyEx` triggers a Group Policy refresh but returns immediately — it does
NOT wait for the DNS Client service to actually reload NRPT from the registry. On
cold machines (first boot, fresh install, long sleep), the DNS Client may take
several seconds to process the policy refresh. During this window, NRPT rules exist
in the registry but the DNS Client hasn't loaded them — queries bypass ctrld.

### The Solution: Active Probing

After writing NRPT to the registry, ctrld sends a probe DNS query through the
Windows DNS Client path to verify NRPT is actually working:

1. Generate a unique probe domain: `_nrpt-probe-<hex>.nrpt-probe.ctrld.test`
2. Send it via Go's `net.Resolver` (calls `GetAddrInfoW` → DNS Client → NRPT)
3. If NRPT is active, DNS Client routes it to 127.0.0.1 → ctrld receives it
4. ctrld's DNS handler recognizes the probe prefix and signals success
5. If the probe times out (2s), NRPT isn't loaded yet → retry with remediation

### Startup Probes

For a matching GP candidate, startup blocks for one 2-second probe before any NRPT mutation and then re-reads the same child. A received query plus the unchanged rule proves both routing and external ownership. If that first probe fails, ctrld installs its normal WFP protection and performs one more ownership-safe probe before advertising startup readiness.

ctrld-owned NRPT retains the asynchronous sequence:

```
Immediate probe
  ├─ Success → "NRPT verified working", done
  └─ Timeout
       ├─ Empty GP parent → clean once, signal once, re-probe
       └─ Otherwise → bounded 1s/2s/4s signal + probe retries
            └─ Still failing → two-phase remove/signal/re-add/final probe
```

### GP-Managed Probe Failure

A matching GP child still owns Windows' effective NRPT store even when its probe fails. Writing a local rule cannot override that precedence, and rewriting the GP child would violate administrator ownership. ctrld therefore retries only its loopback WFP permit protection, reports the ineffective external policy, and leaves NRPT registry values and policy signals untouched.

### Health Monitor Integration

The 30s periodic health monitor now does actual probing, not just registry checks:

```
Every 30s:
    ├─ GP-managed owner
    │   ├─ Matching child + probe success → observe only
    │   ├─ Matching child + probe failure → WFP-only retry; no NRPT mutation
    │   └─ Matching child gone → activate ctrld-owned fallback + verify
    │
    ├─ ctrld-owned owner
    │   ├─ Working matching GP child returns → remove only ctrld keys; adopt GP
    │   ├─ ctrld key missing → restore + signal + verify
    │   └─ ctrld key present → probe; run owned heal sequence on failure
    │
    └─ (hard mode) Check WFP sublayer; full intercept restart if missing
```

**Singleton guard:** Only one asynchronous probe-and-heal sequence runs at a time (atomic bool). Startup's GP-candidate probe completes before the health monitor starts; direct periodic probes finish before they schedule a heal sequence.

**Why periodic, not just network-event?** VPN software or Group Policy updates can
clear NRPT at any time, not just during network changes. A 30s periodic check ensures
recovery within a bounded window.

**Hard mode safety:** The health monitor verifies NRPT before checking WFP. If NRPT
is gone, it's restored first. WFP is never running without NRPT — this prevents
DNS blackholes where WFP blocks everything but NRPT isn't routing to ctrld.

## DNS Flow Diagrams

### Normal Resolution (both modes)

```
App → DNS Client → NRPT lookup → "." matches → 127.0.0.1 → ctrld
    → Control D DoH (port 443, not affected by WFP port-53 rules)
    → response flows back
```

### VPN Split DNS (both modes)

```
App → DNS Client → NRPT lookup:
    VPN domain (*.corp.local) → VPN's NRPT rule wins → VPN DNS server
    Everything else → ctrld's "." catch-all → 127.0.0.1 → ctrld
        → VPN domain match → forward to VPN DNS (port 53)
        → (hard mode: WFP subnet permit allows private IP DNS)
```

### Bypass Attempt (hard mode only)

```
App → raw socket to 8.8.8.8:53 → WFP ALE_AUTH_CONNECT → BLOCK
```

In `dns` mode, this query would succeed (no WFP) — the tradeoff for never
breaking DNS.

## Key Differences from macOS (pf)

| Aspect | macOS (pf) | Windows dns mode | Windows hard mode |
|--------|-----------|------------------|-------------------|
| **Routing** | `rdr` redirect | NRPT policy | NRPT policy |
| **Enforcement** | `route-to` + block rules | Loopback WFP protect | WFP block filters |
| **Can break DNS?** | Yes (pf corruption) | No | Yes (if NRPT lost) |
| **VPN coexistence** | Watchdog + stabilization | NRPT + loopback hard-permit | Same + WFP permits |
| **Bypass protection** | pf catches all packets | None | WFP catches all connections |
| **Recovery** | Probe + auto-heal | Health monitor re-adds | Full restart on sublayer loss |

## WFP API Notes

### Struct Layouts

WFP C API structures are manually defined in Go (`golang.org/x/sys/windows` doesn't
include WFP types). Field alignment must match the C ABI exactly — any mismatch
causes access violations or silent corruption.

### FWP_DATA_TYPE Enum

```
FWP_EMPTY    = 0
FWP_UINT8    = 1
FWP_UINT16   = 2
FWP_UINT32   = 3
FWP_UINT64   = 4
...
```

**⚠️** Some documentation examples incorrectly start at 1. The enum starts at 0
(`FWP_EMPTY`), making all subsequent values offset by 1 from what you might expect.

### GC Safety

When passing Go heap objects to WFP syscalls via `unsafe.Pointer`, use
`runtime.KeepAlive()` to prevent garbage collection during the call:

```go
conditions := make([]fwpmFilterCondition0, 3)
filter.filterCondition = &conditions[0]
r1, _, _ := procFwpmFilterAdd0.Call(...)
runtime.KeepAlive(conditions)
```

### Authentication

`FwpmEngineOpen0` requires `RPC_C_AUTHN_DEFAULT` (0xFFFFFFFF) for the authentication
service parameter. `RPC_C_AUTHN_NONE` (0) returns `ERROR_NOT_SUPPORTED` on some
configurations (e.g., Parallels VMs).

### Elevation

WFP requires admin/SYSTEM privileges. `FwpmEngineOpen0` fails with HRESULT 0x32
when run non-elevated. Services running as SYSTEM have this automatically.

## Debugging

### Check NRPT Rules

```powershell
# PowerShell — show active NRPT rules
Get-DnsClientNrptRule

# Check registry directly
Get-ChildItem "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig"
```

### Check WFP Filters (hard mode)

```powershell
# Show all WFP filters (requires admin) — output is XML
netsh wfp show filters

# Search for ctrld's filters
Select-String "ctrld" filters.xml
```

### Verify DNS Resolution

```powershell
# Use Resolve-DnsName, NOT nslookup (nslookup bypasses NRPT)
Resolve-DnsName example.com
ping example.com

# If you must use nslookup, specify localhost:
nslookup example.com 127.0.0.1

# Force GP refresh (if NRPT not loading)
gpupdate /target:computer /force

# Verify service registration
sc qc ctrld
```

### Service Verification

After install, verify the Windows service is correctly registered:

```powershell
# Check binary path and start type
sc qc ctrld

# Should show:
#   BINARY_PATH_NAME: "C:\...\ctrld.exe" run --cd xxxxx --intercept-mode dns
#   START_TYPE: AUTO_START
```

## Related

- [DNS Intercept Mode Overview](dns-intercept-mode.md) — cross-platform documentation
- [pf DNS Intercept](pf-dns-intercept.md) — macOS technical reference
- [Microsoft WFP Documentation](https://docs.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page)
- [Microsoft NRPT Documentation](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn593632(v=ws.11))
