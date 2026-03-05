# DNS Intercept Mode

## Overview

DNS intercept mode is an alternative approach to DNS management that uses OS-level packet interception instead of modifying network interface DNS settings. This eliminates race conditions with VPN software, endpoint security tools, and other programs that also manage DNS.

## The Problem

By default, ctrld sets DNS to `127.0.0.1` on network interfaces so all queries go through ctrld's local listener. However, VPN software (F5 BIG-IP, Cisco AnyConnect, Palo Alto GlobalProtect, etc.) also overwrites interface DNS settings, creating conflicts:

1. **DNS Setting War**: ctrld sets DNS to `127.0.0.1`, VPN overwrites to its DNS servers, ctrld's watchdog detects the change and restores `127.0.0.1`, VPN overwrites again — infinitely.

2. **Bypass Window**: During the watchdog polling interval (up to 20 seconds), DNS queries may go to the VPN's DNS servers, bypassing ctrld's filtering profiles (malware blocking, content filtering, etc.).

3. **Resolution Failures**: During the brief moments when DNS is being rewritten, queries may fail entirely, causing intermittent connectivity loss.

## The Solution

DNS intercept mode works at a lower level than interface settings:

- **Windows**: Uses NRPT (Name Resolution Policy Table) to route all DNS queries to `127.0.0.1` (ctrld's listener) via the Windows DNS Client service. In `hard` mode, additionally uses WFP (Windows Filtering Platform) to block all outbound DNS (port 53) except to localhost and private ranges, preventing any bypass. VPN software can set interface DNS freely — NRPT's most-specific-match ensures VPN-specific domains still resolve correctly while ctrld handles everything else.

- **macOS**: Uses pf (packet filter) to redirect all outbound DNS (port 53) traffic to ctrld's listener at `127.0.0.1:53`. Any DNS query, regardless of which DNS server the OS thinks it's using, gets transparently redirected to ctrld.

## Usage

```bash
# Start ctrld with DNS intercept mode (auto-detects VPN search domains)
ctrld start --intercept-mode dns --cd <resolver-uid>

# Hard intercept: all DNS through ctrld, no VPN split routing
ctrld start --intercept-mode hard --cd <resolver-uid>

# Or with a config file
ctrld start --intercept-mode dns -c /path/to/ctrld.toml

# Run in foreground (debug)
ctrld run --intercept-mode dns --cd <resolver-uid>
ctrld run --intercept-mode hard --cd <resolver-uid>
```

### Intercept Modes

| Flag | DNS Interception | VPN Split Routing | Captive Portal Recovery |
|------|-----------------|-------------------|------------------------|
| `--intercept-mode dns` | ✅ WFP/pf | ✅ Auto-detect & forward | ✅ Active |
| `--intercept-mode hard` | ✅ WFP/pf | ❌ All through ctrld | ✅ Active |

**`--intercept-mode dns`** (recommended): Intercepts all DNS via WFP/pf, but automatically discovers search domains from VPN and virtual network adapters (Tailscale, F5, Cisco AnyConnect, etc.) and forwards matching queries to the DNS server on that interface. This allows VPN internal resources (e.g., `*.corp.local`) to resolve correctly while ctrld handles everything else.

**`--intercept-mode hard`**: Same OS-level interception, but does NOT forward any queries to VPN DNS servers. Every DNS query goes through ctrld's configured upstreams. Use this when you want total DNS control and don't need VPN internal domain resolution. Captive portal recovery still works — network authentication pages are handled automatically.

## How It Works

### Windows (NRPT + WFP)

Windows DNS intercept uses a two-tier architecture with mode-dependent enforcement:

- **`dns` mode**: NRPT only — graceful DNS routing through the Windows DNS Client service. At worst, a VPN overwrites NRPT and queries bypass ctrld temporarily. DNS never breaks.
- **`hard` mode**: NRPT + WFP — same NRPT routing, plus WFP kernel-level block filters that prevent any outbound DNS bypass. Equivalent enforcement to macOS pf.

#### Why This Design?

WFP can only **block** or **permit** connections — it **cannot redirect** them (redirection requires kernel-mode callout drivers). Without NRPT, WFP blocks outbound DNS but doesn't tell applications where to send queries instead — they see DNS failures. NRPT provides the "positive routing" while WFP provides enforcement.

Separating them into modes means most users get `dns` mode (safe, can never break DNS) while high-security deployments use `hard` mode (full enforcement, same guarantees as macOS pf).

#### Startup Sequence (dns mode)

1. Creates NRPT catch-all registry rule (`.` → `127.0.0.1`) under `HKLM\...\DnsPolicyConfig\CtrldCatchAll`
2. Triggers Group Policy refresh via `RefreshPolicyEx` (userenv.dll) so DNS Client loads NRPT immediately
3. Flushes DNS cache to clear stale entries
4. Starts NRPT health monitor (30s periodic check)
5. Launches async NRPT probe-and-heal to verify NRPT is actually routing queries

#### Startup Sequence (hard mode)

1. Creates NRPT catch-all rule + GP refresh + DNS flush (same as dns mode)
2. Opens WFP engine with `RPC_C_AUTHN_DEFAULT` (0xFFFFFFFF)
3. Cleans up any stale sublayer from a previous unclean shutdown
4. Creates sublayer with maximum weight (0xFFFF)
5. Adds **permit** filters (weight 10) for DNS to localhost (`127.0.0.1`/`::1` port 53)
6. Adds **permit** filters (weight 10) for DNS to RFC1918 + CGNAT subnets (10/8, 172.16/12, 192.168/16, 100.64/10)
7. Adds **block** filters (weight 1) for all other outbound DNS (port 53 UDP+TCP)
8. Starts NRPT health monitor (also verifies WFP sublayer in hard mode)
9. Launches async NRPT probe-and-heal

**Atomic guarantee:** NRPT must succeed before WFP starts. If NRPT fails, WFP is not attempted. If WFP fails, NRPT is rolled back. This prevents DNS blackholes where WFP blocks everything but nothing routes to ctrld.

On shutdown: stops health monitor, removes NRPT rule, flushes DNS, then (hard mode only) removes all WFP filters and closes engine.

#### NRPT Details

The **Name Resolution Policy Table** is a Windows feature (originally for DirectAccess) that tells the DNS Client service to route queries matching specific namespace patterns to specific DNS servers. ctrld adds a catch-all rule:

| Registry Value | Type | Value | Purpose |
|---|---|---|---|
| `Name` | REG_MULTI_SZ | `.` | Namespace pattern (`.` = catch-all, matches everything) |
| `GenericDNSServers` | REG_SZ | `127.0.0.1` | DNS server to use for matching queries |
| `ConfigOptions` | REG_DWORD | `0x8` | Standard DNS resolution (no DirectAccess) |
| `Version` | REG_DWORD | `0x2` | NRPT rule version 2 |

**Registry path**: `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig\CtrldCatchAll`

**Group Policy refresh**: The DNS Client service only reads NRPT from registry during Group Policy processing cycles (default: every 90 minutes). ctrld calls `RefreshPolicyEx(bMachine=TRUE, dwOptions=RP_FORCE)` from `userenv.dll` to trigger an immediate refresh. Falls back to `gpupdate /target:computer /force` if the DLL call fails.

#### WFP Filter Architecture

**Filter priority**: Permit filters have weight 10, block filters have weight 1. WFP evaluates higher-weight filters first, so localhost and private-range DNS is always permitted.

**RFC1918 + CGNAT permits**: Static subnet permit filters allow DNS to private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10). This means VPN DNS servers on private IPs (Tailscale MagicDNS on 100.100.100.100, corporate VPN DNS on 10.x.x.x, etc.) work without needing dynamic per-server exemptions.

**VPN coexistence**: VPN software can set DNS to whatever it wants on the interface — for public IPs, the WFP block filter prevents those servers from being reached on port 53. For private IPs, the subnet permits allow it. ctrld handles all DNS routing through NRPT and can forward VPN-specific domains to VPN DNS servers through its own upstream mechanism.

#### NRPT Probe and Auto-Heal

`RefreshPolicyEx` returns immediately — it does NOT wait for the DNS Client service to actually load the NRPT rule. On cold machines (first boot, fresh install), the DNS Client may take several seconds to process the policy refresh. During this window, the NRPT rule exists in the registry but isn't active.

ctrld verifies NRPT is actually working by sending a probe DNS query (`_nrpt-probe-<hex>.nrpt-probe.ctrld.test`) through Go's `net.Resolver` (which calls `GetAddrInfoW` → DNS Client → NRPT path). If ctrld receives the probe on its listener, NRPT is active.

**Startup probe (async, non-blocking):** After NRPT setup, an async goroutine probes with escalating remediation: (1) immediate probe, (2) GP refresh + retry, (3) DNS Client service restart + retry, (4) final retry. Only one probe sequence runs at a time.

**DNS Client restart (nuclear option):** If GP refresh alone isn't enough, ctrld restarts the `Dnscache` service to force full NRPT re-initialization. This briefly interrupts all DNS (~100ms) but only fires when NRPT is already not working.

#### NRPT Health Monitor

A dedicated background goroutine (`nrptHealthMonitor`) runs every 30 seconds and now performs active probing:

1. **Registry check:** If the NRPT catch-all rule is missing from the registry, restore it + GP refresh + probe-and-heal
2. **Active probe:** If the rule exists, send a probe query to verify it's actually routing — catches cases where the registry key is present but DNS Client hasn't loaded it
3. **(hard mode)** Verify WFP sublayer exists; full restart on loss

This is periodic (not just network-event-driven) because VPN software can clear NRPT at any time. Additionally, `scheduleDelayedRechecks()` (called on network change events) performs immediate NRPT verification at 2s and 4s after changes.

#### Known Caveats

- **`nslookup` bypasses NRPT**: `nslookup.exe` uses its own DNS resolver implementation and does NOT go through the Windows DNS Client service, so it ignores NRPT rules entirely. Use `Resolve-DnsName` (PowerShell) or `ping` to verify DNS resolution through NRPT. This is a well-known Windows behavior, not a ctrld bug.
- **`RPC_C_AUTHN_DEFAULT`**: `FwpmEngineOpen0` requires `RPC_C_AUTHN_DEFAULT` (0xFFFFFFFF) for the authentication service parameter. Using `RPC_C_AUTHN_NONE` (0) returns `ERROR_NOT_SUPPORTED` on some configurations (e.g., Parallels VMs).
- **FWP_DATA_TYPE enum**: The `FWP_DATA_TYPE` enum starts at `FWP_EMPTY=0`, making `FWP_UINT8=1`, `FWP_UINT16=2`, etc. Some documentation examples incorrectly start at 0.

### macOS (pf)

1. ctrld writes a pf anchor file at `/etc/pf.anchors/com.controld.ctrld`
2. Adds the anchor reference to `/etc/pf.conf` (if not present)
3. Loads the anchor with `pfctl -a com.controld.ctrld -f <file>`
4. Enables pf with `pfctl -e` (if not already enabled)
5. The anchor redirects all outbound DNS (port 53) on non-loopback interfaces to `127.0.0.1:53`
6. On shutdown, the anchor is flushed, the file removed, and references cleaned from `pf.conf`

**ctrld's own traffic**: ctrld's upstream queries use DoH (HTTPS on port 443), not plain DNS on port 53, so the pf redirect does not create a loop for DoH upstreams. **Warning:** If an "os" upstream is configured (which uses plain DNS on port 53 to external servers), the pf redirect will capture ctrld's own outbound queries and create a loop. ctrld will log a warning at startup if this is detected. Use DoH upstreams when DNS intercept mode is active.

## What Changes vs Default Mode

| Behavior | Default Mode | DNS Intercept Mode |
|----------|-------------|-------------------|
| Interface DNS settings | Set to `127.0.0.1` | **Not modified** |
| DNS watchdog | Active (polls every 20s) | **Disabled** |
| VPN DNS conflict | Race condition possible | **Eliminated** |
| Profile bypass window | Up to 20 seconds | **Zero** |
| Requires admin/root | Yes | Yes |
| Additional OS requirements | None | WFP (Windows), pf (macOS) |

## Logging

DNS intercept mode produces detailed logs for troubleshooting:

```
DNS intercept: initializing Windows Filtering Platform (WFP)
DNS intercept: WFP engine opened (handle: 0x1a2b3c)
DNS intercept: WFP sublayer created (weight: 0xFFFF — maximum priority)
DNS intercept: added permit filter "Permit DNS to localhost (IPv4/UDP)" (ID: 12345)
DNS intercept: added block filter "Block outbound DNS (IPv4/UDP)" (ID: 12349)
DNS intercept: WFP filters active — all outbound DNS (port 53) blocked except to localhost
```

On macOS:
```
DNS intercept: initializing macOS packet filter (pf) redirect
DNS intercept: wrote pf anchor file: /etc/pf.anchors/com.controld.ctrld
DNS intercept: loaded pf anchor "com.controld.ctrld"
DNS intercept: pf anchor "com.controld.ctrld" active with 3 rules
DNS intercept: pf redirect active — all outbound DNS (port 53) redirected to 127.0.0.1:53
```

## Troubleshooting

### Windows

```powershell
# Check NRPT rules (should show CtrldCatchAll with . → 127.0.0.1)
Get-DnsClientNrptRule

# Check NRPT registry directly
Get-ChildItem "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig"

# Force Group Policy refresh (if NRPT not taking effect)
gpupdate /target:computer /force

# Check if WFP filters are active
netsh wfp show filters

# Check ctrld's specific filters (look for "ctrld" in output)
netsh wfp show filters | Select-String "ctrld"

# Test DNS resolution (use Resolve-DnsName, NOT nslookup!)
# nslookup bypasses DNS Client / NRPT — it will NOT reflect NRPT routing
Resolve-DnsName example.com
ping example.com

# If you must use nslookup, specify localhost explicitly:
nslookup example.com 127.0.0.1
```

### macOS

```bash
# Check if pf is enabled
sudo pfctl -si

# Check ctrld's anchor rules
sudo pfctl -a com.controld.ctrld -sr
sudo pfctl -a com.controld.ctrld -sn

# Check pf.conf for anchor reference
cat /etc/pf.conf | grep ctrld

# Test DNS is going through ctrld
dig @127.0.0.1 example.com
```

## Limitations

- **Linux**: Not supported. Linux uses `systemd-resolved` or `/etc/resolv.conf` which don't have the same VPN conflict issues. If needed in the future, `iptables`/`nftables` REDIRECT could be used.

- **Split DNS for VPN internal domains**: In `--intercept-mode dns` mode, VPN search domains are auto-detected from virtual network adapters and forwarded to the VPN's DNS servers automatically. In `--intercept-mode hard` mode, VPN internal domains (e.g., `*.corp.local`) will NOT resolve unless configured as explicit upstream rules in ctrld's configuration.

- **macOS mDNSResponder interaction**: On macOS, ctrld uses a workaround ("mDNSResponder hack") that binds to `0.0.0.0:53` instead of `127.0.0.1:53` and refuses queries from non-localhost sources. In dns-intercept mode, pf's `rdr` rewrites the destination IP to `127.0.0.1:53` but preserves the original source IP (e.g., `192.168.2.73`). The mDNSResponder source-IP check is automatically bypassed in dns-intercept mode because the pf/WFP rules already ensure only legitimate intercepted DNS traffic reaches ctrld's listener.

- **Other WFP/pf users**: If other software (VPN, firewall, endpoint security) also uses WFP or pf for DNS interception, there may be priority conflicts. ctrld uses maximum sublayer weight on Windows and a named anchor on macOS to minimize this risk. See "VPN App Coexistence" below for macOS-specific defenses.

## VPN App Coexistence (macOS)

VPN apps (Windscribe, Cisco AnyConnect, F5 BIG-IP, etc.) often manage pf rules themselves, which can interfere with ctrld's DNS intercept. ctrld uses a multi-layered defense strategy:

### 1. Anchor Priority Enforcement

When injecting our anchor reference into the running pf ruleset, ctrld **prepends** both the `rdr-anchor` and `anchor` references before all other anchors. pf evaluates rules top-to-bottom, so our DNS intercept `quick` rules match port 53 traffic before a VPN app's broader rules in their own anchor.

### 2. Interface-Specific Tunnel Rules

VPN apps commonly add rules like `pass out quick on ipsec0 inet all` that match ALL traffic on the VPN interface. If their anchor is evaluated before ours (e.g., after a ruleset reload), these broad rules capture DNS. ctrld counters this by adding explicit DNS intercept rules for each active tunnel interface (ipsec*, utun*, ppp*, tap*, tun*). These interface-specific rules match port 53 only, so they take priority over the VPN app's broader "all" match even within the same anchor evaluation pass.

### 3. Dynamic Tunnel Interface Detection

The network change monitor (`validInterfacesMap()`) only tracks physical hardware ports (en0, bridge0, etc.) — it doesn't see tunnel interfaces (utun*, ipsec*, etc.) created by VPN software. When a VPN connects and creates a new interface (e.g., utun420 for WireGuard), ctrld detects this through a separate tunnel interface change check and rebuilds the pf anchor to include explicit intercept rules for the new interface. This runs on every network change event, even if no physical interface changed.

### 4. pf Watchdog + Network Change Hooks

A background watchdog (30s interval) plus immediate checks on network change events detect when another program replaces the entire pf ruleset (e.g., Windscribe's `pfctl -f /etc/pf.conf`). When detected, ctrld rebuilds its anchor with up-to-date tunnel interface rules and re-injects the anchor reference at the top of the ruleset. A 2-second delayed re-check catches race conditions where the other program clears rules slightly after the network event.

### 4a. Active Interception Probe (pf Translation State Corruption)

Programs like Parallels Desktop reload `/etc/pf.conf` when creating/destroying virtual network interfaces (bridge100, vmenet0). This can corrupt pf's internal translation engine — rdr rules survive in text form but stop evaluating, causing DNS interception to silently fail while the watchdog reports "intact."

ctrld detects interface appearance/disappearance and spawns an async probe monitor:

1. **Probe mechanism:** A subprocess runs with GID=0 (wheel, not `_ctrld`) and sends a DNS query to the OS resolver. If pf interception is working, the query gets redirected to ctrld (127.0.0.1:53) and is detected in the DNS handler. If broken, it times out after 1s.
2. **Backoff schedule:** Probes at 0, 0.5, 1, 2, 4 seconds (~8s window) to win the race against async pf reloads by the hypervisor. Only one monitor runs at a time (atomic singleton).
3. **Auto-heal:** On probe failure, `forceReloadPFMainRuleset()` dumps the running ruleset and pipes it back through `pfctl -f -`, resetting pf's translation engine. VPN-safe because it reassembles from the current running state.
4. **Watchdog integration:** The 30s watchdog also runs the probe when rule text checks pass, as a safety net for unknown corruption causes.

This approach detects **actual broken DNS** rather than guessing from trigger events, making it robust against future unknown corruption scenarios.

### 5. Proactive DoH Connection Pool Reset

When the watchdog detects a pf ruleset replacement, it force-rebootstraps all upstream transports via `ForceReBootstrap()`. This is necessary because `pfctl -f` flushes the entire pf state table, which kills existing TCP connections (including ctrld's DoH connections to upstream DNS servers like 76.76.2.22:443).

The force-rebootstrap does two things that the lazy `ReBootstrap()` cannot:
1. **Closes idle connections on the old transport** (`CloseIdleConnections()`), causing in-flight HTTP/2 requests on dead connections to fail immediately instead of waiting for the 5s context deadline
2. **Creates the new transport synchronously**, so it's ready before any DNS queries arrive post-wipe

Without this, Go's `http.Transport` keeps trying dead connections until each request's context deadline expires (~5s), then the lazy rebootstrap creates a new transport for the *next* request. With force-rebootstrap, the blackout is reduced from ~5s to ~100ms (one fresh TLS handshake).

### 6. Blanket Process Exemption (group _ctrld)

ctrld creates a macOS system group (`_ctrld`) and sets its effective GID at startup via `syscall.Setegid()`. The pf anchor includes a blanket rule:

```
pass out quick group _ctrld
```

This exempts **all** outbound traffic from the ctrld process — not just DNS (port 53), but also DoH (TCP 443), DoT (TCP 853), health checks, and any other connections. This is essential because VPN firewalls like Windscribe load `block drop all` rulesets that would otherwise block ctrld's upstream connections even after the pf anchor is restored.

Because ctrld's anchor is prepended before all other anchors, and this rule uses `quick`, it evaluates before any VPN firewall rules. The result: ctrld's traffic is never blocked regardless of what other pf rulesets are loaded.

The per-IP exemptions (OS resolver, VPN DNS) remain as defense-in-depth for the DNS redirect loop prevention — the blanket rule handles everything else.

### 7. Loopback Outbound Pass Rule

When `route-to lo0` redirects a DNS packet to loopback, pf re-evaluates the packet **outbound on lo0**. None of the existing route-to rules match on lo0 (they're all `on ! lo0` or `on utunX`), so without an explicit pass rule, the packet falls through to the main ruleset where VPN firewalls' `block drop all` drops it — before it ever reaches the inbound rdr rule.

```
pass out quick on lo0 inet proto udp from any to ! 127.0.0.1 port 53
pass out quick on lo0 inet proto tcp from any to ! 127.0.0.1 port 53
```

This bridges the route-to → rdr gap: route-to sends outbound on lo0 → this rule passes it → loopback reflects it inbound → rdr rewrites destination to 127.0.0.1:53 → ctrld receives the query. Without this rule, DNS intercept fails whenever a `block drop all` firewall (Windscribe, etc.) is active.

### 8. Response Routing via `reply-to lo0`

After rdr redirects DNS to 127.0.0.1:53, ctrld responds to the original client source IP (e.g., 100.94.163.168 — a VPN tunnel IP). Without intervention, the kernel routes this response through the VPN tunnel interface (utun420) based on its routing table, and the response is lost.

```
pass in quick on lo0 reply-to lo0 inet proto { udp, tcp } from any to 127.0.0.1 port 53
```

`reply-to lo0` tells pf to force response packets for this connection back through lo0, overriding the kernel routing table. The response stays local, rdr reverse NAT rewrites the source from 127.0.0.1 back to the original DNS server IP (e.g., 10.255.255.3), and the client process receives a correctly-addressed response.

### 9. VPN DNS Split Routing and Exit Mode Detection

When a VPN like Tailscale MagicDNS is active, two distinct modes require different pf handling:

#### The Problem: DNS Proxy Loop

VPN DNS handlers like Tailscale's MagicDNS run as macOS Network Extensions. MagicDNS
listens on 100.100.100.100 and forwards queries to internal upstream nameservers
(e.g., 10.3.112.11, 10.3.112.12) via the VPN tunnel interface (utun13).

Without special handling, pf's generic `pass out quick on ! lo0 route-to lo0` rule
intercepts MagicDNS's upstream queries on the tunnel interface, routing them back
to ctrld → which matches VPN DNS split routing → forwards to MagicDNS → loop:

```
┌──────────────────────────────────────────────────────────────────────┐
│  THE LOOP (without passthrough rules)                                │
│                                                                      │
│  1. dig gitlab.int.windscribe.com                                    │
│     → pf intercepts → route-to lo0 → rdr → ctrld (127.0.0.1:53)    │
│                                                                      │
│  2. ctrld: VPN DNS match → forward to 100.100.100.100:53            │
│     → group _ctrld exempts → reaches MagicDNS                       │
│                                                                      │
│  3. MagicDNS: forward to upstream 10.3.112.11:53 via utun13         │
│     → pf generic rule matches (utun13 ≠ lo0, 10.3.112.11 ≠ skip)   │
│     → route-to lo0 → rdr → back to ctrld ← LOOP!                   │
└──────────────────────────────────────────────────────────────────────┘
```

#### The Fix: Interface Passthrough + Exit Mode Detection

**Split DNS mode** (VPN handles only specific domains):

ctrld adds passthrough rules for VPN DNS interfaces that let MagicDNS's upstream
queries flow without interception. A `<vpn_dns>` table contains the VPN DNS server
IPs (e.g., 100.100.100.100) — traffic TO those IPs is NOT passed through (still
intercepted by pf → ctrld enforces profile):

```
table <vpn_dns> { 100.100.100.100 }

# MagicDNS upstream queries (to 10.3.112.11 etc.) — pass through
pass out quick on utun13 inet proto udp from any to ! <vpn_dns> port 53
pass out quick on utun13 inet proto tcp from any to ! <vpn_dns> port 53

# Queries TO MagicDNS (100.100.100.100) — not matched above,
# falls through to generic rule → intercepted → ctrld → profile enforced
```

```
┌──────────────────────────────────────────────────────────────────────┐
│  SPLIT DNS MODE (with passthrough rules)                             │
│                                                                      │
│  Non-VPN domain (popads.net):                                        │
│  dig popads.net → system routes to 100.100.100.100 on utun13        │
│  → passthrough rule: dest IS in <vpn_dns> → NOT matched             │
│  → generic rule: route-to lo0 → rdr → ctrld → profile blocks it ✅  │
│                                                                      │
│  VPN domain (gitlab.int.windscribe.com):                             │
│  dig gitlab.int... → pf intercepts → ctrld                          │
│  → VPN DNS match → forward to 100.100.100.100 (group exempt)        │
│  → MagicDNS → upstream 10.3.112.11 on utun13                        │
│  → passthrough rule: dest NOT in <vpn_dns> → MATCHED → passes ✅    │
│  → 10.3.112.11 returns correct internal answer (10.3.112.113)        │
└──────────────────────────────────────────────────────────────────────┘
```

**Exit mode** (all traffic through VPN):

When Tailscale exit node is enabled, MagicDNS becomes the system's **default**
resolver (not just supplemental). If we added passthrough rules, ALL DNS would
bypass ctrld — losing profile enforcement.

Exit mode is detected using two independent signals (either triggers exit mode):

**1. Default route detection (primary, most reliable):**
Uses `netmon.DefaultRouteInterface()` to check if the system's default route
(0.0.0.0/0) goes through a VPN DNS interface. If `DefaultRouteInterface` matches
a VPN DNS interface name (e.g., utun13), the VPN owns the default route — it's
exit mode. This is the ground truth: the routing table directly reflects whether
all traffic flows through the VPN, regardless of how the VPN presents itself in
scutil.

**2. scutil flag detection (secondary, fallback):**
If the VPN DNS server IP appears in a `scutil --dns` resolver entry that has
**no search domains** and **no Supplemental flag**, it's acting as the system's
default resolver (exit mode). This catches edge cases where the default route
hasn't changed yet but scutil already shows the VPN as the default DNS.

```
# Non-exit mode — default route on en0, 100.100.100.100 is Supplemental:
$ route -n get 0.0.0.0 | grep interface
  interface: en0                        ← physical NIC, not VPN
resolver #1
  search domain[0] : int.windscribe.com
  nameserver[0] : 100.100.100.100
  flags    : Supplemental, Request A records

# Exit mode — default route on utun13, 100.100.100.100 is default resolver:
$ route -n get 0.0.0.0 | grep interface
  interface: utun13                     ← VPN interface!
resolver #2
  nameserver[0] : 100.100.100.100      ← MagicDNS is default
  flags    : Request A records          ← no Supplemental!
```

In exit mode, NO passthrough rules are generated. pf intercepts all DNS → ctrld
enforces its profile on everything. VPN search domains still resolve correctly
via ctrld's VPN DNS split routing (forwarded to MagicDNS through the group
exemption).

#### Summary Table

| Scenario | Passthrough | Profile Enforced | VPN Domains |
|----------|-------------|-----------------|-------------|
| No VPN | None | ✅ All traffic | N/A |
| Split DNS (Tailscale non-exit) | ✅ VPN interface | ✅ Non-VPN domains | ✅ Via MagicDNS |
| Exit mode (Tailscale exit node) | ❌ None | ✅ All traffic | ✅ Via ctrld split routing |
| Windscribe | None (different flow) | ✅ All traffic | N/A |
| Hard intercept | None | ✅ All traffic | ❌ Not forwarded |

### Nuclear Option (Future)

If anchor ordering + interface rules prove insufficient, an alternative approach is available: inject DNS intercept rules directly into the **main pf ruleset** (not inside an anchor). Main ruleset rules are evaluated before ALL anchors, making them impossible for another app to override without explicitly removing them. This is more invasive and not currently implemented, but documented here as a known escalation path.

## Known VPN Conflicts

### F5 BIG-IP APM

F5 BIG-IP APM VPN is a known source of DNS conflicts with ctrld (Support ticket #1688001). The conflict occurs because F5's VPN client aggressively manages DNS:

**How the conflict manifests:**

1. ctrld sets system DNS to `127.0.0.1` / `::1` for local forwarding
2. F5 VPN connects and **overwrites DNS on all interfaces** by prepending its own servers (e.g., `10.50.10.77`, `192.168.208.56`)
3. F5 enforces split DNS patterns (e.g., `*.provisur.local`) and activates its DNS Relay Proxy (`F5FltSrv.exe` / `F5FltSrv.sys`)
4. ctrld's watchdog detects the change and restores `127.0.0.1` — F5 overwrites again
5. This loop causes intermittent resolution failures, slow responses, and VPN disconnects

**Why `--intercept-mode dns` solves this:**

- ctrld no longer modifies interface DNS settings — there is nothing for F5 to overwrite
- WFP (Windows) blocks all outbound DNS except to localhost, so F5's prepended DNS servers are unreachable on port 53
- F5's DNS Relay Proxy (`F5FltSrv`) becomes irrelevant since no queries reach it
- In `--intercept-mode dns` mode, F5's split DNS domains (e.g., `*.provisur.local`) are auto-detected from the VPN adapter and forwarded to F5's DNS servers through ctrld's upstream mechanism

**F5-side mitigations (if `--intercept-mode dns` is not available):**

- In APM Network Access DNS settings, enable **"Allow Local DNS Servers"** (`AllowLocalDNSServersAccess = 1`)
- Disable **"Enforce DNS Name Resolution Order"**
- Switch to IP-based split tunneling instead of DNS-pattern-based to avoid activating F5's relay proxy
- Update F5 to version 17.x+ which includes DNS handling fixes (see F5 KB K80231353)

**Additional considerations:**

- CrowdStrike Falcon and similar endpoint security with network inspection can compound the conflict (three-way DNS stomping)
- F5's relay proxy (`F5FltSrv`) performs similar functions to ctrld — they are in direct conflict when both active
- The seemingly random failure pattern is caused by timing-dependent race conditions between ctrld's watchdog, F5's DNS enforcement, and (optionally) endpoint security inspection

### Cisco AnyConnect

Cisco AnyConnect exhibits similar DNS override behavior. `--intercept-mode dns` mode prevents the conflict by operating at the packet filter level rather than competing for interface DNS settings.

### Windscribe Desktop App

Windscribe's macOS firewall implementation (`FirewallController_mac`) replaces the entire pf ruleset when connecting/disconnecting via `pfctl -f`, which wipes ctrld's anchor references and flushes the pf state table (killing active DoH connections). ctrld handles this with multiple defenses:

1. **pf watchdog** detects the wipe and restores anchor rules immediately on network change events (or within 30s via periodic check)
2. **DoH transport force-reset** immediately replaces upstream transports when a pf wipe is detected (closing old connections + creating new ones synchronously), reducing the DNS blackout from ~5s to ~100ms
3. **Tunnel interface detection** adds explicit intercept rules for Windscribe's WireGuard interface (e.g., utun420) when it appears
4. **Dual delayed re-checks** (2s + 4s after network event) catch race conditions where VPN apps modify pf rules and DNS settings asynchronously after the initial network change
5. **Deferred pf restore** waits for VPN to finish its pf modifications before restoring ctrld's rules, preventing the reconnect death spiral
6. **Blanket group exemption** (`pass out quick group _ctrld`) ensures all ctrld traffic (including DoH on port 443) passes through VPN firewalls like Windscribe's `block drop all`

## 7. VPN DNS Lifecycle

When VPN software connects or disconnects, ctrld must track DNS state changes to ensure correct routing and avoid stale state.

### Network Change Event Flow (macOS)

```
Network change detected (netmon callback)
    │
    ├─ Immediate actions:
    │   ├─ ensurePFAnchorActive()      — verify/restore pf anchor references
    │   ├─ checkTunnelInterfaceChanges() — detect new/removed VPN interfaces
    │   │   ├─ New tunnel → pfStartStabilization() (wait for VPN to finish pf changes)
    │   │   └─ Removed tunnel → rebuild anchor immediately (with VPN DNS exemptions)
    │   └─ vpnDNS.Refresh()            — re-discover VPN DNS from scutil --dns
    │
    ├─ Delayed re-check at 2s:
    │   ├─ ensurePFAnchorActive()      — catch async pf wipes
    │   ├─ checkTunnelInterfaceChanges()
    │   ├─ InitializeOsResolver()      — clear stale DNS from scutil
    │   └─ vpnDNS.Refresh()            — clear stale VPN DNS routes
    │
    └─ Delayed re-check at 4s:
        └─ (same as 2s — catches slower VPN teardowns)
```

### VPN Connect Sequence

1. VPN creates tunnel interface (e.g., utun420)
2. Network change fires → `checkTunnelInterfaceChanges()` detects new tunnel
3. **Stabilization mode** activates — suppresses pf restores while VPN modifies rules
4. Stabilization loop polls `pfctl -sr` hash every 1.5s
5. When hash stable for 6s → VPN finished → restore ctrld's pf anchor
6. `vpnDNS.Refresh()` discovers VPN's search domains and DNS servers from `scutil --dns`
7. Anchor rebuild includes VPN DNS exemptions (so ctrld can reach VPN DNS on port 53)

### VPN Disconnect Sequence

1. VPN removes tunnel interface
2. Network change fires → `checkTunnelInterfaceChanges()` detects removal
3. Anchor rebuilt immediately (no stabilization needed for removals)
4. VPN app may asynchronously wipe pf rules (`pfctl -f /etc/pf.conf`)
5. VPN app may asynchronously clean up DNS settings from `scutil --dns`
6. **2s delayed re-check**: restores pf anchor if wiped, refreshes OS resolver
7. **4s delayed re-check**: catches slower VPN teardowns
8. `vpnDNS.Refresh()` returns empty → `onServersChanged(nil)` clears stale exemptions
9. `InitializeOsResolver()` re-reads `scutil --dns` → clears stale LAN nameservers

### Key Design Decisions

- **`buildPFAnchorRules()` receives VPN DNS servers**: All call sites (tunnel rebuild, watchdog restore, stabilization exit) pass `vpnDNS.CurrentServers()` so exemptions are preserved for still-active VPNs.
- **`onServersChanged` called even when server list is empty**: Ensures stale pf exemptions from a previous VPN session are cleaned up on disconnect.
- **OS resolver refresh in delayed re-checks**: VPN apps often finish DNS cleanup 1-3s after the network change event. The delayed `InitializeOsResolver()` call ensures stale LAN nameservers (e.g., Windscribe's 10.255.255.3) don't cause 2s query timeouts.
- **Ordering: tunnel checks → VPN DNS refresh → delayed re-checks**: Ensures anchor rebuilds from tunnel changes include current VPN DNS exemptions.

## Related

- [GitLab Issue #489](https://gitlab.int.windscribe.com/controld/clients/ctrld/-/issues/489) — Original issue and discussion
- F5 BIG-IP APM VPN DNS conflict (Support ticket #1688001)
