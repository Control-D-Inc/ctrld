# macOS pf DNS Interception — Technical Reference

## Overview

ctrld uses macOS's built-in packet filter (pf) to intercept all DNS traffic at the kernel level, redirecting it to ctrld's local listeners at `127.0.0.1:53` (IPv4) and `[::1]:53` (IPv6). This operates below interface DNS settings, making it immune to VPN software (F5, Cisco, GlobalProtect, etc.) that overwrites DNS on network interfaces.

## How pf Works (Relevant Basics)

pf is a stateful packet filter built into macOS (and BSD). It processes packets through a pipeline with **strict rule ordering**:

```
options (set) → normalization (scrub) → queueing → translation (nat/rdr) → filtering (pass/block)
```

**Anchors** are named rule containers that allow programs to manage their own rules without modifying the global ruleset. Each anchor type must appear in the correct section:

| Anchor Type | Section | Purpose |
|-------------|---------|---------|
| `scrub-anchor` | Normalization | Packet normalization |
| `nat-anchor` | Translation | NAT rules |
| `rdr-anchor` | Translation | Redirect rules |
| `anchor` | Filtering | Pass/block rules |

**Critical constraint:** If you place a `rdr-anchor` line after an `anchor` line, pf rejects the entire config with "Rules must be in order."

## Why We Can't Just Use `rdr on ! lo0`

The obvious approach:
```
rdr pass on ! lo0 proto udp from any to any port 53 -> 127.0.0.1 port 53
```

**This doesn't work.** macOS pf `rdr` rules only apply to *forwarded/routed* traffic — packets passing through the machine to another destination. DNS queries originating from the machine itself (locally-originated) are never matched by `rdr` on non-loopback interfaces.

This is a well-known pf limitation on macOS/BSD. It means the VPN client's DNS queries would be redirected (if routed through the machine), but the user's own applications querying DNS directly would not.

## Our Approach: route-to + rdr (Two-Step)

We use a two-step technique to intercept locally-originated DNS:

```
Step 1: Force outbound DNS through loopback
  pass out quick on ! lo0 route-to lo0 inet proto udp from any to ! 127.0.0.1 port 53

Step 2: Pass the packet outbound on lo0 (needed when VPN firewalls have "block drop all")
  pass out quick on lo0 inet proto udp from any to ! 127.0.0.1 port 53 no state

Step 3: Redirect it on loopback to ctrld's listener
  rdr on lo0 inet proto udp from any to ! 127.0.0.1 port 53 -> 127.0.0.1 port 53

Step 4: Accept and create state for response routing
  pass in quick on lo0 reply-to lo0 inet proto { udp, tcp } from any to 127.0.0.1 port 53
```

> **State handling is critical for VPN firewall coexistence:**
> - **route-to**: `keep state` (default). State is interface-bound on macOS — doesn't match on lo0.
> - **pass out lo0**: `no state`. If this created state, it would match inbound on lo0 and bypass rdr.
> - **rdr**: no `pass` keyword. Packet must go through filter so `pass in` can create response state.
> - **pass in lo0**: `keep state` (default). Creates the ONLY state on lo0 — handles response routing.

### Packet Flow

```
Application queries 10.255.255.3:53 (e.g., VPN DNS server)
    ↓
Kernel: outbound on en0 (or utun420 for VPN)
    ↓
pf filter: "pass out route-to lo0 ... port 53" → redirects to lo0, creates state on en0
    ↓
pf filter (outbound lo0): "pass out on lo0 ... no state" → passes, NO state created
    ↓
Loopback reflects packet inbound on lo0
    ↓
pf rdr (inbound lo0): "rdr on lo0 ... port 53 -> 127.0.0.1:53" → rewrites destination
    ↓
pf filter (inbound lo0): "pass in reply-to lo0 ... to 127.0.0.1:53" → creates state + reply route
    ↓
ctrld receives query on 127.0.0.1:53
    ↓
ctrld resolves via DoH (port 443, exempted by group _ctrld)
    ↓
Response from ctrld: 127.0.0.1:53 → 100.94.163.168:54851
    ↓
reply-to lo0: forces response through lo0 (without this, kernel routes via utun420 → lost in VPN tunnel)
    ↓
pf applies rdr reverse NAT: src 127.0.0.1 → 10.255.255.3
    ↓
Application receives response from 10.255.255.3:53 ✓
```

### Why This Works

1. `route-to lo0` forces the packet onto loopback at the filter stage
2. `pass out on lo0 no state` gets past VPN "block drop all" without creating state
3. No state on lo0 means rdr gets fresh evaluation on the inbound pass
4. `reply-to lo0` on `pass in` forces the response through lo0 — without it, the kernel routes the response to VPN tunnel IPs via the VPN interface and it's lost
4. `rdr` (without `pass`) redirects then hands off to filter rules
5. `pass in keep state` creates the response state — the only state on the lo0 path
6. Traffic already destined for `127.0.0.1` is excluded (`to ! 127.0.0.1`) to prevent loops
7. ctrld's own upstream queries use DoH (port 443), bypassing port 53 rules entirely

### Why Each State Decision Matters

| Rule | State | Why |
|------|-------|-----|
| route-to on en0/utun | keep state | Needed for return routing. Interface-bound, won't match on lo0. |
| pass out on lo0 | **no state** | If stateful, it would match inbound lo0 → bypass rdr → DNS broken |
| rdr on lo0 | N/A (no pass) | Must go through filter so pass-in creates response state |
| pass in on lo0 | keep state + reply-to lo0 | Creates lo0 state. `reply-to` forces response through lo0 (not VPN tunnel). |

## IPv6 DNS Interception

macOS systems with IPv6 nameservers (common — `scutil --dns` often shows an IPv6 nameserver at index 0) send DNS queries over IPv6. Without IPv6 interception, these queries bypass ctrld, causing ~1s delays (the IPv6 query times out, then the app falls back to IPv4).

### Why IPv6 Needs Special Handling

Three problems prevent a simple "mirror the IPv4 rules" approach:

1. **Cross-AF redirect is impossible**: pf cannot `rdr on lo0 inet6 ... -> 127.0.0.1` (redirecting IPv6 to IPv4). ctrld must listen on `[::1]` to handle IPv6 DNS.

2. **`block return` is ineffective for IPv6 DNS**: BSD doesn't deliver ICMPv6 unreachable errors to unconnected UDP sockets (which `dig` and most resolvers use). So `block return out inet6 ... port 53` generates the ICMP error, but the application never receives it — it waits for the full timeout (~1s).

3. **sendmsg from `[::1]` to global unicast fails**: Unlike IPv4 where the kernel allows `sendmsg` from `127.0.0.1` to local private IPs (e.g., `10.x.x.x`), macOS/BSD rejects `sendmsg` from `[::1]` to a global unicast IPv6 address with `EINVAL`. Since pf's `rdr` preserves the original source IP (the machine's global IPv6 address), ctrld's reply would fail.

### Solution: nat + rdr + [::1] Listener

```
# NAT: rewrite source to ::1 so ctrld can reply
nat on lo0 inet6 proto udp from ! ::1 to ! ::1 port 53 -> ::1
nat on lo0 inet6 proto tcp from ! ::1 to ! ::1 port 53 -> ::1

# RDR: redirect destination to ctrld's IPv6 listener
rdr on lo0 inet6 proto udp from any to ! ::1 port 53 -> ::1 port 53
rdr on lo0 inet6 proto tcp from any to ! ::1 port 53 -> ::1 port 53

# Filter: route-to forces IPv6 DNS to loopback (mirrors IPv4 rules)
pass out quick on ! lo0 route-to lo0 inet6 proto udp from any to ! ::1 port 53
pass out quick on ! lo0 route-to lo0 inet6 proto tcp from any to ! ::1 port 53

# Pass on lo0 without state (mirrors IPv4)
pass out quick on lo0 inet6 proto udp from any to ! ::1 port 53 no state
pass out quick on lo0 inet6 proto tcp from any to ! ::1 port 53 no state

# Accept redirected IPv6 DNS with reply-to (mirrors IPv4)
pass in quick on lo0 reply-to lo0 inet6 proto { udp, tcp } from any to ::1 port 53
```

### IPv6 Packet Flow

```
Application queries [2607:f0c8:8000:8210::1]:53 (IPv6 DNS server)
    ↓
pf filter: "pass out route-to lo0 inet6 ... port 53" → redirects to lo0
    ↓
pf (outbound lo0): "pass out on lo0 inet6 ... no state" → passes
    ↓
Loopback reflects packet inbound on lo0
    ↓
pf nat: rewrites source 2607:f0c8:...:ec6e → ::1
pf rdr: rewrites dest [2607:f0c8:8000:8210::1]:53 → [::1]:53
    ↓
ctrld receives query from [::1]:port → [::1]:53
    ↓
ctrld resolves via DoH, replies to [::1]:port (kernel accepts ::1 → ::1)
    ↓
pf reverses both translations:
  - nat reverse: dest ::1 → 2607:f0c8:...:ec6e (original client)
  - rdr reverse: src ::1 → 2607:f0c8:8000:8210::1 (original DNS server)
    ↓
Application receives response from [2607:f0c8:8000:8210::1]:53 ✓
```

### Client IP Recovery

The `nat` rewrites the source to `::1`, so ctrld sees the client as `::1` (loopback). The existing `spoofLoopbackIpInClientInfo()` logic detects this and replaces it with the machine's real RFC1918 IPv4 address (e.g., `10.0.10.211`). This is the same mechanism used when queries arrive from `127.0.0.1` — no client identity is lost.

### IPv6 Listener

The `[::1]` listener reuses the existing infrastructure from Windows (where it was added for the same reason — can't suppress IPv6 DNS resolvers from the system config). The `needLocalIPv6Listener()` function gates it, returning `true` on:
- **Windows**: Always (if IPv6 is available)
- **macOS**: Only in intercept mode

If the `[::1]` listener fails to bind, it logs a warning and continues — the IPv4 listener is primary.

### nat-anchor Requirement

The `nat` rules in our anchor require a `nat-anchor "com.controld.ctrld"` reference in the main pf ruleset, in addition to the existing `rdr-anchor` and `anchor` references. All pf management functions (inject, remove, verify, watchdog, force-reload) handle all three anchor types.

## Rule Ordering Within the Anchor

pf requires translation rules before filter rules, even within an anchor:

```pf
# === Translation rules (MUST come first) ===
rdr on lo0 inet proto udp from any to ! 127.0.0.1 port 53 -> 127.0.0.1 port 53
rdr on lo0 inet proto tcp from any to ! 127.0.0.1 port 53 -> 127.0.0.1 port 53

# === Exemptions (filter phase, scoped to _ctrld group) ===
pass out quick on ! lo0 inet proto { udp, tcp } from any to <OS_RESOLVER_IP> port 53 group _ctrld
pass out quick on ! lo0 inet proto { udp, tcp } from any to <VPN_DNS_IP> port 53 group _ctrld

# === Main intercept (filter phase) ===
pass out quick on ! lo0 route-to lo0 inet proto udp from any to ! 127.0.0.1 port 53
pass out quick on ! lo0 route-to lo0 inet proto tcp from any to ! 127.0.0.1 port 53

# === Allow redirected traffic on loopback ===
pass in quick on lo0 reply-to lo0 inet proto { udp, tcp } from any to 127.0.0.1 port 53
```

### Exemption Mechanism (Group-Scoped)

Some IPs must bypass the redirect:

- **OS resolver nameservers** (e.g., DHCP-assigned DNS): ctrld's recovery/bootstrap path may query these on port 53. Without exemption, these queries loop back to ctrld.
- **VPN DNS servers**: When ctrld forwards VPN-specific domains (split DNS) to the VPN's internal DNS, those queries must reach the VPN DNS server directly.

Exemptions use `pass out quick` with `group _ctrld` **before** the `route-to` rule. The `group _ctrld` constraint ensures that **only ctrld's own process** can bypass the redirect — other applications cannot circumvent DNS interception by querying the exempted IPs directly. Because pf evaluates filter rules in order and `quick` terminates evaluation, the exempted packet goes directly out the real interface and never hits the `route-to` or `rdr`.

### The `_ctrld` Group

To scope pf exemptions to ctrld's process only, we use a dedicated macOS system group:

1. **Creation**: On startup, `ensureCtrldGroup()` creates a `_ctrld` system group via `dscl` (macOS Directory Services) if it doesn't already exist. The GID is chosen from the 350-450 range to avoid conflicts with Apple's reserved ranges. The function is idempotent.

2. **Process GID**: Before loading pf rules, ctrld sets its effective GID to `_ctrld` via `syscall.Setegid()`. All sockets created by ctrld after this point are tagged with this GID.

3. **pf matching**: Exemption rules include `group _ctrld`, so pf only allows bypass for packets from processes with this effective GID. Other processes querying the same exempt IPs are still redirected to ctrld.

4. **Lifecycle**: The group is **never removed** on shutdown or uninstall. It's a harmless system group, and leaving it avoids race conditions during rapid restart cycles. It is recreated (no-op if exists) on every start.

## Anchor Injection into pf.conf

The trickiest part. macOS only processes anchors declared in the active pf ruleset. We must inject our anchor references into the running config.

### What We Do

1. Read `/etc/pf.conf`
2. If our anchor reference already exists, reload as-is
3. Otherwise, inject `nat-anchor "com.controld.ctrld"` and `rdr-anchor "com.controld.ctrld"` in the translation section and `anchor "com.controld.ctrld"` in the filter section
4. Write to a **temp file** and load with `pfctl -f <tmpfile>`
5. **We never modify `/etc/pf.conf` on disk** — changes are runtime-only and don't survive reboot (ctrld re-injects on every start)

### Injection Logic

Finding the right insertion point requires understanding the existing pf.conf structure. The algorithm:

1. **Scan** for existing `rdr-anchor`/`nat-anchor`/`binat-anchor` lines (translation section) and `anchor` lines (filter section)
2. **Insert `rdr-anchor`**:
   - Before the first existing `rdr-anchor` line (if any exist)
   - Else before the first `anchor` line (translation must come before filtering)
   - Else before the first `pass`/`block` line
   - Last resort: append (but this should never happen with a valid pf.conf)
3. **Insert `anchor`**:
   - Before the first existing `anchor` line (if any)
   - Else before the first `pass`/`block` line
   - Last resort: append

### Real-World pf.conf Scenarios

We test against these configurations:

#### Default macOS (Sequoia/Sonoma)
```
scrub-anchor "com.apple/*"
nat-anchor "com.apple/*"
rdr-anchor "com.apple/*"
anchor "com.apple/*"
load anchor "com.apple" from "/etc/pf.anchors/com.apple"
```
Our `rdr-anchor` goes before `rdr-anchor "com.apple/*"`, our `anchor` goes before `anchor "com.apple/*"`.

#### Little Snitch
Adds `rdr-anchor "com.obdev.littlesnitch"` and `anchor "com.obdev.littlesnitch"` in the appropriate sections. Our anchors coexist — pf processes multiple anchors in order.

#### Lulu Firewall (Objective-See)
Adds `anchor "com.objective-see.lulu"`. We insert `rdr-anchor` before it (translation before filtering) and `anchor` before it.

#### Cisco AnyConnect
Adds `nat-anchor "com.cisco.anyconnect"`, `rdr-anchor "com.cisco.anyconnect"`, `anchor "com.cisco.anyconnect"`. Our anchors insert alongside Cisco's in their respective sections.

#### Minimal pf.conf (no anchors)
Just `set skip on lo0` and `pass all`. We insert `rdr-anchor` and `anchor` before the `pass` line.

#### Empty pf.conf
Both anchors appended. This is a degenerate case that shouldn't occur in practice.

## Failure Modes and Safety

### What happens if our injection fails?
- `ensurePFAnchorReference` returns an error, logged as a warning
- ctrld continues running but DNS interception may not work
- The anchor file and rules are cleaned up on shutdown
- **No damage to existing pf config** — we never modify files on disk

### What happens if ctrld crashes (SIGKILL)?
- pf anchor rules persist in kernel memory
- DNS is redirected to 127.0.0.1:53 but nothing is listening → DNS breaks
- On next `ctrld start`, we detect the stale anchor file, flush the anchor, and start fresh
- Without ctrld restart: `sudo pfctl -a com.controld.ctrld -F all` manually clears it

### What if another program flushes all pf rules?
- Our anchor references are removed from the running config
- DNS interception stops (traffic goes direct again — fails open, not closed)
- The periodic watchdog (30s) detects missing rules and restores them
- ctrld continues working for queries sent to 127.0.0.1 directly

### What if another program reloads pf.conf (corrupting translation state)?
Programs like Parallels Desktop reload `/etc/pf.conf` when creating or destroying
virtual network interfaces (bridge100, vmenet0). This can corrupt pf's internal
translation engine — **rdr rules survive in text form but stop evaluating**.
The watchdog's rule-text checks say "intact" while DNS is silently broken.

**Detection:** ctrld detects interface appearance/disappearance in the network
change handler and spawns an asynchronous interception probe monitor:

1. A subprocess sends a DNS query WITHOUT the `_ctrld` group GID, so pf
   intercept rules apply to it
2. If ctrld receives the query → pf interception is working
3. If the query times out (1s) → pf translation is broken
4. On failure: `forceReloadPFMainRuleset()` does `pfctl -f -` with the current
   running ruleset, resetting pf's translation engine

The monitor probes with exponential backoff (0, 0.5, 1, 2, 4s) to win the race
against async pf reloads. Only one monitor runs at a time (singleton). The
watchdog also runs the probe every 30s as a safety net.

The full pf reload is VPN-safe: it reassembles from `pfctl -sr` + `pfctl -sn`
(the current running state), preserving all existing anchors and rules.

### What if another program adds conflicting rdr rules?
- pf processes anchors in declaration order
- If another program redirects port 53 before our anchor, their redirect wins
- If after, ours wins (first match with `quick` or `rdr pass`)
- Our maximum-weight sublayer approach on Windows (WFP) doesn't apply to pf — pf uses rule ordering, not weights

### What about `set skip on lo0`?
Some pf.conf files include `set skip on lo0` which tells pf to skip ALL processing on loopback. **This would break our approach** since both the `rdr on lo0` and `pass in on lo0` rules would be skipped.

**Mitigation:** When injecting anchor references via `ensurePFAnchorReference()`,
we strip `lo0` from any `set skip on` directives before reloading. The watchdog
also checks for `set skip on lo0` and triggers a restore if detected. The
interception probe provides an additional safety net — if `set skip on lo0` gets
re-applied by another program, the probe will fail and trigger a full reload.

## Cleanup

On shutdown (`stopDNSIntercept`):
1. `pfctl -a com.controld.ctrld -F all` — flush all rules from our anchor
2. Remove `/etc/pf.anchors/com.controld.ctrld` anchor file
3. `pfctl -f /etc/pf.conf` — reload original pf.conf, removing our injected anchor references from the running config

This is clean: no files modified on disk, no residual rules.

## Comparison with Other Approaches

| Approach | Intercepts local DNS? | Survives VPN DNS override? | Risk of loops? | Complexity |
|----------|----------------------|---------------------------|----------------|------------|
| `rdr on ! lo0` | ❌ No | Yes | Low | Low |
| `route-to lo0` + `rdr on lo0` | ✅ Yes | Yes | Medium (need exemptions) | Medium |
| `/etc/resolver/` | Partial (per-domain only) | No (VPN can overwrite) | Low | Low |
| `NEDNSProxyProvider` | ✅ Yes | Yes | Low | High (needs app bundle) |
| NRPT (Windows only) | N/A | Partial | Low | Medium |

We chose `route-to + rdr` as the best balance of effectiveness and deployability (no app bundle needed, no kernel extension, works with existing ctrld binary).

## Key pf Nuances Learned

1. **`rdr` doesn't match locally-originated traffic** — this is the biggest gotcha
2. **Rule ordering is enforced** — translation before filtering, always
3. **Anchors must be declared in the main ruleset** — just loading an anchor file isn't enough
4. **`rdr` without `pass`** — redirected packets must go through filter rules so `pass in keep state` can create response state. `rdr pass` alone is insufficient for response delivery.
5. **State handling is nuanced** — route-to uses `keep state` (state is floating). `pass out on lo0` must use `no state` (prevents rdr bypass). `pass in on lo0` uses `keep state` + `reply-to lo0` (creates response state AND forces response through loopback instead of VPN tunnel). Getting any of these wrong breaks either the forward or return path.
6. **`quick` terminates evaluation** — exemption rules must use `quick` and appear before the route-to rule
7. **Piping to `pfctl -f -` can fail** — special characters in pf.conf content cause issues; use temp files
8. **`set skip on lo0` would break us** — but it's not in default macOS pf.conf
9. **`pass out quick` exemptions work with route-to** — they fire in the same phase (filter), so `quick` + rule ordering means exempted packets never hit the route-to rule
10. **pf cannot cross-AF redirect** — `rdr on lo0 inet6 ... -> 127.0.0.1` is invalid. IPv6 DNS must be handled by an `[::1]` listener.
11. **`block return` doesn't work for IPv6 DNS** — BSD doesn't deliver ICMPv6 unreachable to unconnected UDP sockets (`sendto`). Apps timeout waiting for a response that never comes.
12. **sendmsg from `::1` to global unicast fails on macOS** — unlike IPv4 where `127.0.0.1` can send to any local address, `::1` cannot send to the machine's own global IPv6 address. `nat` on lo0 is required to rewrite the source.
13. **`nat-anchor` is separate from `rdr-anchor`** — pf requires both in the main ruleset for nat and rdr rules in an anchor to be evaluated. `rdr-anchor` alone does not cover nat rules.
