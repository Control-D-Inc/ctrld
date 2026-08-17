# Firewall Mode

Firewall mode makes DNS policy unbypassable *while ctrld is running* by blocking outbound
connections to any IP that wasn't resolved by ctrld. On Windows, enforcement is tied to the
process lifetime - see [Enforcement lifetime](#enforcement-lifetime-what-happens-when-the-process-dies). This closes the "DNS gap" - where apps use hardcoded
IPs, direct-IP fallbacks, or alternative DNS resolvers to bypass DNS-based filtering.

## How It Works

1. **DNS responses feed the allowlist**: Every successful A/AAAA record resolved by ctrld
   is added to an in-memory allowlist with TTL-based expiry.

2. **Outbound connections are checked**: Before any outbound TCP/UDP connection, the
   destination IP is checked against the allowlist. If it wasn't resolved by ctrld, the
   connection is blocked.

3. **Permanent entries are always allowed**: Loopback, RFC1918 private ranges, link-local,
   CGNAT, multicast, ctrld's own listener, and upstream resolver IPs are always allowed.

4. **The organization's allowed destinations are always allowed**: managed endpoints receive
   an explicit list of destinations from the API that stay reachable without a DNS lookup -
   see [Organization Allowed Destination IPs](#organization-allowed-destination-ips).

## Configuration

### TOML Config

```toml
[service]
  firewall_mode = "on"   # "off" (default) or "on"
  intercept_mode = "hard" # Required on desktop for enforcement
```

### CLI Flag

```bash
ctrld start --firewall-mode on --intercept-mode hard
```

### Remote API

Firewall mode can be toggled remotely via the ControlD API's `custom_config` field,
which is polled by `apiConfigReload()`. The same response carries the organization's
`destination_ips` list - see
[Organization Allowed Destination IPs](#organization-allowed-destination-ips).

## Platform-Specific Enforcement

### macOS (pf)

When both firewall mode and intercept mode are active, ctrld extends the pf anchor
with a `<ctrld_allowed>` table:

- Default: block all outbound traffic
- Pass: traffic to IPs in the `<ctrld_allowed>` table
- Pass: traffic to the organization's allowed destinations in the `<ctrld_allowed_dst>` table
- Pass: traffic to loopback and link-local
- Pass: existing DNS intercept rules

The table is dynamically updated as DNS responses arrive. Updates are batched (200ms
accumulation window) to avoid excessive `pfctl` calls.

### Windows (WFP)

When both firewall mode and hard intercept mode are active, ctrld extends the WFP
sublayer with dynamic permit filters:

- Base: block all outbound traffic (low-weight filter)
- Dynamic: permit filters for each IP in the allowlist
- Static: permits for loopback, RFC1918, ctrld listener
- Organization: permit filters for each entry in the Allowed Destination IP list

Permit filters are added/removed dynamically as the allowlist changes.

#### Enforcement lifetime: what happens when the process dies

ctrld opens its WFP session as a **dynamic** session, so Windows removes every filter it
added - including firewall mode's block-all - as soon as the process exits, however it
exits. That is a deliberate trade, recorded here because it changes what "unbypassable"
means on Windows:

- **Before**: a hard kill (`taskkill /f`, a crash) left the filters installed with no ctrld
  to manage them. The host was unusable rather than unfiltered, and only a reboot or a
  manual WFP cleanup recovered it. A replacement ctrld could not even reach the API to
  start, so it never got far enough to clean up - the deadlock this session change breaks.
- **Now**: the same kill leaves the host *unfiltered* until the service restarts.

A clean stop or uninstall behaved this way already, and both need administrator rights, as
does killing a SYSTEM service - so the newly exposed case is specifically the hard kill of
an already-privileged process. What it costs is that an administrator can turn enforcement
off without uninstalling and without a trace beyond the service state.

Compensating controls:

1. **Restart policy backs off instead of burning out.** `ConfigureWindowsServiceFailureActions`
   uses 5s / 30s / 2m restart delays with a 10-minute reset window, so three failures cannot
   spend the whole budget inside 15 seconds and leave the host unfiltered. Repeated kills
   still end in a stopped service - a bounded policy has to - but it takes minutes.
2. **Startup cleans up predecessors.** `cleanupStaleDNSInterceptState` removes filters left
   by a build that predates session-scoped ownership, so an upgrade from such a build cannot
   inherit the old lockout.

Still open: enforcement stopping while policy should be active is visible only in the local
log. Reporting that state centrally is follow-up work, and is the control that would make
the hard-kill case detectable rather than merely bounded.

### Linux and Unsupported Platforms

Kernel enforcement is not implemented yet. On unsupported platforms, `firewall_mode = "on"` currently fails open: ctrld still records allowlist stats, but it does not block outbound traffic. A warning is logged at startup so this is visible. Future work: iptables/nftables rules or eBPF, and possibly a strict mode that fails closed when platform enforcement is unavailable.

## Permanently Allowed IPs

These IPs are always allowed regardless of DNS resolution:

| Range | Reason |
|-------|--------|
| `127.0.0.0/8`, `::1` | Loopback - local services |
| `10.0.0.0/8` | RFC1918 - LAN, printers, NAS |
| `172.16.0.0/12` | RFC1918 - LAN |
| `192.168.0.0/16` | RFC1918 - LAN |
| `169.254.0.0/16`, `fe80::/10` | Link-local - DHCP, mDNS |
| `100.64.0.0/10` | CGNAT - Tailscale, carrier NAT |
| `224.0.0.0/4`, `ff00::/8` | Multicast - mDNS, SSDP |
| ctrld listener IPs | Self - DNS proxy must be reachable |
| Upstream resolver IPs | DoH/DoT/DoQ endpoints |

## Organization Allowed Destination IPs

Firewall Mode only permits what ctrld resolved, so a service addressed by literal IP - with
no DNS lookup to observe - is unreachable. An organization can publish a list of destinations
that stay reachable anyway, without having to turn Firewall Mode off.

The API sends the *effective* list for the endpoint's organization in the `destination_ips`
field of every resolver-config response: the organization's own entries plus any inherited
from a parent organization that applies its settings to sub-organizations. Entries are IPv4
or IPv6 addresses (bare, e.g. `203.0.113.10`) or CIDRs (e.g. `198.51.100.0/24`,
`2001:db8::/48`). Nothing is configured locally - the list is not a TOML setting.

How it is applied:

- **As a set, not as additions.** Every refresh - the scheduled one and a forced
  `apiConfigReload` - replaces the previous set. An entry added upstream takes effect on the
  next refresh; an entry removed upstream stops bypassing Firewall Mode on the next refresh,
  unless it is independently allowed by a DNS resolution or a permanent entry.
- **Without a reload.** Applying the list does not restart listeners or reload the config,
  and it is unaffected by the allowlist flushes that follow a profile change or a network
  change - unlike DNS-resolved IPs, these entries carry no TTL and are never reaped.
- **Per platform.** macOS puts them in a second pf table, `<ctrld_allowed_dst>`, passed by
  its own rules; Windows installs a WFP permit filter per entry, at the same weight as the
  dynamic permits. Both are kept apart from the DNS-resolved entries so a flush of those
  leaves the organization's list installed. On Linux and other unsupported platforms the set
  is tracked in memory and reported in stats, but nothing enforces it (see above).
- **Retried until enforcement agrees.** ctrld tracks the set the API asked for separately
  from the set pf/WFP has accepted. A failed `pfctl` call or WFP filter operation does not
  advance the applied set, so the same change is retried by the next refresh and by a
  reconcile every 5 minutes - a rejected addition does not leave an approved destination
  blocked, and a rejected removal does not leave a withdrawn one permitted. Until the two
  agree the difference is reported as `allowed_destinations_pending` in the stats line, and
  the "applied" log line is not written.
- **Enforcement startup replaces, it does not add.** When pf/WFP enforcement comes up, ctrld
  knows nothing about what it holds - the macOS table is a `persist` table that outlives the
  process, so it can still contain what a previous run put there, including entries the
  organization has since withdrawn. The first reconcile therefore replaces the table's whole
  contents (an empty list means emptying it), and that replace is retried on the same
  schedule until it succeeds; only then does ctrld consider any part of the set applied.
- **Bad entries are dropped individually.** An entry that is not a valid address or CIDR is
  logged once and skipped; the rest of the list still applies.
- **Addresses are logged at debug level.** The list is organization network topology, so
  Info-level logging - which is persisted and travels in support bundles - carries only
  counts.

Devices with Firewall Mode off are unaffected: there is nothing to make an exception to, so
the list is ignored until the mode is turned on.

## Live Profile Updates

When a ControlD profile changes (domain goes from allowed → blocked or vice versa):

1. ctrld's `apiConfigReload()` detects the change
2. The entire allowlist is flushed
3. Subsequent DNS queries repopulate the allowlist under the new policy
4. Brief connectivity interruption (~seconds) while DNS cache repopulates

This is the "flush and repopulate" strategy - simple and correct, with a small
tradeoff of a brief connectivity blip on config changes.

## Network State Changes

When the device changes networks (WiFi → cellular, between WiFi networks, etc.):

1. `monitorNetworkChanges()` detects the transition
2. The allowlist is flushed (old IPs may not be routable on new network)
3. DNS cache is also flushed (existing behavior)
4. Both repopulate naturally from new DNS queries

## Edge Cases

### CDN IP Rotation
A domain may resolve to different IPs over time. Each resolved IP is added independently
with its own TTL. Multiple IPs can coexist for the same domain.

### CNAME Chains
For `foo.com` → CNAME → `bar.cdn.com` → A record, the final A/AAAA IPs are allowlisted
and associated with the original query domain (`foo.com`).

### Short TTLs
Some CDNs use 30-second TTLs. The allowlist enforces a minimum TTL of 30 seconds to
prevent excessive churn. The background reaper runs every 30 seconds.

### App Startup Race
Apps may attempt connections before their first DNS query reaches ctrld. This is a known
limitation. A "learning mode" grace period at startup is a future enhancement.

### Cached Responses
When ctrld serves a response from its DNS cache, the allowlist entries are refreshed.
This prevents the case where the DNS cache outlives the allowlist TTL.

### Long-Lived Connections and Direct-IP Retries
Firewall mode learns allowed destinations from DNS responses. If an app keeps a
long-lived connection open across a firewall/profile refresh, or retries directly
to a previously resolved IP without issuing another DNS query, the reconnect can
remain blocked until the app performs DNS resolution again. This is an accepted
v1 tradeoff and should be called out in release notes and compatibility testing
for common apps.

## VM / Container Workloads (macOS)

By default a VM or container resolves DNS through a path the host ctrld does not
observe (the hypervisor's own resolver on the guest bridge, or a resolver the
guest is configured to use). The guest-resolved public IP therefore never enters
`<ctrld_allowed>`, and the guest's forwarded/NATed egress to that IP is dropped by
the blanket block - DNS "works" inside the guest but TCP/443 fails. (Tracked as
issue #569.)

Exempting the whole bridge interface would turn the guest into a policy bypass,
so it is intentionally **not** done. Instead ctrld makes those guests first-class
Firewall Mode clients by forcing their DNS through itself. The trusted source
subnets are the **union** of:

1. **Auto-detected VM networks (default, no config).** At pf-anchor build time an
   interface is trusted only when it is up, carries an **RFC1918 IPv4** network, and
   its VM ownership can be proven one of two ways:

   - **its own name is vendor-specific** - `vnic` (Parallels), `vboxnet`
     (VirtualBox host-only), `vmnet` (legacy kext-based VMware Fusion on Intel);
   - **it is a `bridge*` whose member list contains a vendor VM interface**
     (typically `vmenet*`). This is the case for every `vmnet.framework` stack -
     UTM and other Virtualization.framework guests, Docker Desktop, Multipass, and
     Fusion 12.1+ NAT - where the RFC1918 gateway address sits on `bridge10x` and
     the vendor-named `vmenet*` interface is an address-less member of it. Matching
     on interface name alone never sees those stacks.

   Physical uplinks (`en*`), loopback, VPN tunnels (`utun*`), public ranges, and
   IPv6 never qualify. Each auto-trusted subnet is logged at debug level
   (`Firewall: auto-detected VM/container network for forwarded DNS`, with the
   `reason` field naming the proof), and its pf rules are scoped to the interface it
   was detected on (`on <iface>`), so an unrelated interface carrying the same
   private range is never affected.

   A `bridge*` **name** is still not proof of anything: macOS uses that namespace
   for Thunderbolt and aggregated links too (ctrld's own tunnel-change code treats
   `bridge0` as physical). Membership is what distinguishes them - a Thunderbolt
   bridge has `en*` members and is never trusted, however private its address.

2. **Configured subnets (opt-in).** Needed for any stack whose ownership
   auto-detection cannot prove - a VM network on a plain interface with no vendor
   name, a bridge with no vendor member, or a deliberately non-RFC1918 range:

   ```toml
   [service]
     firewall_mode = "on"
     intercept_mode = "hard"
     # Only needed when auto-detection cannot prove the network is a VM network.
     firewall_forwarded_sources = ["192.168.64.0/24"]
   ```

   Find the subnet with `ifconfig` on the host - for a `vmnet.framework` stack it is
   the `bridge1xx` interface serving the VM. Use the network address in CIDR form;
   host bits are normalized away. A configured entry matches on the source CIDR
   alone - it is an admin opt-in, so it is not tied to one interface. Entries must be
   **IPv4**; interception targets ctrld's IPv4 listener, so an IPv6 entry is ignored
   with a warning. Config only **adds** to auto-detection; it never disables it.

   A malformed or non-IPv4 entry is dropped with a warning and the rest of the set
   still applies - this field is deliberately **not** hard-validated at startup, so a
   typo in an MDM-pushed subnet cannot stop ctrld from serving DNS. The warning is
   logged when the set of bad entries changes, not on every internal rebuild, so a
   standing typo does not fill the log.

### Guest start/stop and network changes

VM/container interfaces come and go while ctrld runs, and the pf watchdog does not
rebuild an anchor whose rules are still intact. ctrld therefore tracks the effective
forwarded-source set (auto-detected ∪ configured) and, whenever it changes,
rebuilds the anchor and drops the pf states of the affected subnets (targeted
`pfctl -k <subnet>`, not a global state flush) so the new policy applies
immediately instead of when old states expire. A guest's in-flight connections are
re-established under the new rules.

Reconciliation runs on interface appear/disappear, on network changes, on the
delayed post-change re-checks (a new VM network often gets its address slightly
after its interface appears), and on the pf watchdog tick - which bounds how long a
started guest can go untrusted, or a stopped guest stay trusted, to one watchdog
interval even if no network event fires. Each transition is logged with the subnets
that gained and lost trust.

The set ctrld considers applied only advances once pf has actually accepted the new
anchor. If the write or `pfctl -f` fails, the previous set stays recorded, nothing is
flushed, a warning is logged, and the next reconciliation (at the latest the next
watchdog tick) retries the same transition - so a transient failure cannot leave the
old anchor installed while ctrld believes the change is done.

### Supported behavior and trust boundary

For each source subnet (auto-detected or configured), when Firewall Mode +
intercept are active, ctrld:

- **Forces guest plaintext DNS (port 53) through ctrld** (pf `route-to lo0` onto
  the existing loopback redirect). Every guest resolution is policy-enforced and
  populates `<ctrld_allowed>`, so the guest's egress to allowed destinations is
  then permitted by the same allowlist rule as the host.
- **Blocks guest IPv4 DoT (port 853)** so a guest cannot swap in an alternate
  encrypted resolver to escape policy. Rules are emitted for the source's own
  address family only (all sources are IPv4) - pf refuses to load an entire anchor
  containing an `inet6` rule with an IPv4 source, which would take DNS interception
  down with it. Guest traffic to an IPv6 DoT resolver is instead covered by the
  blanket IPv6 outbound block, since such a resolver never enters `<ctrld_allowed>`.

The boundary is explicit and per-subnet - a guest still **cannot** bypass Control
D policy via a direct public IP (never resolved through ctrld ⇒ never allowlisted)
or an alternate plaintext/DoT resolver. It is not an interface-wide permit.

### Confirming what is trusted

At startup (and on every change) ctrld logs the effective set, naming each subnet's
origin, so `firewall_forwarded_sources` can be verified without reading pf rules:

```
Firewall: forwarded-workload (VM/container) DNS interception active for these source subnets count=2 sources=["192.168.64.0/24 (auto-detected on bridge100)","192.168.252.0/24 (configured)"]
```

The interface named is where the address lives, which for a `vmnet.framework` stack
is the bridge (`bridge100`), not its `vmenet*` member.

When the set is empty the log says so explicitly, rather than staying silent:

```
Firewall: no forwarded-workload (VM/container) sources — guest DNS is not intercepted. Auto-detection needs an up interface with an RFC1918 IPv4 address that is either vendor-named (vnic*, vboxnet*, vmnet*) or a bridge with a VM member (vmenet*); anything else must be listed in service.firewall_forwarded_sources
```

Note that `firewall_forwarded_sources` is a **local** config setting. If it is not in
`/etc/controld/ctrld.toml` on the device, ctrld has nothing to act on - check the file
itself, not only the dashboard.

### Limitations

- **A resolver running inside the guest is not supported** while Firewall Mode is on.
  The design depends on the guest sending plaintext DNS (port 53) that host ctrld can
  observe. A guest-side resolver (ctrld, systemd-resolved with DoT, dnscrypt, ...)
  sends its upstream queries encrypted instead, so the host learns no addresses and
  the guest's egress is blocked - and its DoT is blocked outright by the port-853 rule.
  That is the trust boundary working as intended, not a regression: a guest that
  resolves privately could otherwise reach any destination it liked. Point the guest
  at the host bridge address (its default DHCP resolver) and let host ctrld enforce
  policy for it.
- **DoH over 443** inside the guest is indistinguishable from ordinary HTTPS and
  is not intercepted. To keep enforcement strict, disable DoH in the guest OS/
  browser, or restrict the guest to the host resolver.
- **IPv6 guest DNS** is not redirected (ctrld's intercept listener is IPv4); the
  anchor's existing IPv6 DNS block forces guests to fall back to interceptable
  IPv4 DNS. IPv6 forwarded sources are therefore unsupported: an IPv6
  `firewall_forwarded_sources` entry is ignored with a warning rather than emitted
  as a rule.
- Auto-detection needs ownership proof: a vendor interface name, or a bridge with a
  vendor VM member. A VM network on a plain unrecognized interface, or a bridge whose
  hypervisor attaches no vendor-named member, needs an explicit
  `firewall_forwarded_sources` entry. Bridge membership is read with `ifconfig`, and
  only for a bridge that already carries an RFC1918 IPv4 address.
- macOS only. Windows (WFP) Firewall Mode VM behavior is tracked separately
  (#568).

## Metrics

Allowlist stats are logged every 5 minutes:

```
Firewall allowlist stats allowed_ips=142 permanent_ips=18 allowed_destinations=3 allowed_destinations_pending=0 tracked_domains=89 total_hits=4521 total_misses=23
```

`allowed_destinations` is the number of prefixes in the organization's Allowed Destination
IP list. `allowed_destinations_pending` is how many of its changes platform enforcement has
not accepted yet - normally 0; a non-zero value that persists across reconciles means
`pfctl`/WFP keeps rejecting the change, and the warning that named the error is in the log.


## Troubleshooting

### Everything is blocked
- Check that the upstream resolver IPs are in the permanent allowlist (logged at startup)
- Verify DNS is working: `nslookup example.com 127.0.0.1`
- Check allowlist stats for hit/miss ratio

### Certain apps don't work
- The app may be using hardcoded IPs (this is the intended behavior - those IPs aren't DNS-resolved).
  For an approved service, add its addresses to the organization's Allowed Destination IP list,
  then either wait for the next scheduled refresh (`refetch_time`, hourly by default) or force
  one by resolving `<cdUID>.verify.controld.com` through ctrld, which is the only trigger that
  makes ctrld re-fetch its resolver config on demand. The applied set is logged as `Firewall:
  applied organization allowed destination IPs` and counted as `allowed_destinations` in the
  stats line. If that line does not appear, check for `could not apply all organization allowed
  destinations` (a delta that enforcement rejected) or `could not install organization allowed
  destinations, will retry` (the full install done when enforcement starts, or after a resync),
  along with the `allowed_destinations_pending` count - enforcement is refusing the change and
  the reconcile is retrying it
- Check if the app uses a custom DNS resolver that bypasses ctrld
- RFC1918 traffic is always allowed, so LAN-only apps should work

### High miss count
- Normal for the first few seconds after startup or network change
- Persistent high misses may indicate apps using hardcoded IPs extensively
