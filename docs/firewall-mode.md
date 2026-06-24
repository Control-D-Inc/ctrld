# Firewall Mode

Firewall mode makes DNS policy unbypassable by blocking outbound connections to any
IP that wasn't resolved by ctrld. This closes the "DNS gap" — where apps use hardcoded
IPs, direct-IP fallbacks, or alternative DNS resolvers to bypass DNS-based filtering.

## How It Works

1. **DNS responses feed the allowlist**: Every successful A/AAAA record resolved by ctrld
   is added to an in-memory allowlist with TTL-based expiry.

2. **Outbound connections are checked**: Before any outbound TCP/UDP connection, the
   destination IP is checked against the allowlist. If it wasn't resolved by ctrld, the
   connection is blocked.

3. **Permanent entries are always allowed**: Loopback, RFC1918 private ranges, link-local,
   CGNAT, multicast, ctrld's own listener, and upstream resolver IPs are always allowed.

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
which is polled by `apiConfigReload()`.

## Platform-Specific Enforcement

### macOS (pf)

When both firewall mode and intercept mode are active, ctrld extends the pf anchor
with a `<ctrld_allowed>` table:

- Default: block all outbound traffic
- Pass: traffic to IPs in the `<ctrld_allowed>` table
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

Permit filters are added/removed dynamically as the allowlist changes.

### Linux and Unsupported Platforms

Kernel enforcement is not implemented yet. On unsupported platforms, `firewall_mode = "on"` currently fails open: ctrld still records allowlist stats, but it does not block outbound traffic. A warning is logged at startup so this is visible. Future work: iptables/nftables rules or eBPF, and possibly a strict mode that fails closed when platform enforcement is unavailable.

## Permanently Allowed IPs

These IPs are always allowed regardless of DNS resolution:

| Range | Reason |
|-------|--------|
| `127.0.0.0/8`, `::1` | Loopback — local services |
| `10.0.0.0/8` | RFC1918 — LAN, printers, NAS |
| `172.16.0.0/12` | RFC1918 — LAN |
| `192.168.0.0/16` | RFC1918 — LAN |
| `169.254.0.0/16`, `fe80::/10` | Link-local — DHCP, mDNS |
| `100.64.0.0/10` | CGNAT — Tailscale, carrier NAT |
| `224.0.0.0/4`, `ff00::/8` | Multicast — mDNS, SSDP |
| ctrld listener IPs | Self — DNS proxy must be reachable |
| Upstream resolver IPs | DoH/DoT/DoQ endpoints |

## Live Profile Updates

When a ControlD profile changes (domain goes from allowed → blocked or vice versa):

1. ctrld's `apiConfigReload()` detects the change
2. The entire allowlist is flushed
3. Subsequent DNS queries repopulate the allowlist under the new policy
4. Brief connectivity interruption (~seconds) while DNS cache repopulates

This is the "flush and repopulate" strategy — simple and correct, with a small
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

## Metrics

Allowlist stats are logged every 5 minutes:

```
Firewall allowlist stats allowed_ips=142 permanent_ips=18 tracked_domains=89 total_hits=4521 total_misses=23
```


## Troubleshooting

### Everything is blocked
- Check that the upstream resolver IPs are in the permanent allowlist (logged at startup)
- Verify DNS is working: `nslookup example.com 127.0.0.1`
- Check allowlist stats for hit/miss ratio

### Certain apps don't work
- The app may be using hardcoded IPs (this is the intended behavior — those IPs aren't DNS-resolved)
- Check if the app uses a custom DNS resolver that bypasses ctrld
- RFC1918 traffic is always allowed, so LAN-only apps should work

### High miss count
- Normal for the first few seconds after startup or network change
- Persistent high misses may indicate apps using hardcoded IPs extensively
