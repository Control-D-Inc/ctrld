# Organization Internal Domains

Internal Domains let an organization administrator route a domain suffix, and
every subdomain under it, to a chosen resolver. The selection is made in the
Control D dashboard and reaches the endpoint through the managed resolver
configuration, so no hand-edited `ctrld.toml` is involved and changes apply on
the next configuration refresh.

## API contract

The managed resolver configuration carries the list in `resolver.split_dns`:

```json
{
  "resolver": {
    "split_dns": [
      { "domain": "corp.example.com", "mode": "resolvers", "resolvers": ["10.0.0.53", "10.0.0.54"] },
      { "domain": "office.example.com", "mode": "os", "resolvers": [] }
    ]
  }
}
```

`mode` is what the administrator selected, and it decides the routing:

| `mode` | Behavior |
|---|---|
| `os` | The query goes to `upstream.os`, the endpoint's current system resolver, and follows DHCP and VPN resolver changes. Any addresses still present in `resolvers` are **not** read, so switching a domain back to the OS resolver cannot be undone by leftovers from a previous selection. |
| `resolvers` | The query goes only to the addresses in `resolvers`, tried in the order given. An empty or entirely unusable list does not become OS resolution: the entry is dropped instead. |
| absent | A deployment that predates the field. The mode is inferred from `resolvers`, which is what the field encodes. |
| anything else | Dropped. Routing a private domain by guess is the disclosure this feature exists to prevent. |

A dropped entry leaves its domain on its normal path and is reported in the
`skipped` count.

Addresses may be IPv4 or IPv6, bare or with a port; a bare address uses port 53.
An address that is not a valid IP is dropped from the list.

A domain is lowercased and stripped of surrounding whitespace, a leading `*.`
and the root dot, then validated as an ASCII hostname suffix: 1-63 character
labels, letters, digits and hyphens only, no leading or trailing hyphen, 253
characters overall. Single-label names and punycode are supported. This is the
same rule the API validates against, so anything the dashboard accepted passes.
A value that fails is rejected and counted, never repaired — deleting the
offending characters would produce a different suffix from the configured one,
and routing a private domain to the wrong place is worse than not routing it.

## Generated configuration

Each accepted domain contributes two policy rules, `<domain>` and `*.<domain>`,
which is how ctrld matches a suffix and all of its subdomains. Explicit mode
also generates one upstream per resolver address, named `internal_<n>`:

```toml
[upstream.internal_0]
  type = "legacy"
  endpoint = "10.0.0.10:53"

[listener.0.policy]
  rules = [
    { "aws.example.com" = ["upstream.internal_0", "upstream.internal_1"] },
    { "*.aws.example.com" = ["upstream.internal_0", "upstream.internal_1"] },
    { "corp.internal" = [] },
    { "*.corp.internal" = [] },
  ]
```

An empty target list is the same representation Magic Folder excludes use, and
`proxy()` resolves it through `upstream.os`.

## Precedence

The generated configuration is built in a fixed order, and a rule that already
exists for a source is never overwritten. From highest precedence to lowest:

1. **Endpoint custom configuration.** A valid `ctrld.custom_config` replaces the
   generated configuration outright. Internal Domains are not merged into it,
   the same as Magic Folder excludes — if an organization uses a custom config,
   its rules are the whole policy.
2. **Magic Folder excludes** (`resolver.exclude`). These are written first, so an
   excluded domain keeps its exclusion even if it also appears as an Internal
   Domain. Only the exact source collides: an exclude for `aws.example.com` does
   not stop the Internal Domain from claiming `*.aws.example.com`.
3. **Internal Domains** (`resolver.split_dns`), most specific suffix first.
   The API permits overlapping suffixes and returns the list sorted bytewise by
   domain, which puts a parent ahead of its children. Policy rules are matched
   in order and the first hit wins, so appending in API order would let
   `*.example.com` swallow every query a configured `z.example.com` was meant to
   answer. Entries are therefore ordered by label count before generation, and
   the ordering is stable, so equally specific entries keep API order and the
   first of two identical domains still wins.
4. **Active Directory auto-detection** (Windows). `addExtraSplitDnsRule` runs
   after the generated configuration and skips any domain that already has a
   rule, so an Internal Domain for the AD domain takes precedence over the
   auto-detected one.

**VPN DNS auto-detection** is evaluated inside `proxy()` in DNS-intercept mode,
after policy matching and independently of it, so it needs its own rule:

- An **explicit-resolver** Internal Domain skips VPN routing. The administrator
  named the resolvers for that suffix; VPN suffixes are discovered from the OS,
  and letting a discovered route override a named one is the leak this feature
  exists to prevent.
- An **OS-resolver** Internal Domain does not skip it, and behaves exactly like
  a Magic Folder exclude. It asks for the endpoint's default resolution, which
  under intercept mode includes the VPN's own resolver.

Every domain that is not an Internal Domain keeps its current VPN routing.

## Unreachable explicit resolvers

When every resolver for an explicit-mode domain fails, the query returns
SERVFAIL. It is deliberately not retried against the OS resolver, and it does
not trigger the endpoint recovery flow:

- Sending a private name to a resolver the administrator did not select is the
  leak this feature exists to prevent.
- The recovery flow exists for the loss of general DNS. One unavailable internal
  server is not that, and letting it start recovery would reset endpoint DNS
  settings for every other domain.

OS-resolver mode has no such restriction: it is the system resolver, so it
follows DHCP and VPN changes and shares their failure handling.

## Self-uninstall eligibility

ctrld treats a plain managed install — one Control D upstream and no endpoint
custom configuration — as eligible for the REFUSED-triggered deletion check,
which is the fast path that notices a device has been deleted server-side.
Generated `internal_*` upstreams do not count toward that, because they come
from the managed configuration itself rather than from an operator choosing a
second upstream. Eligibility is recomputed on every setup and reload, so adding
or removing Internal Domains, or gaining a genuinely custom second upstream,
is reflected instead of latching on the first value seen.

Discounting is by upstream shape, not by key name alone: an endpoint custom
configuration replaces the generated config outright and could name an upstream
`internal_0`, which must not buy eligibility. The uninstall itself remains
gated on the API confirming the device is gone.

## Refresh

`apiConfigReload` compares the stored `split_dns` against each fetch. Domains
are compared in canonical form and independently of API ordering, so an
unchanged list does not reload; resolver order is significant, because it is the
administrator's failover order. Any add, removal, domain change or resolver
change triggers a reload, which regenerates the configuration from the API
response. Because the generated configuration is rebuilt rather than patched, a
removed domain leaves no rule and no `internal_*` upstream behind.

## Logging

Generated `internal_*` upstreams carry the organization's private resolver
addresses, so anything naming one stays at debug, and the level above it carries
only a classification (`timeout`, `refused`, `unreachable`, `source_unavailable`,
`error`). The per-query error sampler applies to the classification line as
well. After 5 lines in one minute for the same upstream and class, the next
classification lines go to debug, and one `Per-query errors sampled` line gives
the count. That covers every consumer, not just query handling:

- the bootstrap-IP line in `setupUpstream`;
- the transport error from a failed query, which names the endpoint;
- the **loop checker**, which probes every local upstream on a one-minute
  ticker — a generated resolver is always a local address, so this path runs
  with no user query at all;
- the **recovery checker**, which takes every non-OS upstream. Keeping an
  Internal Domain query from *starting* recovery does not keep its resolver out
  of recovery started for another reason.

Info and warning logs report counts only — domains applied, OS-resolver and
explicit-resolver totals, generated resolvers, skipped and preempted entries.
Domain names and resolver addresses are organization-private and appear only at
debug level.
