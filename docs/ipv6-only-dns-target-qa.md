# IPv6-only DNS-target validation

Relates to #617. Native CLAT/PF behavior is not proven by parser tests or cross-compilation. This change must not disable IPv6 DNS enforcement, change PF routing, or reclassify every failed DHCP command as empty DNS.

## Regression gates

- Ordinary static IPv4 DNS and successful DHCPv4 discovery retain their existing behavior.
- An explicit non-owned IPv6 loopback resolver (`::1`), alone or mixed with other static DNS, prevents the expanded fallback. Its settings and backup must remain unchanged through reconciliation and cleanup.
- The target-specific DHCP lookup shares a two-second deadline across both commands, with a 100 ms pipe-cleanup grace. Timeout remains an error, not confirmed absence. This does not impose a deadline on legacy global discovery or every operation under the target lock.
- An unknown, truncated, malformed, timed-out or permission-denied native-state read authorizes no new DNS mutation.
- A CLAT-looking address alone is insufficient. Positive native publication must match the current default interface/service, with no contradictory native IPv4 state.
- Confirmed IPv6-only state can reach the existing listener-aware target installation path despite unavailable DHCPv4 data.
- Repeated reconciliation is idempotent. Existing targets, external DNS changes, default-service switches, DHCP return and restart/stop cleanup preserve ownership.
- A failed preservation snapshot cannot authorize the new fallback write.
- Logs distinguish configured IPv6 blocking, observed rule counters, missing evidence, counter resets and successful local receipt. Shared counters cannot identify which packet was blocked.
- Diagnostics are bounded, omit raw PF dumps/query names and do not cause DNS/PF changes or repeated repair actions.

## Native comparison

Use an owned disposable Mac with a local console, an identified baseline/candidate and the same profile/listener. Save exact original DNS settings. Do not run host-mutating tests on shared CI hosts; native unit tests must intercept the first mutation boundary.

1. Verify a healthy baseline on ordinary IPv4/DHCP, then establish actual host-side CLAT using an owned hotspot or isolated NAT64/PREF64 fixture. Record the interface/service mapping, native state, routes, static DNS, raw scutil DNS and both DHCP commands' exit/output. A carrier label or synthetic address assignment is not a fixture.
2. Confirm upstream and direct-listener resolution independently. Keep a pre-existing manual loopback DNS override from masking the target decision, without deleting unrelated configuration.
3. Compare startup already attached, disconnected startup followed by attachment, and a same-process transition to the IPv6-only network. Test sleep/wake separately and exclude intentionally offline/sleep periods from recovery measurements.
4. On the candidate, require the appropriate temporary target and fresh system-resolution success while still on CLAT. Record any independent PF-probe failure rather than treating working system DNS as proof of repaired transparent interception.
5. Return to IPv4/DHCP; verify target removal/restoration. Repeat with explicit static DNS, an existing tracked target, external DNS changes and an injected unknown/read-error state. Stop/uninstall must not leave DNS pointing to a dead listener.
6. Read the retained diagnostics after a failed probe and after restored receipt. Distinguish missing rules/read errors from a present IPv6 block with cumulative traffic counters. A reload or rising shared counter does not prove a particular probe's fate.

Preserve captures privately and record the exact artifact. A successful owned-lab case supports the scoped fix; a customer retest remains a separate validation gate.
