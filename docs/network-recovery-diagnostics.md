# Network-recovery diagnostics

Use continuous `ctrld log tail` capture during a reproduction. Internal logs rotate by size.
A later `log send` can contain recent debug events and older warnings.
Match timestamps and IDs. The last retained error does not necessarily describe the current network.
Issue #604 tracks upload-time device and version headers separately.

## Transitions and recovery

`Network transition` debug events include a `transition_id`, affected interface, default route, and stored source addresses before and after the callback.
The outcome identifies an accepted, ignored, superseded, or unusable change.
Newer accepted changes supersede pending recovery. Ignored changes do not cancel accepted recovery.
Source commits validate addresses against the current network state.
Netmon does not order minor callbacks within one major cache epoch.
For minor callbacks and late major callbacks in that epoch, ctrld reads current interface addresses and flags.
This read does not change host DNS. A failed read defers source writes, but reconciliation continues.

`Removed stale resolver source` is a warning only when ctrld removes an invalid address.
The warning gives the reason and survives debug rotation.
`Recovery begin` and `Recovery end` connect the transition to a `recovery_generation`, reason, outcome, and elapsed time.
Only the first upstream failure in each recovery produces a bounded summary.
If a recovery encounters a failure, its final outcome also enters the warning stream.
Normal successful recovery stays at debug level.

These summaries exclude upstream URLs and queried names.
Each PF probe records the recovery generation at its start.
A later recovery cannot receive credit for an earlier probe.

### Cancellation event migration

On `master`, `Recovery end` with `outcome=canceled` replaces `Recovery failed; DNS settings remain removed`.
Update support runbooks and log searches to use the structured event.
The cancellation event alone does not prove that interface DNS remains removed.

Note: On the 1.x (`v1.0`) line, the previous message was `Recovery canceled; DNS settings remain removed`.

## PF probes (macOS)

`DNS intercept probe result` includes these fields:

- `probe_id` and `recovery_generation`
- Numeric `resolver_target` and `resolver_family`
- `stage`, bounded `error_code`, and `outcome`
- `repair_eligible`, `repeated_results`, and elapsed milliseconds

A changed unsuccessful condition produces a warning. The condition consists of the stage, error code, outcome, and target.
Equal results stay at debug level. The next changed condition includes the preceding repeat count.
The first restored receipt also produces a warning-stream event. This event prevents an older failure from appearing current.
Normal receipts and shutdown cancellation stay at debug level.
The warning buffer is finite. These events do not guarantee indefinite retention.

The outcomes have these meanings:

- `intercepted`: the registered query reached the local handler. This proves interception delivery, not remote DNS health.
- `not_intercepted`: the helper confirmed a successful UDP write, but the handler did not receive the query before the deadline.
  This result permits bounded repair. It does not identify an external PF writer or explain the delivery failure.
- `indeterminate`: the probe has no suitable target, cannot send, receives an invalid helper acknowledgement, or stops before a conclusive result.
  This result alone does not cause a PF reload or transport reset. The existing monitor or watchdog retries later.
  Independent evidence of missing rules still permits ordinary repair.

The literal stages are `target`, `start`, `decode`, `dial`, `deadline`, `write`, `sent`, `helper`, `delivery`, and `received`.
`sent` is the helper acknowledgement before the final delivery result.
The error codes are `unavailable`, `invalid_argument`, `unreachable`, `source_unavailable`, `permission`, `timeout`, `io`, `invalid_status`, and `canceled`.
Successful results have an empty error code. No raw subprocess output enters these fields.

The sender runs outside the `_ctrld` group exemption.
ctrld blocks outgoing IPv6 DNS with its own PF rule and does not redirect it.
The selector preserves a usable first IPv4 target, including an original public resolver.
Otherwise, it selects the first usable IPv4 address in the leading LAN group.
It stops at the public group, which can contain a synthetic fallback. It does not blacklist a particular public IP.
Loopback, unspecified, and multicast addresses are not usable targets.

`PF repair` events carry the causal `probe_id` and `recovery_generation` for all four callers.
They record `started`, `not_run`, or `reload_completed`. Completed means that the reload ran, not that interception recovered.
A confirming probe adds its own ID and its interception outcome to the original repair correlation.
The watchdog leaves confirmation to its next scheduled probe.
`budget_exhausted` records a wake repair that the existing budget prevents.
A probe-triggered reload does not count as a missing-anchor repair.

See [PF DNS interception](pf-dns-intercept.md) and [DNS intercept mode](dns-intercept-mode.md) for the rule lifecycle.

## Reproduction boundaries

Compare the affected release with the exact candidate artifact on an owned host.
Keep the configuration unchanged. Capture ordinary DNS and a direct query to the actual listener and port.
Measure recovery after a usable route and resolver return. Exclude unavoidable offline time.
Record source-address changes, PF observations, and upstream results. Success at one layer does not prove success at another.

Use the recovery mode, ownership, outcome, and effective network-service DNS configuration to assess cancellation.
Never flush global PF state to collect diagnostics.
