# Network-recovery diagnostics

The retained stream is the journal, the file `ctrld-journal.log` in the ctrld home directory.
It keeps every warning and every error, plus every event marked `journal=true`.
The journal is on disk, so it keeps these events across a restart and a self-upgrade.
Its budget is 2 MB with 2 backup files.
Every `ctrld log send` upload holds the whole journal, so a reproduction does not need a continuous `ctrld log tail` capture.
Match timestamps and IDs. The last retained error does not describe the current network in every case.
Each upload starts with a header line that names the build, the intercept mode, and the network at send time.

## Journal events

These events describe the host network. Each one carries `journal=true`, so it stays on disk after a rotation and after a restart.
netmon reports every network change as a delta, which holds the state before the change and the state after it.
The table gives the trigger, the level, and the fields of each event.

| Event | Trigger | Level | Fields |
|---|---|---|---|
| `Network snapshot` | Start, an accepted transition, a recovery begin, and a recovery end. Two limits hold some of them back | info | `trigger` (`start`, `transition`, `recovery_begin`, `recovery_end`), `network` |
| `Network interface changed` | One event per changed interface of a delta that is not noise. A mixed delta gives an event for the interfaces outside the noise class only | info | `transition_id`, `interface`, `action`, `class`, `hardware_port`, `service`, `ips_before`, `ips_after`, `flags`, `mtu`, `is_default_route` |
| `Network transition` | The end of every network callback that is not noise | info, debug for the outcomes `ignored` and `snapshot_superseded` | `transition_id`, `outcome`, `is_major_change`, `changed`, `interface`, `changed_interfaces`, `time_jumped`, `default_route_before`, `default_route_after`, `have_v4_before`, `have_v4_after`, `have_v6_before`, `have_v6_after`, `source_ipv4_before`, `source_ipv4_after`, `source_ipv6_before`, `source_ipv6_after`, `source_snapshot_available` |
| `Network delta noise` | Each noise delta, and one journal line per 10 minutes of a storm | debug, info for the journal line | `interfaces`, `count`, `first_at`, `last_at` |
| `Host woke` | One event per wake: a time jump in a netmon delta, or the macOS wake detector, which runs in DNS intercept mode only | info | `gap_known`, `gap_ms` (only when `gap_known` is true), `source` (`netmon`, `detector`), `default_route`, `interfaces_up` |
| `OS resolver set changed` | A nameserver read that differs from the read before | info | `source` (`scutil`, `dhcp`, `resolv.conf`, `unknown`), `before`, `after`, `default_route`, `reason` (`start`, `recovery`, `delayed_recheck`, `wake_probe`, `vpn_settle`, `unspecified`) |
| `Reinitialized OS resolver with nameservers: …` | ctrld read the nameservers of the system again and built the OS resolver again | info | none, the nameservers are part of the message |
| `DNS configuration changed` | A `scutil --dns` poll that finds a changed resolver, one event per resolver (macOS) | info | `nameservers`, `if_index`, `interface`, `scoped`, `action` (`added`, `changed`, `removed`), `flags`, `search_domain_count`, `order`, `reachable` |
| `Recovery begin` | The start of every recovery | info | `transition_id`, `recovery_generation`, `recovery_reason`, `intercept`, `probe_upstreams` |
| `Recovery skipped: configured upstream is not marked down` | An OS-only failure does not start global recovery because a configured candidate is not marked down. First/changed candidate, then at most once per 5 minutes for an unchanged candidate | info | `recovery_reason`, `healthy_upstream` |
| `Recovery end` | The end of every recovery | info, warn for a canceled recovery and for a recovery with a failure | `transition_id`, `recovery_generation`, `recovery_reason`, `outcome`, `had_failure`, `duration_ms`, `recovered_upstream`, `dhcp_servers`, `dhcp_server_count`, `intercept_target_action`, `bypass_active` |
| `Upstream … recovered …` | An upstream that was down answers again | info | `down_for_ms` |
| `Recovery canceled with no successor …` | A recovery stops and no other recovery follows it | info | none |
| `DNS intercept recovery: enabling DHCP bypass …` | ctrld sends the queries of a recovery to the OS resolver | info | none |
| `DNS intercept recovery complete: disabling DHCP bypass …` | The recovery ends and the normal query path returns | info | none |
| `DNS intercept recovery: found DHCP nameservers: …` | ctrld read the DHCP nameservers of the service | info | `dhcp_servers` |
| `DNS intercept recovery: no DHCP nameservers found` | The service gave no DHCP nameserver | warn | none |
| `intercept DNS target: service … set …` | ctrld wrote the loopback target into a network service | warn | `service`, `target`, `reason` |
| `intercept DNS target: removed …` | ctrld took the loopback target out of the service | info | `service`, `target`, `reason` |
| `intercept DNS target: … DNS changed externally …` | Another program changed the DNS of the service, so the target of ctrld is gone (macOS) | info | `service`, `target`, `reason` (`external_change`) |
| `dns64: discovered NAT64 prefix …` | A NAT64 prefix that differs from the result before | info | none |
| `dns64: no NAT64 prefix present …` | A no-prefix result that differs from the result before | info | none |
| `DNS intercept: interface appeared/disappeared …` | An interface appeared or disappeared, and the probe monitor starts | info | `interface`, `class`, `action` |
| `PF anchor list changed` | A missing anchor, a restored anchor, a stabilization start, and a stabilization end (macOS) | warn for the reason `missing`, info for the rest | `reason`, `anchors`, `anchors_known`, `pf_enabled`, `pf_since` |
| `Tunnel interface changed` | The set of tunnel interfaces changes (macOS). A retry of the same change writes no second event | info | `added`, `removed`, `owner` |
| `DNS intercept: VPN connecting …` | A new tunnel interface starts the stabilization mode (macOS) | info | none |
| `DNS intercept: pf stable for …` | The pf ruleset stops changing and stabilization ends (macOS) | info | none |
| `Query health` | A change of the health class that holds for two evaluations, and a heartbeat every 15 minutes | info | `class`, `window_s`, `queries`, `failed_queries`, `cache_hits`, `failures_by_class`, `upstreams_down`, `bypass_active`, `cache_hit_ratio` |

No event in this catalog holds a query name, an upstream URL, or a token.
The journal does hold network addresses. It holds the LAN and VPN resolver addresses, the gateways, the addresses of the host, and the DHCP servers of a service.
It holds no search suffix. `DNS configuration changed` counts the suffixes in `search_domain_count` and logs the count alone.
The field `owner` of `Tunnel interface changed` names the VPN product that owns the tunnel. On Windows the field `hardware_port` names the VPN product of an adapter in the same way.
The Wi-Fi network name is never logged. On macOS 14 and later, only a process with the Location Services permission can read it, and a daemon cannot request that permission.

### The network object

The `network` object describes the host network at one moment.
The `Network snapshot` event and the header line of every log file render the same object, with these fields:

- Routes: `default_route_v4`, `default_route_v6`, `gateway_v4`, `gateway_v6`
- Families: `have_v4`, `have_v6`
- Interfaces: `interfaces`, an array of `name`, `class`, `up`, `ips`, `hardware_port`, `service`, and the count `interfaces_omitted`
- Resolvers: `resolvers`, the host and the port of each OS nameserver
- Source addresses: `source_ipv4`, `source_ipv6`
- Intercept state: `intercept_target`, `dns_less_target`, `bypass_active`, `recovery_running`, `pf_stabilizing`
- Link: `link_type`, `tethered`, `clat_present`, `nat64_prefix`

The field `default_route_interface` is gone. Read `default_route_v4` and `default_route_v6` in its place.
The two routes and the two gateways come from the route table of macOS, one route per address family. A tunnel that owns the default route has no next hop, so its route names the tunnel and its gateway stays empty.
Windows and Linux read no route table in this release. They fill `default_route_v4` from the network monitor and leave `default_route_v6`, `gateway_v4`, and `gateway_v6` empty.

`link_type` is one of `wifi`, `ethernet`, `usb_tether`, `tunnel`, and `unknown`.
macOS reads it from the name of the hardware port. Linux reads `wifi`, `ethernet`, `usb_tether`, and `tunnel` from the kernel.
Windows reads the description of the adapter in place of a port name. The words Ethernet, LAN, and Thunderbolt win over the tunnel class on every platform, so a VPN adapter with a description such as `SSL VPN Virtual Ethernet Adapter` reads as `ethernet`.
Windows gives `tunnel` to the other VPN adapters. The other links are `unknown`.
The field `service` names a macOS network service. It stays empty on Windows and on Linux.
`tethered` is true on every platform when the interface of the default route holds an address of the range 172.20.10.0/28.
It is also true when the default gateway is in that range, and when the hardware port of the default route is `iPhone USB`.

The list `interfaces` holds the interfaces that are up or hold an address, and it stops at 32 entries.
`interfaces_omitted` counts the interfaces that the list leaves out, the ones over the limit included.
A container host holds hundreds of interfaces, and a list of all of them fills the journal.

ctrld does not write a snapshot for every trigger. A snapshot equal to the snapshot written last reaches no journal.
Every other snapshot waits 60 s after the snapshot written last. A new value of `default_route_v4`, `default_route_v6`, or `resolvers` passes that wait.
The trigger `start` always writes.

### Noise class

A noise delta changes interfaces of the noise class only, and it does not move the default route.
The noise class holds `awdl*` and `llw*` on macOS.
On Linux it holds the names `docker*`, `veth*`, `virbr*`, and `br-*`. A device of the tun or tap type is a tunnel, not a noise interface.
On Windows it holds the virtual adapters without a connector. A Windows adapter whose description names TAP, Wintun, WireGuard, or VPN is a tunnel, not a noise interface.
On Linux and on Windows, an interface that holds a global address on either side of the delta is never noise.
A delta is also not noise when it flips `have_v4` or `have_v6`, or when it carries a time jump.
A noise delta runs no reconcile work.
ctrld starts no `scutil` process, reads no PF rule, discovers no tunnel, refreshes no VPN DNS, and schedules no delayed recheck for it.
A delta that touches a hardware port and a noise interface in the same callback is not noise.
The PF watchdog keeps its own 30 s timer, so it still tests the PF rules during a delta storm.

Each noise delta logs one debug line. The first noise delta of a storm also writes a journal line with `count` 1.
While the storm lasts, one journal line of the same name arrives every 10 minutes, with the count of that window.
AirDrop in the Finder is the common source of such a storm on macOS.

### DNS configuration poll (macOS)

ctrld polls `scutil --dns` on macOS only. The first poll runs at start.
The poll runs every 15 s for 10 minutes after a network change, a wake, or the end of a recovery.
Each of these three events starts the fast cadence at once, even while the poll waits.
At rest the poll runs every 5 minutes. Each changed resolver of a poll gives one `DNS configuration changed` event.

### Change-only lines

These lines log at debug level on change only. Each one carries `repeats`, the number of equal results before it:

- `Got system nameservers`
- `Final available nameservers`
- `pf anchor intact`
- `discovered active tunnel interfaces`
- `VPN DNS refresh completed`

### PF anchor list (macOS)

A `PF anchor list changed` event reaches the journal when its reason, its anchor list, or `pf_enabled` differs from the event before it.
The field `pf_since` is no part of that test, because the uptime of pf grows between two reads of one state.
A failed read of the anchor names gives `anchors_known` false and no anchor list.

### Host woke

ctrld writes one `Host woke` event per wake. Two sources that report the same wake inside 30 s give one event.
The macOS wake detector runs in DNS intercept mode only. Outside that mode, and on Windows and Linux, the netmon delta is the only source.
The netmon source knows no gap, so its report waits 8 s for the detector. A detector report inside that hold gives the event, with `gap_known` true and the length of the sleep in `gap_ms`. Without a detector report, the netmon report goes out with `gap_known` false and no `gap_ms`. Every later report of the same wake is dropped.

### Query health

ctrld grades the query path over a window of 15 minutes and reads the window every minute.
Each failed client query counts one failure, whatever number of upstreams that query tried.
`failures_by_class` keeps one count per failure class. The class `internal_domain` holds the failures of an Internal Domain resolver.
The grade leaves the class `internal_domain` out, and `upstreams_down` counts no Internal Domain resolver.
A laptop away from the company network cannot reach these resolvers. Without this rule the grade stays degraded for the whole day.
A change of the class reports after it holds for two reads of the window.

## Transitions and recovery

`Network transition` events include a `transition_id`, affected interface, default route, and stored source addresses before and after the callback.
The outcome identifies an accepted, ignored, superseded, snapshot_superseded, or unusable change.
A callback whose state read a newer snapshot gives the outcome `snapshot_superseded` at debug level with `transition_id` 0, and it gives no interface event.
Newer accepted changes supersede pending recovery. Ignored changes do not cancel accepted recovery.
Source commits validate addresses against the current network state.
Netmon does not order minor callbacks within one major cache epoch.
For minor callbacks and late major callbacks in that epoch, ctrld reads current interface addresses and flags.
This read does not change host DNS. A failed read defers source writes, but reconciliation continues.

`Removed stale resolver source` is a warning only when ctrld removes an invalid address.
The warning gives the reason. Every warning enters the journal, so it stays on disk after a debug rotation and after a restart.
`Recovery begin` and `Recovery end` connect the transition to a `recovery_generation`, reason, outcome, and elapsed time.
Only the first upstream failure in each recovery produces a bounded summary.
Every recovery outcome enters the journal.
A canceled recovery and a recovery with a failure log at warn level.
For the outcome `superseded`, `intercept_target_action` is `unchanged` and `bypass_active` is false. The recovery that follows owns both of them. The outcome `failed` means that the preparation of the recovery reported an error, and the event is at warn level.

These summaries exclude upstream URLs and queried names.
Each PF probe records the recovery generation at its start.
A later recovery cannot receive credit for an earlier probe.

### Cancellation event migration

On `master`, `Recovery end` with `outcome=canceled` replaces `Recovery failed; DNS settings remain removed`.
Update support runbooks and log searches to use the structured event.
The cancellation event alone does not prove that interface DNS remains removed.

Note: On the 1.x (`v1.0`) line, the previous message was `Recovery canceled; DNS settings remain removed`.

### OS-triggered recovery scope

An OS-only policy failure does not establish that configured DNS is unavailable.
Before starting OS-triggered recovery, ctrld checks its configured non-OS upstreams, excluding generated Internal Domain resolvers.
If any candidate is not marked down, it leaves shared recovery state and DNS settings unchanged.
The skipped trigger still refreshes in-memory OS-resolver discovery, at most once per 10 seconds while OS failures continue. Concurrent triggers do not queue duplicate discovery work.
This read preserves the existing resolver when discovery yields no nameservers. It does not clear the OS failure state; a successful OS query does that.
It does not remove interface DNS, reload interception rules, or enable bypass. A network change is not required for this refresh.
`Recovery skipped: configured upstream is not marked down` enters the journal with `healthy_upstream`, the candidate that admitted the skip. Generated IDs are retained; operator-defined keys are redacted to `upstream.custom`.
An unchanged candidate is journaled at most once per 5 minutes, rather than once per failed query. A changed candidate is journaled immediately when no refresh is in progress.
If all candidates are down, it uses that same pool for recovery probes instead of waiting only for OS DNS. The recovery still refreshes OS discovery initially, but only configured candidates can end it; the OS-only periodic probe/reinitialization loop is not part of that pool.
With no such configured candidates, it retains OS-only recovery.
`Recovery begin` includes `probe_upstreams` so the exit condition is visible in the journal.

This is a configured pool, not a reconstruction of every listener's effective default route.
Custom configurations can include policy-only or unused upstreams, and an untested upstream is not marked down.
Ordinary upstream-failure and network-change admission and candidate selection are unchanged.
A success racing with admission can still cause brief bypass; probing the configured pool prevents the old OS-only wait from persisting.
The original OS policy remains OS-routed.

### DNS-target decision failures (macOS)

`intercept DNS target: decision unavailable; DNS unchanged` retains the first discovery failure and changes to that condition.
Identical consecutive failures are suppressed, even if recovery IDs change.
A later `decision available again` event closes the episode and reports the cumulative `repeat_count`.
Do not add repeat counts from separate events in the same episode.

These events include the interface/service, discovery stage, bounded error class, target ownership before/after, and correlation IDs captured before discovery.
`failure_recovery_generation` and `failure_transition_id` identify the episode's first failed decision.
Raw error detail remains in the debug stream, not the journal fields.
A stage can be `system_discovery`, `default_route`, `interface_lookup`, `service_lookup`, `static_dns`, or `dhcp_dns`.
An error class can be `unavailable`, `timeout`, `canceled`, `permission_denied`, `command_failed`, or `read_failed`.

A DHCP error is not an empty DNS result and never authorizes a DNS write.
Resolution means discovery can make a decision again, not that a DNS write or client lookup succeeded.
`action` describes the change in tracked target ownership; it is not independent proof of an OS write.
The target's existing set/remove events still report those operations.
The journal retains these decisions separately from the bounded debug upload.

## PF probes (macOS)

`DNS intercept probe result` includes these fields:

- `probe_id` and `recovery_generation`
- Numeric `resolver_target` and `resolver_family`
- `stage`, bounded `error_code`, and `outcome`
- `repair_eligible`, `repeated_results`, and elapsed milliseconds

A changed unsuccessful condition produces a warning. The condition consists of the stage, error code, outcome, and target.
Equal results stay at debug level. The next changed condition includes the preceding repeat count.
The first restored receipt also produces a warning, which enters the journal. This event prevents an older failure from appearing current.
Normal receipts and shutdown cancellation stay at debug level.
The journal budget is finite and the journal rotates by size. It does not keep these events without a limit.

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
