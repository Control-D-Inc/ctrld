# Target ownership safety (relates to #619)

The target cleanup record is not proof of actual service DNS. Reconciliation now reports a tracked/actual mismatch instead of returning an implicit already-installed decision. An external clear or IPv6-only edit does not authorize reinstalling a target; the record is retained to prevent repeated watchdog admission. Usable external IPv4 keeps the existing guarded cleanup path.

Ownership is written by atomic replacement before target installation. Failure refuses installation, rather than depending on a future restart to recover an untracked target. A failed DNS command may have partly mutated OS state, so its cleanup record is retained. Failed ownership-file removal also retains memory state and does not emit the target-removed success event.

On external edits, cleanup discards the stale saved-static backup before releasing the record. The full saved-static sweep skips a service with retained target cleanup state; unreadable/malformed ownership state conservatively skips the sweep. No unbounded retry, fatal exit, or machine-stop policy is introduced.

## Evidence and limits

- Linux-adapted Darwin tests execute the real target lifecycle and saved-static sweep with only OS boundaries replaced. New regression tests cover persistence failure before mutation, external edit through reconciliation/cleanup/full sweep, ownership clear failure, actual-vs-tracked discrepancy, and failed-cleanup sweep guards. Custom listener values are configured and assertions derive the target from the production selector.
- This is not native macOS PF/CLAT proof. Existing native CLAT admission/removal behavior still needs native validation on the integrated artifact; no PF rules or target selector were changed here.
- A missing target is not automatically repaired: external clearing and accidental loss cannot safely be distinguished from these observations. The diagnostic reports the uncertainty; it does not claim resolution.
- Once explicit cleanup releases a record, a later new admission uses the existing policy for IPv6-only static DNS. This is not a persistent per-service operator opt-out mechanism.
- Retaining cleanup state does not guarantee another cleanup attempt after process exit. The void shutdown API still cannot report aggregate stop failure to its caller; no guaranteed retry or issue closure is claimed.
- Startup/running-interface reset and callback shutdown ordering live in prog.go and are outside this patch. Persistence failure was not a universal restart orphan on the baseline: startup can rescue the current interface, while old/noncurrent-service cases are conditional.
- Network configuration commands are not compare-and-swap transactions. A concurrent external edit after the last read remains a native race; these tests do not prove otherwise. Atomic file replacement does not claim power-loss durability.
