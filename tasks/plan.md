# Plan: provisioning failure codes (issue #586)

Spec: SPEC.md. Baseline: `ac0e6aed` on `v1.0`.
Branches: `issue-586` (off `v1.0`), `issue-586-master` (off `master`).
Two MRs, both referencing #586; the `v1.0` MR carries `Closes #586`.

## Shared contract (fixed here so parallel tasks cannot diverge)

| Code | Stage | Exit |
|---|---|---|
| `API_UNREACHABLE` | bootstrap | 30 |
| `API_REJECTED` | bootstrap | 31 |
| `API_DEVICE_INVALID` | bootstrap | 32 |
| `LISTENER_BIND_FAILED` | listener | 41 |
| `LISTENER_CONFIGURED_ADDR_UNAVAILABLE` | listener | 42 |
| `SERVICE_INSTALL_FAILED` | service | 51 |
| `SERVICE_START_FAILED` | service | 52 |
| `SERVICE_SELFCHECK_FAILED` | service | 53 |

- Result file: `provision_result.json` in the ctrld home dir (same
  resolution as the persisted internal log: `absHomeDir` on v1.0, the
  `userHomeDir`-based equivalent on master). Atomic write (temp +
  rename in the same dir). Cleared when provisioning succeeds.
- Result schema (version 1): `version`, `timestamp` (RFC3339, UTC),
  `stage`, `code`, `exit_code`, `message`, optional `detail.attempts[]`
  of `{addr, proto, os_error}`; attempts capped at 12 entries, every
  string capped at 256 chars.
- Identifier line, exact format (greppable, token-free by
  construction): `provisioning failed: stage=<stage> code=<CODE> (exit <N>)`.
- Redaction: results are built through a constructor that takes the
  secrets in scope (cd UID, provision token) and strips them from every
  field. Messages come from our own summaries plus OS error strings,
  never raw config or API bodies.
- Exit seam: `provisionExit = os.Exit` package var so tests can stub
  process exit. Emission helper `failProvision(...)` writes the file,
  logs the identifier line, calls the notify func, then exits with the
  stage code. Nonzero exit is preserved everywhere the daemon exits
  nonzero today; the deliberate clean return on permanent API rejection
  stays a clean return (result file only).

## Dependency graph

```
A1 (contract module + doc, v1.0)          D1 (master port)
  ├─► B1 daemon emissions (cli.go)          depends on: contract table
  ├─► B2 start-side (commands.go+service.go)  (from A1) + C1 verified
  └─► B3 postinstall (scripts, tests)          implementation as reference
        └─► C1 v1.0 checkpoint ────────────► D1 ─► E1 final checkpoint
```

## Group A — serial, runs inline (1 task)

### A1. Contract foundation on `issue-586`
Create branch `issue-586` from `v1.0`. New files:
`cmd/cli/provision_result.go`, `cmd/cli/provision_result_test.go`,
`docs/provisioning-failure-codes.md`.

Module contents: stage type + the 8 code constants + exit-code map;
`ProvisionResult` struct per schema; bounded/redacting constructor;
atomic `writeProvisionResult` / `readProvisionResult` /
`clearProvisionResult`; identifier-line formatter; `provisionExit`
seam; `failProvision` helper. Doc: full table — code, stage, exit,
failure scenario, next safe troubleshooting action / evidence request.

Tests (RED first): every code maps to exactly one stage and one
in-range exit code (30–39/40–49/50–59); no collision with 0–3
(`ctrld status`) or 126 (pin); file round-trip; atomic overwrite;
clear; redaction (a result built from inputs containing a fake token
and cd UID serializes without them); attempts/string caps enforced;
identifier line matches the exact format.

Acceptance: `go build ./...` and `go test ./cmd/cli/` green; doc rows
exactly match the constants.

## Group B — parallel Workflow fan-out, one subagent per task, worktree isolation, branched from `issue-586` after A1

### B1. Daemon emissions in `cli.go`
- Bootstrap branches in `run()` (`cli.go:339-372`):
  - permanent rejection (`permanentAPIRejection`): write `API_REJECTED`
    result (HTTP status + our own summary, no raw API body), keep the
    existing clean return and its comment.
  - invalid device (`controld.InvalidConfigCode`): write
    `API_DEVICE_INVALID` before `uninstallInvalidCdUID`.
  - fatal fetch: write `API_UNREACHABLE`, replace
    `cdLogger.Fatal()` with error log + identifier line +
    `failProvision` exit 30 (still nonzero for the service manager).
- Listener (`tryUpdateListenerConfig`, `tryUpdateListenerConfigIntercept`):
  - record every failed bind attempt `{addr, proto, os_error}` —
    capture UDP and TCP errors separately in `tryListen` (keep
    `errors.Join` for control flow), cap per contract.
  - exhaustion fatal (`cli.go:1639`) and converged-random fatal
    (`cli.go:1720`) → `LISTENER_BIND_FAILED` exit 41 with attempts.
  - no-fallback-allowed fatal (`cli.go:1652`) and intercept-mode fatals
    (`cli.go:1452,1467`) → `LISTENER_CONFIGURED_ADDR_UNAVAILABLE`
    exit 42 (fallback-exhausted intercept fatal stays
    `LISTENER_BIND_FAILED`).
  - all fatals keep calling the notify func first; final message
    includes the code string.
- Clear the result file at the point provisioning is known good
  (after `updateListenerConfig` succeeds in `run()`).

Tests (RED first): occupy a UDP+TCP port, drive the listener path to
exhaustion with the exit seam stubbed, assert the result file has
`LISTENER_BIND_FAILED`, the attempted address, both protocols'
`os_error` (`address already in use` class); pure mapping test
API error → code (permanent 4xx → `API_REJECTED`, 40402 →
`API_DEVICE_INVALID`, network error → `API_UNREACHABLE`) following
`cli_preflight_test.go` patterns.

Acceptance: only `cmd/cli/cli.go` + new/extended tests touched;
`go build ./... && go test ./cmd/cli/` green.

### B2. `ctrld start` reporting in `commands.go` + `service.go`
- Add `doTasksE` (returns failed task name + error; `doTasks` keeps
  its signature and delegates).
- Fresh-install path (`commands.go:618`): failed `Install` task →
  `SERVICE_INSTALL_FAILED` (write result, print identifier line, exit
  51); failed `Start` task → `SERVICE_START_FAILED` (exit 52). This
  fixes the current fall-through that exits 0 on install failure.
- Existing-service path (`commands.go:528-543`): failure → 52 with the
  same reporting (replaces bare `os.Exit(1)`).
- Self-check failure branch (`commands.go:627-664`): keep the log
  drain and `uninstall(p, s)`; then read the daemon's result file —
  if present and stamped after this start attempt began, report its
  stage/code/exit (daemon identity wins: e.g. `LISTENER_BIND_FAILED`);
  otherwise write and report `SERVICE_SELFCHECK_FAILED` exit 53.
  Extract this into a testable helper (fabricated result files +
  stubbed exit seam).
- On successful start (self-check ok), clear any stale result file.

Tests (RED first): `doTasksE` failure attribution; helper precedence
(fresh daemon result wins; stale/missing falls back to 53); exit-code
selection per failed task.

Acceptance: only `cmd/cli/commands.go`, `cmd/cli/service.go` + tests
touched; build and package tests green.

### B3. postinstall MDM surface
- `scripts/pkg/postinstall`: capture `ctrld start` output to a
  `mktemp` file (chmod 600) instead of `/dev/null`; keep the plist
  check as the success gate; on failure, `grep -m1 '^provisioning
  failed: '` from the capture into the install log together with the
  exit code; delete the capture file always; never echo any other
  output line (token safety preserved by extracting only the
  fixed-format line).
- Shell test `test-scripts/darwin/test-postinstall-provision-failure.sh`
  (matching existing script conventions): stub `$CTRLD` that prints a
  fake token plus a valid identifier line and exits 41; assert the
  logged output contains stage/code/exit and not the token; assert
  success path unchanged. Runs without root.
- Update `docs/macos-pkg-mdm.md` where it documents the discard
  behavior/failure triage, and add the failure-code doc link.

Acceptance: shell test passes locally (`sh test-scripts/darwin/...`);
only `scripts/pkg/postinstall`, `test-scripts/darwin/`, `docs/`
touched.

## Checkpoint C1 — serial, after Group B merges

Merge order: B1, B2, B3 into `issue-586`. Then: `go build ./...`,
`go vet ./...`, `go test ./cmd/cli/...` (and full `./...`), run the B3
shell test, verify doc table == constants, and verify each spec
acceptance criterion has an implementation + test. Fix-forward any
merge fallout before Group D starts.

## Group D — serial (1 task, own worktree off `master`)

### D1. Master port on `issue-586-master`
Create `git worktree` with branch `issue-586-master` from
`origin/master`/`master`. Port with the v1.0 implementation as
reference, adapted to master's structure (zap-shaped logging idiom,
no `commands.go`):

- `cmd/cli/provision_result.go` + tests: identical contract table.
- Bootstrap: `run()` branches at master `cli.go:340-374` (same
  permanent-rejection clean return, invalid-device, fatal fetch).
- Listener: `tryUpdateListenerConfig` fatals at master
  `cli.go:1657/1667/1719`; intercept variant at `cli.go:1487/1502`;
  per-attempt capture (bind errors currently logged at Debug,
  `cli.go:1665`).
- Start side: `commands_service_start.go` — both `doTasks` call sites,
  self-check `default:` arm (`os.Exit(1)` ~line 370), same fall-through
  audit, same precedence logic; `doTasksE` in `service.go`.
- `docs/provisioning-failure-codes.md`: same table (omit
  pkg/postinstall-specific notes; master has no `scripts/pkg`).
- No postinstall work on master.

Tests mirrored from v1.0 where the structure allows.

Acceptance: in the master worktree, `go build ./...`,
`go test ./cmd/cli/...` green; constants table semantically identical
to `issue-586`.

## Checkpoint E1 — serial, final

- Cross-branch contract equality: compare code constants, exit codes,
  identifier-line format, result schema between the two branches.
- Full test suites on both branches.
- Both branches committed (per-task Conventional Commits); no pushes,
  no MRs yet — `/draft-review` is the next pipeline step.

## Execution notes

- Each parallel group runs as one Workflow fan-out, one subagent per
  task, `isolation: 'worktree'` so parallel edits never conflict;
  serial tasks (A1, C1, D1, E1) run inline (D1 manages its own
  master-based worktree).
- Every subagent follows RED → GREEN → regression → build and commits
  in its worktree; the orchestrator merges in dependency order and
  runs the full suite before the next group.
- Subagent prompts are self-contained: they carry the contract table
  and file anchors from this plan, not references to SPEC.md (worktree
  copies may not include untracked files).
