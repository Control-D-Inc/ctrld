# SPEC: Stable customer-visible provisioning failure codes

Issue: [#586](https://gitlab.int.windscribe.com/controld/clients/ctrld/-/issues/586)
Requested by: Catt Garrod (@catt). Scope expanded by: Anthony Wong (@anthony).

## 1. Objective

Terminal provisioning failures in ctrld — bootstrap/API setup, listener
binding, and service installation/startup — must produce a stable,
support-facing failure identifier that survives process exit and reaches
both manual CLI users and MDM-driven installs. A customer or admin reports
one code; Support maps it to a scenario and a next action without asking
for reruns or verbose logs.

Motivating incident (v1.5.5, macOS): provisioning reached the Control D
API, then died with only `FTL listener.0 could not find available listen
ip and port`. The per-address UDP/TCP bind errors existed only at Info
level in an in-memory logger and vanished on exit. The macOS pkg
`postinstall` discards ctrld's stdout/stderr entirely and judges success
by plist existence, so nothing useful reached the MDM log.

**Users:** end customers and IT admins reporting failures; Support agents
triaging them; MDM/RMM operators reading installer logs.

### Failure contract (agreed design)

Three surfaces, all carrying the same identifier:

1. **Result file** — on terminal provisioning failure, ctrld writes a
   small redacted JSON file (atomic write: temp + rename) in the ctrld
   home directory (same base dir as the internal `ctrld.log`,
   via `absHomeDir`). Removed/overwritten on later successful
   provisioning so stale failures don't mislead. Schema:

   ```json
   {
     "version": 1,
     "timestamp": "2026-08-18T12:00:00Z",
     "stage": "listener",
     "code": "LISTENER_BIND_FAILED",
     "exit_code": 41,
     "message": "could not find available listen ip and port",
     "detail": {
       "attempts": [
         {"addr": "127.0.0.1:53", "proto": "udp", "os_error": "address already in use"}
       ]
     }
   }
   ```

   `detail` is bounded (cap recorded bind attempts; cap string lengths)
   and redacted by construction: no provisioning tokens, resolver IDs,
   config contents, or unrelated host data.

2. **Exit code + final stderr line** — the installer-facing command
   (`ctrld start`, and `ctrld run` when run manually in the foreground)
   exits with a stage-scoped code and prints one final line containing
   the string code and stage, e.g.
   `provisioning failed: stage=listener code=LISTENER_BIND_FAILED (exit 41)`.

3. **Installer log (MDM path)** — `scripts/pkg/postinstall` stops
   discarding the signal: it captures `ctrld start`'s output to a
   private temp file, extracts only the fixed-charset identifier line
   (`stage=[a-z]* code=[A-Z_]* (exit [0-9]*)` — structurally unable to
   carry the token), and echoes it with the exit code into the
   installer log. The result file's `message`/`detail` fields are
   deliberately never surfaced there. The plist-existence check remains
   the final success gate.

### Identifier format

- **Primary identifier: stable string codes.** Initial set —
  bootstrap: `API_UNREACHABLE`, `API_REJECTED`, `API_DEVICE_INVALID`;
  listener: `LISTENER_BIND_FAILED`, `LISTENER_CONFIGURED_ADDR_UNAVAILABLE`;
  service: `SERVICE_INSTALL_FAILED`, `SERVICE_START_FAILED`,
  `SERVICE_SELFCHECK_FAILED`. Codes are append-only; renames are new
  codes plus a deprecation note in the mapping doc.
- **Secondary: stage-scoped process exit codes** as a coarse machine
  signal: bootstrap 30–39, listener 40–49, service install/start 50–59.
  Each string code owns one exit code. Existing contracts are untouched:
  `ctrld status` 0–3, deactivation-pin 126, success 0.
- One underlying failure maps to one code on every path (manual CLI and
  MDM), on both branches.

### Propagation (daemon → installer)

The listener/bootstrap fatals fire inside the daemon process
(`ctrld run` under launchd/systemd/SCM), not in `ctrld start`. The
daemon writes the result file before exiting; the existing log-socket
exit notification (`notifyExitToLogServer`) already unblocks `ctrld
start`'s self-check. `ctrld start` then reads the result file, prints
the identifier, and exits with the mapped stage exit code. The daemon's
own exit-status semantics toward service managers are preserved —
in particular the deliberate exit-0 on permanent API rejection that
protects the restart-policy budget; the result file carries the failure
identity in that case.

### Support mapping

`docs/provisioning-failure-codes.md` in this repo: one row per code —
code, stage, exit code, failure scenario, next safe troubleshooting
action or evidence request. Updated in the same MR whenever a code is
added or changed.

### Branch scope

Full implementation on **both** `v1.0` (release line for v1.5.5) and
`master`. The branches diverge heavily (`v1.0`: zerolog fork,
`commands.go`, `service_status.go`, macOS pkg scripts; `master`: zap,
inline commands, no pkg scripts), so this is one shared contract
(codes, exit-code ranges, file schema, doc) implemented twice, as two
MRs referencing #586.

## 2. Commands

- Build: `go build ./...`
- Test: `go test ./cmd/cli/...` (full: `go test ./...`)
- Vet: `go vet ./...`
- Branch workflow: feature branch off `v1.0` for the v1.0 MR; separate
  feature branch off `master` for the port MR. Rebase, never merge the
  base branch in.

## 3. Project structure

New and touched files on `v1.0` (master port mirrors the same contract
at its equivalent emission points in its `cli.go`):

- `cmd/cli/provision_result.go` (new) — stage + code enums, exit-code
  mapping, result-file schema, atomic write/read/clear helpers,
  bounded/redacted detail builders. Pattern follows `service_status.go`
  (small file: named constants + classifier + dedicated tests).
- `cmd/cli/provision_result_test.go` (new).
- `cmd/cli/cli.go` — emission points: `run()` bootstrap failure branches
  (permanent rejection, invalid-device, fatal fetch), and
  `tryUpdateListenerConfig` / `tryUpdateListenerConfigIntercept` fatals,
  which now record per-attempt `{addr, proto, os_error}` bind detail.
- `cmd/cli/commands.go` — `initStartCmd`: doTasks install/start failures
  and the self-check failure branch read the result file, print the
  identifier, and exit with the stage code (replacing bare `os.Exit(1)`
  on those paths).
- `scripts/pkg/postinstall` — propagate exit code + result-file contents
  into the installer log (v1.0 only; master has no pkg scripts).
- `docs/provisioning-failure-codes.md` (new) — support mapping.

## 4. Code style

- Per repo conventions and global rules: guard clauses, small functions,
  descriptive names, explicit error handling — never weaken existing
  handling (e.g. keep the permanent-rejection exit-0 rationale intact).
- Comments only for non-obvious constraints (e.g. why the daemon must
  still exit 0 on permanent rejection), simple-english, self-contained —
  no issue/MR references in code.
- Match each branch's logging idiom: zerolog fork on `v1.0`, zap on
  `master`. No new dependencies.
- Conventional Commits; MR titles in simple-english; both MRs reference
  #586 (release-line MR carries `Closes #586`).

## 5. Testing strategy

Test-first where the harness allows. Coverage required by the issue:

- **Code/mapping unit tests** — every string code maps to exactly one
  stage and one in-range exit code; ranges don't collide with existing
  contracts (0–3 status, 126 pin).
- **Result file round-trip** — write/read/clear; atomic write; stale
  file removed on success.
- **Redaction** — serialize a result built from inputs containing a
  provision token, resolver ID, and config content; assert none appear.
- **Listener bind failure (regression test for the incident)** — occupy
  a port, drive the listener-config path to exhaustion, assert the
  result records `LISTENER_BIND_FAILED` with attempted address, UDP/TCP
  operation, and OS error (`address already in use`-class).
- **Bootstrap failures** — mock API: permanent 4xx → `API_REJECTED`;
  invalid-device 40402 → `API_DEVICE_INVALID`; unreachable →
  `API_UNREACHABLE`.
- **Service install/start/self-check failures** — injected task
  failures assert code selection and `ctrld start` exit code.
- **MDM surface** — shell-level check of `postinstall` failure branch
  (result file present → correct log line and exit), aligned with the
  existing `test-scripts/` approach; manual pkg verification steps
  documented in the MR.
- Both branches: the shared contract tests exist on both; branch-specific
  emission tests match each branch's structure.

## 6. Boundaries

**Always:**
- Redact tokens, resolver IDs, config contents, host data from every
  customer-visible surface (result file, stderr line, installer log).
- Preserve existing exit-code contracts (`ctrld status` 0–3, pin 126)
  and the daemon's service-manager-facing exit semantics.
- Bound all recorded detail (attempt counts, string lengths).
- Keep codes append-only once merged.

**Ask first:**
- Changing the daemon's (`ctrld run` under a service manager) exit codes
  or restart-relevant behavior beyond writing the result file.
- Adding any persisted file outside the ctrld home directory.
- Expanding scope to runtime (post-provisioning) failures — this ticket
  owns terminal provisioning failures only.

**Never:**
- Print or persist the provisioning token (the reason postinstall
  discards output today — the replacement surface must stay token-free).
- Auto-detect or kill conflicting processes (explicitly out of scope).
- Break `ctrld status`'s documented exit-code contract.
