# TODO: issue #586 provisioning failure codes

Groups run in order; tasks inside a parallel group run as one Workflow
fan-out (one subagent per task, worktree isolation).

## Group A (serial)
- [x] A1: contract module `cmd/cli/provision_result.go` + tests + `docs/provisioning-failure-codes.md` on branch `issue-586`

## Group B (parallel after A1)
- [x] B1: daemon emissions — bootstrap + listener paths in `cmd/cli/cli.go` + tests
- [x] B2: `ctrld start` reporting — `cmd/cli/commands.go`, `cmd/cli/service.go` (doTasksE, exit-0 fall-through fix, self-check precedence) + tests
- [x] B3: postinstall MDM surface — `scripts/pkg/postinstall`, shell test, `docs/macos-pkg-mdm.md`

## Checkpoint C1 (serial)
- [x] C1: merge B1→B2→B3 into `issue-586`, full build/vet/test, shell test, doc/constants parity, spec AC audit

## Group D (serial)
- [x] D1: master port on `issue-586-master` (contract module, cli.go emissions, commands_service_start.go, docs) + tests

## Checkpoint E1 (serial)
- [x] E1: cross-branch contract equality, full suites on both branches, commits tidy — stop before push/MR (`/draft-review` next)
