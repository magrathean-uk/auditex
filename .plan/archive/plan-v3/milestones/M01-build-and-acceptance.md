---
id: M01
name: build-and-acceptance
weight: 15
status: done
---
# M01 build-and-acceptance
Starts after M00. Closes the two release-process gaps 1.3.0 shipped with: v2 DEC-019 (plain `make dist` not byte-reproducible) and v2 DEC-017 (full v3.9.1 replay waived).

## Goal
Plain `make dist` is byte-reproducible and `scripts/check-reproducible-build.py` proves byte identity for both the wheel and the sdist. The v3.9.1 replay kit is located on this Mac, hash-verified and kept in the Auditex machine records folder outside the public repo (G, DEC-001), and one local command, `make acceptance`, runs the full value-rule replay and the explainer acceptance suite, which pass on `main`.

## Definition of Done
- [x] Two plain `make dist` builds of the same clean commit give a byte-identical wheel and a byte-identical sdist, and the check proves both: `.venv/bin/python scripts/check-reproducible-build.py && .venv/bin/python -m pytest tests/test_check_reproducible_build.py`
- [x] `make acceptance` runs the full v3.9.1 replay (26,898 vectors, pinned hashes) and the explainer acceptance suite and passes on `main`: `make acceptance` (evidence: M01-T04 on b3fc70f, replay 1 passed 0 skipped, explainer 6 passed; .plan/work/M01-T04/result.md)
- [x] The runbook documents the acceptance run and its kit variable, and no doc names the stale variable: `grep -q 'AUDITEX_TEST_VALUE_RULE_VECTORS_V391' docs/development/runbook.md && ! git grep -q -E 'AUDITEX_TEST_VALUE_RULE_VECTORS([^_]|$)' -- docs README.md`
- [x] Review: the runbook build and acceptance sections say exactly what `make dist`, `scripts/check-reproducible-build.py` and `make acceptance` do (terra read-through recorded in `.plan/work/M01-T04/result.md`) (evidence: M01-T04 read-through verdict exact)
- [x] Every acceptance run verifies all three pinned kit hashes (vectors, A2 vectors, A2 overrides) and fails on a wrong companion file: `.venv/bin/python -m pytest tests/test_value_rules_replay.py -k kit_hashes`
- [x] `make acceptance` refuses to run without the kit and names the variable, whether it is unset or points at a missing file: `! env -u AUDITEX_TEST_VALUE_RULE_VECTORS_V391 make acceptance >"$TMPDIR/acc-unset.log" 2>&1 && grep -q AUDITEX_TEST_VALUE_RULE_VECTORS_V391 "$TMPDIR/acc-unset.log" && ! env AUDITEX_TEST_VALUE_RULE_VECTORS_V391="$TMPDIR/no-such-kit/vectors.jsonl" make acceptance >"$TMPDIR/acc-missing.log" 2>&1 && grep -q AUDITEX_TEST_VALUE_RULE_VECTORS_V391 "$TMPDIR/acc-missing.log"`
- [x] Review: an other-vendor review approves the plan v3 merge of M01-T01 (Tier A: release build) at the exact merged head (ARCHITECTURE.md review binding): `T=M01-T01; c=$(git log v1.3.0..HEAD --format=%H -1 --grep="^Plan-Task: $T\$") && test -n "$c" && s=$(git log -1 --format=%B "$c" | sed -n "s/^Plan-Review: REV-$T approve \([0-9a-f]\{12,40\}\)\$/\1/p") && test -n "$s" && grep -qE "^[[:space:]]*(summary: )?reviewed: $s" ".plan/work/REV-$T/result.md" && grep -qE '^[[:space:]]*(summary: )?verdict: approve' ".plan/work/REV-$T/result.md"` Orchestrator check at close (ARCHITECTURE.md provider binding): the dispatch record names a launcher of the other vendor from the author's.

## Tasks
| id | title | owner | size | tags | status |
|---|---|---|---|---|---|
| M01-T01 | Make plain make dist byte-reproducible and check sdist bytes | codex | M | - | done |
| M01-T02 | Locate and hash-verify the v3.9.1 replay kit | luna | S | - | done |
| M01-T03 | Add make acceptance and the runbook acceptance section | terra | S | - | done |
| M01-T04 | Run the acceptance suites on main | luna | S | - | done |

## Acceptance criteria
### M01-T01 Make plain make dist byte-reproducible and check sdist bytes
- `make dist` pins `SOURCE_DATE_EPOCH` to the commit time of `HEAD` when the caller has not set it, and normalises the sdist (gzip header mtime, tar member mtime, owner, group, mode and order) so the archive bytes depend only on the commit.
- `scripts/check-reproducible-build.py` builds twice through plain `make dist` (no `SOURCE_DATE_EPOCH` in its environment) into separate directories and compares the wheel bytes and the sdist bytes; it exits non-zero and names the artefact on any difference. The member comparison may stay as a diagnostic.
- `tests/test_check_reproducible_build.py` gains a case where two sdists with identical members but different gzip headers are reported as different.
- `make release-archive` and `bash scripts/release-smoke.sh dist "$TMPDIR/auditex-release-smoke"` still pass; the runbook release section (`docs/development/runbook.md`, build lines only) states the byte-identity guarantee.
- verify: `.venv/bin/python -m pytest tests/test_check_reproducible_build.py && .venv/bin/python scripts/check-reproducible-build.py && make release-archive && bash scripts/release-smoke.sh dist "$TMPDIR/auditex-release-smoke"`
- files: `Makefile` (dist target only), `scripts/check-reproducible-build.py`, `tests/test_check_reproducible_build.py`, `docs/development/runbook.md` (build lines only)

### M01-T02 Locate and hash-verify the v3.9.1 replay kit
- Searches this Mac only (repository, machine work and records folders, the 4TB); no downloads, paid runs or external hosts (v2 DEC-017).
- Found: `vectors.jsonl`, `a2-vectors.jsonl` and `a2-label-overrides.jsonl` match the sha256 pins and line counts in `tests/test_value_rules_replay.py`; the kit is copied unchanged to the Auditex machine records folder on the internal disk (G, DEC-001) and the copy is hash-checked again; no launchd or other scheduled job is created. The location is recorded outside the public repo; `result.md` names only the variable and the hashes.
- Not found or hashes differ: the task stops and reports; the orchestrator raises the G decision (regenerate offline or keep the replay waived) and M01 waits on it.
- verify: `V="$AUDITEX_TEST_VALUE_RULE_VECTORS_V391"; test -f "$V" && d=$(dirname "$V") && printf '%s  %s\n' 3515b6facbac73091ef43bfa51b746e9265ac508909103ffcc016a5dab92cf4e "$V" 0351259550c0a87d27d65cfac8f98b8547334cbd1d94321af244ad06b622ac0b "$d/a2-vectors.jsonl" 74639d1775267bb7d8e3d7cdf777b5eac4449e636ec383c16e21f79b3d8e1fa1 "$d/a2-label-overrides.jsonl" | shasum -a 256 -c -`
- files: `.plan/work/M01-T02/result.md` (no repository file changes)

### M01-T03 Add make acceptance and the runbook acceptance section
- Runs after M01-T01 merges (both own `Makefile` and the runbook); M02-T03 and every later writer of `Makefile`, the runbook or `docs/guides/model-development.md` runs after this task merges.
- `make acceptance` requires `AUDITEX_TEST_VALUE_RULE_VECTORS_V391`; when it is unset or the file is missing it exits non-zero with a message naming the variable (it never silently skips the replay). It then runs `-m value_rule_acceptance` and the `explainer_acceptance` recipe from `tests/explainer_checks/README.md` serially and exits non-zero on any failure.
- The full replay test checks the sha256 of all three kit files (`vectors.jsonl`, `a2-vectors.jsonl`, `a2-label-overrides.jsonl`) against the pins before replaying, through one helper; new `kit_hashes` tests in `tests/test_value_rules_replay.py` prove, with `tmp_path` files, that a wrong hash in any of the three fails and that the helper never skips. Today only `vectors.jsonl` is hashed (`tests/test_value_rules_replay.py:227`).
- `docs/development/runbook.md` gains an acceptance section: the variable, the three pinned hashes, the command and when to run it (each milestone close and the release gate); `tests/explainer_checks/README.md` points to `make acceptance`.
- `docs/guides/model-development.md:148` names `AUDITEX_TEST_VALUE_RULE_VECTORS_V391` (unless M02 has already removed the guide).
- verify: `make -n acceptance >/dev/null && .venv/bin/python -m pytest tests/test_value_rules_replay.py -k kit_hashes && ! git grep -q -E 'AUDITEX_TEST_VALUE_RULE_VECTORS([^_]|$)' -- docs README.md && ! env -u AUDITEX_TEST_VALUE_RULE_VECTORS_V391 make acceptance >"$TMPDIR/acc-unset.log" 2>&1 && grep -q AUDITEX_TEST_VALUE_RULE_VECTORS_V391 "$TMPDIR/acc-unset.log" && ! env AUDITEX_TEST_VALUE_RULE_VECTORS_V391="$TMPDIR/no-such-kit/vectors.jsonl" make acceptance >"$TMPDIR/acc-missing.log" 2>&1 && grep -q AUDITEX_TEST_VALUE_RULE_VECTORS_V391 "$TMPDIR/acc-missing.log"`
- files: `Makefile` (new acceptance target only), `docs/development/runbook.md` (new acceptance section only), `tests/explainer_checks/README.md`, `docs/guides/model-development.md` (line 148 only), `tests/test_value_rules_replay.py` (kit hash helper and `kit_hashes` tests only), and the stale `AUDITEX_TEST_VALUE_RULE_VECTORS` reads in `tests/test_value_rules_{contract,s4,s5,s6,s7,s8,s9,vectors}.py` (variable name only; INV3 finding: switched to the `_V391` name where those tests pass on the v3.9.1 kit, listed in `result.md` where they do not)

### M01-T04 Run the acceptance suites on main
- Precondition: M01-T01 and M01-T03 merged; M01-T02 reported the kit found and verified.
- In a detached worktree at the `main` head, under `run-job`, behind the load rule, `make acceptance` runs with the variable pointing at the verified kit copy.
- `result.md` records the commit, the three kit hashes the run verified, the pass, skip and fail counts per suite (the replay must report zero skips) and the terra read-through of the runbook sections (DoD item 4); on failure it names the failing ids and stops (no fixes; a debug task follows).
- verify: `make acceptance`
- files: `.plan/work/M01-T04/result.md` (read-only run; no repository file changes)
