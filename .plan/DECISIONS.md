# Decisions
<!-- ADR-lite. One entry per decision, newest last. Approver is G or auto (within the orchestrator's authority). -->

## DEC-001 Plan v3 adopted
- date: <UTC date of approval>
- status: proposed; G approved the scope in advance ("ok to all, continue dev until 100%") and answered the scope gate on 9 Nov 2026 (below); the remaining G gates are the M02 and M03 deletion lists, the D5 design and the yes naming 1.4.0
- decision: 100 percent is the 1.4.0 release built from plan v2's BACKLOG Next items, published on G's separate explicit yes naming 1.4.0 (D9), in seven milestones: M00 foundation (10), M01 build-and-acceptance (15), M02 model-layer-retirement (20), M03 cleanup-and-bootstrap (10), M04 boundary-scanners (10), M05 d5-name-masking (20), M06 release-1-4-0 (15). Re-baseline: plan v2 closed at 100 percent with 1.3.0 published; plan v3 opens at 4 percent against its own DoD (four M00 items pass, evidence committed in `.plan/work/PLAN-v3/plan-evidence.md`).
- G's answers (9 Nov 2026, approved): (1) D5 masks the names of everyone in the run's own directory records wherever they appear in shareable output, not only privileged users; (2) the divergent `tenant-bootstrap/azure_tenant_audit/` module copies are deleted through the deletion gate, keeping only the forwarder, and G approves the exact list; (3) the replay kit stays outside the public repo in the Auditex machine records folder, acceptance runs at each milestone close and at the release gate, and no launchd or other scheduled job is created; (4) the next release is 1.4.0 and its notes name the removal of the parked `model` command and the `model_train` extra; (5) 100 percent includes publication of 1.4.0 on G's separate explicit yes naming 1.4.0.
- orchestrator rulings (auto): repo-wide Ruff adopts the rule set and target version the pre-commit Ruff hook already uses (E4, E7, E9, F; target from `requires-python`), widening is BACKLOG; once `make dist` is byte-reproducible (M01) the release gate compares sdist bytes as well as wheel bytes.
- options: a) 1.4.0 from all BACKLOG Next items | b) a smaller 1.3.1 (reproducible build and acceptance only) with the retirement and D5 later | c) also pull live-tenant or Google baseline work in
- why: G's 9 Nov answer takes the Next items as the next release scope; each item closes a gap 1.3.0 shipped with (v2 DEC-004, DEC-011, DEC-017, DEC-019, D6).
- consequences: plan v2 decisions stay binding and are cited as "v2 DEC-nnn" (archive `.plan/archive/plan-v2/DECISIONS.md`); D6 (G, 7 Nov 2026) is recorded here for the first time: D5 is a redesign from `main` with bounded per-record matching, an HTML peak within `main` plus 15 percent and a privacy review by both providers. Removals wait on G's approval of each exact path list; the orchestrator records each gate as its own entry ("M02 deletion gate", "M03 deletion gate") and each approved path as a CLEANUP.md row. The model retirement changes no verdict, explainer output or bundle field; a needed change is a G re-baseline. Tier A reviews bind to the exact merged head through the merge trailer and the ledger. No hosted CI, no PyPI.
- approver: G

## DEC-002 auditex assess replaces the model assess command
- date: 2026-11-09
- status: approved
- decision: retiring the model layer adds a top-level `auditex assess <run-dir>` with the same `--policies` and projection flags (minus dry-run and model-endpoint options) and unchanged output files; it is the only writer of the rule-only SCuBA assessment behind report policy explanations.
- options: auditex assess | fold the assessment into auditex report
- why: keeps the shipped behaviour while the model subcommand goes.
- consequences: M02-T03 or M02-T04 adds the command; the 1.4.0 notes name the change.
- approver: G

## DEC-003 D5 masks names inside group and role names
- date: 2026-11-09
- status: approved
- decision: a person's full name is masked wherever it appears in shareable output, including inside group and role names.
- options: mask inside group and role names | keep them as a stated D3 limit
- why: matches "wherever they appear" (plan v3 DEC-001).
- consequences: one D3 test that kept group and role names verbatim changes.
- approver: G

## DEC-004 D5 pseudonyms keep the run-path salt in 1.4.0
- date: 2026-11-09
- status: approved
- decision: pseudonyms stay SHA-256 salted with the run path (deterministic per run, no bundle change); the confirm-a-guess limit is documented in the privacy reference; a keyed per-run scheme is a BACKLOG item.
- options: keep the run-path salt | keyed per-run secret now (bundle change)
- why: no bundle or contract change in 1.4.0.
- consequences: M05-T04 documents the limit.
- approver: G

## DEC-005 M02 deletion gate: model-layer removal list approved
- date: 2026-11-09
- status: approved
- decision: the 38 tracked paths in `.plan/work/M02-T01/removal-list.txt` (reviewed design, Codex approve at 52c0de3) are approved for removal in M02-T04, after M02-T03 re-homes the shared helpers and adds `auditex assess` (DEC-002).
- options: approve all 38 | hold
- why: model-layer-only paths; shipped assessment, report and bundle output are preserved and checked by the M02-T02 digests.
- consequences: each deletion is recorded in CLEANUP.md (M02-T06).
- approver: G

## DEC-006 M03 deletion gate: cleanup removal list approved, lab tools kept
- date: 2026-11-09
- status: approved
- decision: 30 of the 33 paths in `.plan/work/M03-T01/removal-list.txt` are approved for removal in M03-T02: the 25 drifted tenant-bootstrap module copies (forwarder kept, dependent tests updated), benchmarks/fake_graph_benchmark.py, scripts/tenant-audit-flow, assets/auditex-logo.png, requirements.txt and tenant-bootstrap/requirements.txt. The Dependabot entry is updated and docs/legal/third-party-notices.md line 65 is changed to say the dependencies are declared in pyproject.toml (G approved that change). tenant-bootstrap/scripts/run-auditor.sh, create-lab-populator-app.py and auth-lab-populator.py stay with the parked dummy-tenant kit.
- options: approve keeping the three lab tools | approve all 33 | hold
- why: unreferenced or duplicate paths; the lab tools may belong to parked kit work.
- consequences: each deletion is recorded in CLEANUP.md (M03-T05).
- approver: G

## DEC-007 Merge order for shared files, and the REASON_OUTSIDE line
- date: 2026-11-09
- status: approved
- decision: (1) M03-T02 and M05-T03 may merge before the M02 to M04 tasks their preconditions name. merge.sh rebases each branch onto current main and runs the full criteria verify there, and every later task that edits the same test, doc, redaction or writer files is cut from main after these merges, so those files are still edited one task at a time, in the order M03, M05, then M02 to M04. (2) The unused constant `REASON_OUTSIDE` in `src/azure_tenant_audit/output_redaction.py` (one line, no reader: `rg -nw` finds only its definition, M03-T01) is removed in M03-T02. It is a code line, not a path, so the path deletion gate (DEC-006) does not cover it; git history keeps it.
- options: merge in milestone order (holds M03-T02 and M05-T03 behind the model-layer removal) | rebase-and-verify order as above
- why: the preconditions exist to serialise edits to shared files; a clean rebase plus the full verify on the rebased head gives the same guarantee without idling finished work.
- consequences: M02-T03, M02-T04, M04-T01 and M04-T03 start from a main that already holds M03-T02 (and M05-T03 once merged); reviewers of those tasks see the earlier changes as base.
- approver: orchestrator

## DEC-008 Read-boundary scanner re-scoped after two repair rounds
- date: 2026-11-09
- status: approved
- decision: M04-T02 stops at 6e866b3 (AGENTS.md: two repair rounds, then re-scope). L1 to L4 are closed for every planted case from the v2 notes and three review rounds, under one fail-closed rule (a value reaching a launcher, importer, callee lookup or standard input counts as resolved only when proved literal). Three bypasses from the final review need in-repo code written to defeat the scanner: a local function that shadows a read-only hand-off name (`info`) and mutates its argument; a local function that shadows a transparent conversion (`list`); and an import binding that follows a literal assignment to the same name. They are named limits: M04-T03 states them in `docs/reference/security-privacy.md`, and BACKLOG Next holds the fix (treat any callee name the module rebinds as unresolved, and include import bindings in the binding union).
- options: a third repair round | re-scope with the limits documented
- why: the scanner guards our own source against accidental write or content-read calls; code review covers deliberate obfuscation, and each further round has found only more contrived cases.
- consequences: the M04-T02 criteria carry the limit clause below; the final Codex review judges 6e866b3 against it.
- approver: orchestrator
