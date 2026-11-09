## RESULT VAL-v3
status: done
summary:
verdict: gaps
reviewed: c3740c3c0ab63cad9c6dbf0d34f67c467935f929
Structure passes: 27 tasks, 48 DoD items, integer weights totalling 100.
Blocking gaps concern evidence availability, false-positive verification, sequencing and regression guarantees.
changes: none
verification:
- PASS: `percent.py --check`; task-field and evidence-suffix checks; ownership-map replay across 901 tracked non-plan files found no unmatched non-test paths or overlapping module globs.
- PASS: `gitleaks dir . --no-banner --redact`; `git diff --check`; working tree remains clean.
- FAIL: M01-T03 verification returned 0 despite the acceptance target being absent; M03-T01 verification returned 0 despite its removal list being absent.
- FAIL: M01/M02 review predicates accept existing approvals for unrelated plan-v2 commits.
- SKIPPED: builds, suites, acceptance execution, audit-deps and the taint script require filesystem writes. Existing evidence was inspected.
risks: stale approvals; replay input integrity; D5 performance evidence, detailed below.
questions_for_g: none needed to repair the plan.
### Findings

Numbered gaps:

1. `.plan/milestones/M00-foundation.md:18-22` cites `.plan/work/PLAN-v3/evidence.md`, absent from this commit. It exists only in the main checkout. Commit sanitised evidence and make referenced v3 inputs available to detached workers, or untick unsupported items and recalculate progress.

2. `.plan/milestones/M01-build-and-acceptance.md:18` and `M02-model-layer-retirement.md:21` accept old plan-v2 review files today. Use version-specific evidence paths and verify the exact reviewed SHA and reviewer provider against each new task.

3. `.plan/milestones/M01-build-and-acceptance.md:49` tests the exit status of the entire preceding chain, so any earlier failure produces success. Keep prerequisite checks outside the expected-failure assertion and check the missing-variable diagnostic separately.

4. `.plan/milestones/M03-cleanup-and-bootstrap.md:34` succeeds without its removal list because failed command substitution leaves `git ls-files` with no path arguments. Require a readable, non-empty list before validating every entry; apply the same protection to `M02-model-layer-retirement.md:36`.

5. `.plan/milestones/M01-build-and-acceptance.md:41,46` does not require each acceptance run to hash all three replay inputs. `tests/test_value_rules_replay.py:225` hashes only the main vectors file. Require all three pinned hashes on every run and assign ownership for that check.

6. `.plan/milestones/M02-model-layer-retirement.md:11,43` permits output changes named by the design, contradicting `.plan/master-plan.md:26`. Remove that exemption or obtain an explicit re-baseline; add a deterministic before/after output comparison to the DoD.

7. `.plan/milestones/M02-model-layer-retirement.md` and `M03-cleanup-and-bootstrap.md` assign removals without assigning `.plan/CLEANUP.md` updates. Add an orchestrator-owned closure item recording each deletion’s reason, reference evidence, approval and commit.

8. `.plan/milestones/M05-d5-name-masking.md:33,39-43` allows the harness to start while its measurement method is still being designed. Freeze that interface first; require a fixed person-bearing workload, explicit redacted profile and proof that matching runs during measurement.

9. `.plan/milestones/M02-model-layer-retirement.md` through `M05-d5-name-masking.md` omit the milestone-close acceptance checks promised in `.plan/BACKLOG.md`. Add `make acceptance` to their closure DoDs once M01 supplies it.

Sequencing risks:

- `.plan/master-plan.md:73-75`: M01 and M02 share `Makefile`, the runbook and model guide. Add explicit ordering between their writers.
- `.plan/milestones/M03-cleanup-and-bootstrap.md:8,42,48,55`: T02/T03 can both remove bootstrap copies, while T04 shares documentation with M02-T04. Give deletion one owner and add explicit predecessor tasks.

Missing DoD items:

- Deterministic retirement output comparison, complete cleanup-ledger evidence and M02-M05 acceptance runs, as specified in gaps 6, 7 and 9.

Top 3 uncovered risks:

1. `.plan/milestones/M01-build-and-acceptance.md:18`: reused review paths can make unrelated historical approvals appear to satisfy new Tier A work.
2. `.plan/milestones/M01-build-and-acceptance.md:37-46`: kit availability remains unresolved, and companion-file integrity is not enforced at every acceptance run.
3. `.plan/milestones/M05-d5-name-masking.md:38-43`: a harness without a frozen workload and verified masking activity can pass while missing the known D5 memory failure.
