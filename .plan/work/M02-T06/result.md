## RESULT M02-T06
status: blocked
summary: Blocked on two conflicts between the amended criteria and the frozen kit, found by building and checking the full collected set in a scratch kit copy; real kit and repository unchanged.
summary: (1) Any file under heldout/collected fails the sealed M02-T02 `kit-check twins` (its heldout/ folder check is complete and skips only caches and notes), breaking `kit-check all`, M02-T03's verify and REV-M02-kit. Fixing it needs a fourth twins.py change or another folder.
summary: (2) `gpu-hours: heldout 0` fails `kit-check usage`: M02-T06 is not in the budget table's heldout row nor in the frozen usage.py stage list.
summary: Scratch build: kept 221/501 (identity 209, transformed 19, all reproduced by the pinned Rego), 77/102 policies, 120/314 cells, twins 0, agreement 221/221; deterministic rebuild.
changes: none in the kit or repository; .plan/work/M02-T06/{notes.md,notes-round1.md (round 1 notes renamed),progress.md,draft/} (work notes and draft code only)
verification: 1.4.0 wheel sha256 equals WHEEL_SHA256 pass; OPA sha256 equals pin pass; scratch `twins --heldout heldout/collected` with OPA pass (221/221); scratch `collected` pass; builder --check pass; heldout/tests 24 pass with the three changes; heldout/collected/tests 22/23 with three changes (the failure is conflict 1), 23/23 with the candidate fourth change; brief verify on the scratch kit with a draft result under the scratchpad and the candidate fourth change: pass; scratch `usage` on that result: fail (conflict 2); real-kit verify not run (blocked)
risks: Real-kit `kit-check all` already fails at `checks` (M02-T03 data not placed). | Leakage probe: nearest-neighbour decisive copy 147/221 (67 per cent) against 216/501 (43 per cent) sealed; REV-M02-kit should weigh it. | Frozen kitcheck rejects underscore keys; collected.py compares the eight state lines itself (no plan change).
questions_for_g: (orchestrator) Conflict 1, pick one. A (recommended): amend DEC-025 to allow a fourth two-line twins.py change, so that when it checks a folder it skips the subfolders FOLDER_TASKS names beneath it (only collected/ under heldout); those files stay verified complete by `twins --heldout heldout/collected` and by `collected`, which `kit-check all` runs (draft/twins-candidate-fourth-change.diff). B: move the set to a kit-root folder such as heldout-collected/, with no fourth change, but amend the M02-T06 files and verify lines, the DEC-025 (2) pair, the M02 review item, M02-T03's text and the airr-kit map row. Conflict 2: drop `gpu-hours: heldout 0` from M02-T06's criteria (recommended; CPU-only task outside the budget table), or add M02-T06 to the heldout row and the frozen usage.py.
### Findings
heldout-form: collected (scratch only; not sealed in the kit)
scratch-kept: 221/501 (identity 209, transformed 19; default_scuba_config 10, single_object_as_list 12)
scratch-kept-states: met 86, not_met 110, not_applicable 15, not_assessed 10
scratch-dropped-states: met 131, not_met 140, not_applicable 9, not_assessed 0
scratch-coverage: rows 221/501, policies 77/102 (25 lost), cells 120 of 188 sealed-covered (68 lost), template 314
scratch-drop-reasons: section not collected 126, item value unusable 68, sharing capability unusable 11, section empty 10, environment field 9, DNS record 8, rules decide another verdict 8, other not-assessed codes 33, twin of a compared split row after re-expression 6, twin of a kept row 0, share-cap trim 1
scratch-twins-check: heldout-twins 0, heldout-max-share 2.71 per cent, heldout-soundness pass, heldout-label-reproduction 221/221 (OPA rerun)
scratch-heldout-sha256: 80361d9efd2d7fbe72627fad4ba15856e871de19272bb65fc26a5a89f792fb05
blocker-1: files under heldout/collected fail the sealed M02-T02 twins check (complete heldout/ SHA256SUMS)
blocker-2: gpu-hours line fails kit-check usage (M02-T06 not in the budget table's heldout row)
gpu-hours: heldout 0
Details: .plan/work/M02-T06/notes.md and .plan/work/M02-T06/draft/
