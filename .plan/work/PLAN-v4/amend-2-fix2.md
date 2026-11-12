# Plan v4 amendment 2 - close one open item (new author)

You are a new author closing a bounded list on branch `task/PLAN-v4-plan-v4-amend-2` (head d7619ea). The re-check `.plan/work/REV-PLAN-v4/result-6.md` in the main checkout closed D1 to D5 and left three points, all in `.plan/milestones/M02-explainer-data-and-judging.md` (task M02-T06 and the M02 review item). Apply the reviewer's fixes as written there; do not redesign.

1. "New (medium)", the `checks/collected.py` contract: the collected set carries `heldout/collected/dropped.json` and `rule-outputs.json`; kept and dropped case ids are disjoint and together equal the M02-T02 `heldout.jsonl` case ids; each kept row's verdict equals its sealed label by case id; the wheel pin equals `WHEEL_SHA256` in `judging/inputs/build_inputs.py`; the per-state count line keys are named; the review item says REV-M02-kit judges every drop reason. Add the two new files to the files line.
2. "New (low)", the Writes line and the review item: every line `kit-check twins --heldout heldout/collected` prints, and the review item names that command with `--result .plan/work/M02-T06/result.md`.
3. "Cosmetic": the missing comma in the files line.
4. Change nothing else in any file: no weight, status, tick, other task or other milestone. `percent.py --check` passes. Do not edit `.plan/STATE.md` or `.plan/DECISIONS.md`. In the summary give the path:line for each of the three points.
