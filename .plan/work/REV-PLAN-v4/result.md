## RESULT REV-PLAN-v4
status: done
summary: verdict: approve
summary: reviewed: dabe3524f0ccba103fe051bfa9c58af43addd5f7
summary: All three points from result-6 are closed. The diff from d7619ea to HEAD changes only M02 :21, :77 and :81. The predicates at :19 and :80 are unchanged and behave correctly in the probes.
summary: percent.py --check returned rc 0 (overall 35%, M02 50%). Evidence is in .plan/work/REV-PLAN-v4/evidence.md under "Re-check 7".
changes: none in the repository. Notes are in .plan/work/REV-PLAN-v4/evidence.md and progress.md.
verification: percent.py --repo . --check: pass (rc 0). git diff d7619ea HEAD -- .plan: 1 file, 3 lines changed. Scratch probes with a stub kit-check, :19 and :80: good collected input passes (0/0); copied T02 seal fails (1/1); wrong hash fails (1/1); missing heldout/collected fails (1/1); per-state without scoring-per-state.md fails (1/1); per-state with it passes (0/0).
risks: The verify at :80 still passes 209/501 because the n/n check is left to kit-check collected. That was settled before. The :77 contract now forces it (each kept row's verdict must equal its sealed label), and the DoD at :19 rejects it.
questions_for_g: none
### Findings
- New (medium) closed: .plan/milestones/M02-explainer-data-and-judging.md:77 now covers all of these:
  - rule-outputs.json and dropped.json, both under SHA256SUMS
  - the wheel pin must equal WHEEL_SHA256 in judging/inputs/build_inputs.py
  - kept and dropped case ids must be disjoint and together equal the M02-T02 heldout.jsonl case ids
  - each kept row's verdict must equal its sealed label by case id
  - the line keys are heldout-kept-<state> and heldout-dropped-<state> for each of the four states
  - :21 says REV-M02-kit judges every drop reason in dropped.json
- New (low) closed: M02:77 writes every line that `kit-check twins --heldout heldout/collected` prints. M02:21 names `kit-check twins --heldout heldout/collected --result .plan/work/M02-T06/result.md`.
- Cosmetic closed: M02:81 now has the comma before `checks/collected.py`, and both new files are on the files line.
- Diff scope: only the M02 milestone file and only these three points. No weight, status, tick, other task or other milestone changed.
- Minor wording, not blocking, present since d7619ea: M02:77 says "verifies that `SHA256SUMS`;". Fix: change it to "verifies `SHA256SUMS`;" next time the file is edited.
