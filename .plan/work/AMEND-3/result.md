## RESULT AMEND-3
status: done
summary: Amendment 3 is committed as 57de5d2 on task/AMEND-3-amend-3. It adds M03-T08 (verifier), M03-T06 (pilot) and M03-T07 (data v2), re-scopes M03-T02, adds two DoD items and puts a `dataround` budget row of 160 GPU-hours taken from the reserve.
  Neither budget route in the brief works with the frozen kit: `checks/usage.py` `STAGE_TASKS` ties each stage to fixed task ids. So M03-T06 and M03-T07 cannot claim a new stage, and they cannot claim `prose` or `judging` either.
  How it works without changing the frozen interface: the round writes `round-gpu-hours: dataround <used>`, which `kit-check usage` ignores, and a new plug-in check, `kit-check dataround` from M03-T08, recomputes those hours.
  A verifier task was needed for three reasons: no existing kind recomputes judged targets, `explainer-validation-v1` accepts only `data/explainer`, and the usage binding above.
changes: .plan/milestones/M03-explainer-training.md, .plan/master-plan.md, .plan/ARCHITECTURE.md (BACKLOG.md unchanged: none of its lines are absorbed by this amendment)
verification: python3 percent.py --repo . --check on 57de5d2: pass (rc 0). bash -n over all 18 DoD and verify commands: pass. Budget loop on a scratch copy with a synthetic approved DEC-037: a round total of 160.0 passes, 160.1 fails and a `gpu-hours: dataround` line fails. M02-T03 data-untouched clause against the real kit: pass. git diff --check: pass. Path scan: clean.
risks: DEC-002 says each cap resize needs an amendment line under DEC-002. The orchestrator should add one with DEC-037: reserve 16,384 -> 16,224, dataround 0 -> 160. | The master-plan milestone table still shows M03 at 25 (percent.py now gives 20), and master-plan.md is exactly at its 150-line limit. | M03-T08 is size M, not "small", because it does three jobs: the pilot and filter kind, data v2 in the explainer kind, and the round's hours.
questions_for_g: Accounting route for the data round. Recommendation: keep it as written (round-gpu-hours lines recomputed by the M03-T08 plug-in; frozen interface unchanged). The alternative is a reviewed one-line `STAGE_TASKS` change (`dataround: M03-T06, M03-T07`). That would let the round use plain `gpu-hours:` lines and make M03-T08 smaller, but it changes the frozen interface, which this brief forbids.
### Findings
- M03-T08 Add the data-round checks to the kit verifier | sol | M | hard | verify: result greps, then `kit-check selftest` and `kit-check score runs/base-comparison` (M03-T01 still verifies)
- M03-T06 Teacher prompt v2 and the validation pilot | terra | M | hard | verify: `pilot: (pass|fail)`, `heldout-reads: 0`, `kit-check dataround --result` M03-T06
- M03-T07 Regenerate, judge-filter and register data v2 | terra | M | - | verify: `pilot: pass`, `data-version: data/explainer-v2 <hex>`, `kit-check checks --prose data/explainer-v2`, `kit-check dataround --result` M03-T07
- M03-T02 Train three seeds of the chosen base on data v2 (re-scoped; id and files line kept) | terra | M | debug | verify: `heldout-reads: 0`, the M03-T07 `data-version` line repeated, `kit-check score runs/large`
- DoD: pilot item and data v2 item added. The large-runs item now trains on data v2 and checks the data-version line. The budget item loops over basecmp, large, build and dataround, then runs `kit-check dataround` for M03-T06 and M03-T07. Both ticked items stay ticked.
- Budget before: bringup 32, repro 64, heldout 0, prose 256, judging 128, basecmp 1,024, large 2,048, build 64, reserve 16,384, total 20,000.
- Budget after: the same, plus dataround 160 (M03-T06 and M03-T07, set by DEC-037), reserve 16,224 (DEC-037), total 20,000.
- Where the hours are counted: pilot and data v2 jobs go in runs/usage/M03-T06/ and runs/usage/M03-T07/ under stage dataround (`kit-check dataround`). Training and scoring go under large in runs/usage/M03-T02/ (`kit-check usage`). Basecmp and build are unchanged.
- Verifier task needed: yes (M03-T08), for the three reasons in the summary.
- Sequencing: M03-T08 -> M03-T06 -> M03-T07 -> M03-T02 -> M03-T03 -> M03-T04. On `pilot: fail` the round stops and the question returns to G under DEC-013.
- Overall percentage: 53 before, 52 after (M03 has 2 of 10 DoD items ticked, so 25 -> 20). Weights unchanged.
- Notes: .plan/work/AMEND-3/progress.md
