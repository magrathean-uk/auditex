## RESULT M02-T06
status: done
summary: Collected-form held-out set built with the pinned 1.4.0 wheel and sealed in kit/heldout-collected/ (DEC-027): 221 of 501 rows kept, 280 dropped and counted, none relabelled; rebuild byte-identical (sha256 80361d9e..., as the scratch build).
  kit/checks/twins.py carries exactly the three DEC-025 changes (no fourth); new kit/checks/collected.py; checks/SHA256SUMS lines for both. No gpu-hours line (DEC-027).
  The sealed heldout/ set is untouched and its twins check passes unchanged against the M02-T02 result. No kit data/ yet, so the explainer comparison is empty and the check says so.
changes: kit/heldout-collected/** (heldout.jsonl, rule-outputs.json, dropped.json, manifest.json, measures.json, reproduction.json, consumed-splits.json, policy-states.json, build_heldout.py, heldout_lib.py, twin_definition.py, notes/field-reads.json, tests/test_collected_checks.py, SHA256SUMS); kit/checks/twins.py; kit/checks/collected.py; kit/checks/SHA256SUMS (twins.py line replaced, collected.py line added). No repository edits.
verification: task verify run from the main checkout on the real kit against a scratch copy of this block under the session TMPDIR (folder M02-T06): pass. kit-check twins --result .plan/work/M02-T02/result.md: pass (lines unchanged, with and without OPA). kit-check twins --heldout heldout-collected: pass (with and without OPA). kit-check collected: pass. kit-check selftest: pass. kit/heldout-collected/tests 23 OK; kit/heldout/tests 24 OK (1 skipped). Builder --check: 0 problems. Detail: .plan/work/M02-T06/evidence.md
risks: (1) leakage probe for REV-M02-kit: nn-copy decisive 147/221 (67 per cent) against 216/501 (43 per cent) sealed; full 99/221 against 205/501; policy-majority 92/221 against 189/501; rows the 1.4.0 rules can read sit closer to training rows. (2) coverage lost: 25 of 102 policies, 68 of 188 sealed cells; 126 drops are "section not collected" (product collection gap for the backlog); the DEC-013 bar on 221 rows needs the kit review's check. (3) the M02-T06 first-choice sentence in the milestone still lists `gpu-hours: heldout 0`; written per DEC-027 without it. `kit-check all --results .plan/work` on the real kit still stops at `checks` until M02-T03 places kit/data (not this task).
questions_for_g: none
### Findings
heldout-form: collected
heldout-label-agreement: 221/221
heldout-twins: 0
heldout-sha256: 80361d9efd2d7fbe72627fad4ba15856e871de19272bb65fc26a5a89f792fb05
heldout-kept-met: 86
heldout-kept-not_met: 110
heldout-kept-not_applicable: 15
heldout-kept-not_assessed: 10
heldout-dropped-met: 131
heldout-dropped-not_met: 140
heldout-dropped-not_applicable: 9
heldout-dropped-not_assessed: 0
heldout-rows: 221
heldout-policies: 77/102
heldout-cells: 120/314
heldout-share-cap: 3 per cent
heldout-max-share: 2.71 per cent
heldout-soundness: pass
heldout-unknown-policies: none
heldout-label-reproduction: 221/221
heldout-nn-copy-decisive: 147/221
heldout-nn-copy-full: 99/221
heldout-nn-copy-policy-majority: 92/221
heldout-availability-matches: 0
collected-explainer-twins: 0
coverage kept: rows 221/501, policies 77/102, cells 120 of 188 sealed cells (template 314); lost: rows 280, policies 25, cells 68
reexpression: identity 209, transformed 19 (default_scuba_config 10, single_object_as_list 12, dns_rdata_as_list 0), Rego reproduced 19/19
drops by reason: section not collected 126; item value unusable 68; sharing capability unusable 11; section empty 10; environment field 9; DNS record unusable 8
drops by reason (cont.): rules decide another verdict 8; other not-assessed codes 33; twin of a compared split row after re-expression 6; twin of a kept row 0; share-cap trim 1; Rego not reproduced 0 (total 280)
negative cases change (1): emptied cell with a sealed row not dropped; wrong dropped count; reason on a cell without sealed rows; reason in the sealed folder (all fail as required)
negative cases change (2): collected folder with task M02-T02; another folder with M02-T06; sealed folder with M02-T06 (all fail)
negative cases change (3): cap drop the cap does not require; cap drop naming another policy (both fail)
negative cases collected.py: shared file not identical, wheel pin mismatch, unlisted file, kept/dropped not a partition, rule output not the sealed label, relabelled row, explainer twin of a collected or sealed row, explainer sha256 mismatch, state lines against the result (all fail); discovery via heldout-form: collected
