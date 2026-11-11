## RESULT M02-T02
status: done
summary: Built and sealed the clean held-out set in the AIRR kit: 736 rows over all 102 template policies, generated offline from new synthetic tenants (deterministic mutations of Rego-read fields of the saved v10 seed tenants) and labelled by the pinned ScubaGear Rego (2446ad7) with OPA 1.20.2, both checked at run time.
summary: Twins are removed against v10 train and validation under the M02-T01 definition and a stricter null-insensitive key, with one row per twin key. The share cap is 3 per cent per policy (largest 1.22 per cent); test-v7 had 39 per cent in one policy.
summary: Added the `twins` subcommand. The rebuild is deterministic (byte-identical on a second run). No GPU, no repository change. Scope note: accept() held two verdicts in one evidence key for 64 policies on the new candidates; all 19,235 such rows were dropped (see risks).
changes: kit/20261111-airr-v4/heldout/{build_heldout.py,heldout.jsonl,manifest.json,measures.json,policy-states.json,README.md,SHA256SUMS,tests/test_twins_check.py}; kit/20261111-airr-v4/checks/twins.py; kit/20261111-airr-v4/checks/SHA256SUMS (twins.py line only); .plan/work/M02-T02/notes.md
verification: `grep -qx 'heldout-twins: 0' <result> && "$AIRR_KIT/bin/kit-check" twins --result <result>` pass, run against a scratch result file with these Findings lines in a folder named M02-T02 under $TMPDIR, as the brief allows.
verification: `kit-check all --results <scratch>` pass (twins and usage); `unittest discover -s heldout/tests` 7 pass; `unittest discover -s checks/tests` 54 pass.
risks: The twin key is coarser than the Rego for 64 policies (mostly the CA items: a not-collected marker in a section whose read paths do not match its shape vanishes from the key). It over-merges, so no twin can hide, but M02-T03 should know when it uses accept().
risks: Labels are Rego verdicts and evidence is in the pack's shape. M03-T03 must build the value-rule reason and template text with the 1.4.0 wheel and set aside any row where the rule verdict differs. 49 of 314 cells are uncovered (45 single-section not_assessed cells, plus MS.AAD.5.6v1 and MS.AAD.9.1v1 not_applicable, MS.EXO.13.1v1 not_met and MS.SECURITYSUITE.5.1v1 met).
risks: The kit folder resolves to the external 4TB volume, as the v10 pack already does. The rows are synthetic and hold no tenant data, but this contradicts the kit README's encrypted-disk line.
questions_for_g: none
### Findings
heldout-twins: 0
heldout-sha256: 13ebcdffdeb1800fc55af45d05b968a323630def861d898d79c4da34869a168e
heldout-rows: 736
heldout-policies: 102/102
heldout-cells: 265/314
heldout-share-cap: 3 per cent
heldout-max-share: 1.22 per cent
heldout-soundness: pass
heldout-unknown-policies: none
gpu-hours: heldout 0
