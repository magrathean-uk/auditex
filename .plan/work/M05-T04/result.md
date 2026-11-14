## RESULT M05-T04
status: done
summary: The fixed sentence of `unmatched_names_note` now reads "their name fields are pseudonymised; a person whose name is a vocabulary word is still masked in values and free text." This matches the privacy reference. It is committed as c4f5f12 on top of the first-run head 684c250. All earlier criteria remain met. No digest moved.
changes: src/azure_tenant_audit/output_redaction.py, tests/test_redaction_person_names.py, docs/reference/security-privacy.md (plus the first-run files listed in .plan/work/M05-T04/result-1.md)
verification: `make lint` pass (once, after the change); `pytest tests/test_redaction_person_names.py` pass; `make contract-smoke` and `compare-run-outputs.py --digests tests/fixtures/contract-smoke-digests.json outputs/ci-contract` pass through the heavy slot (all 43 digests match, none moved, fixture untouched). I did not rerun `make test` or the other focused tests on c4f5f12; the first run had them passing on 684c250.
risks: The privacy reference quoted the old sentence (the note quote and the "fixed wording is generic" bullet), so I edited both, wording only. The existing tests pin only the note's prefix, so I added an assertion for the new sentence (and for "left as written" being absent) to `test_the_note_is_true_for_every_reason`. That is the only test change; no test names changed this round.
questions_for_g: none
### Findings
First-run findings kept: model_assessment_prompts.jsonl is a legacy tolerated name and old bundles still validate; `Redactor.text` lost `names` and its three call sites; `_is_privileged_user` removed; "model view" became "projected view"; `compare-run-outputs.py` now validates the baseline's run and artefact inventory (exit 2 on mismatch); the reproducibility test varies only the gzip header; the D5 test names no longer cite review rounds.
note-sentence: corrected
