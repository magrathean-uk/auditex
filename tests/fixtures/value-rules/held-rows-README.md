# held-rows-s4.json and held-rows-s5.json: enabled, kept as the record

These files hold the rows for `MS.SECURITYSUITE.6.1v1` and `6.2v1` (stage 4) and `MS.SECURITYSUITE.1.1v1`
(stage 5), which were built and reviewed before the Security Suite failure ledger
(`securitysuite_unsuccessful_commands`, projection item P4) reached the rule view, so they stayed out of
`configs/scuba-value-rules.json`.

They are now enabled: the three rows were copied unchanged into `configs/scuba-value-rules.json` (the policy
set is 102). `tests/test_value_rules_held.py` asserts that the shipped rows equal these files exactly, so a
wording or cell change must be made in both places on purpose. The files are no longer a registration gate.
They are left byte-identical because `scripts/build-value-rule-fixture-s5.py` still reads
`held-rows-s5.json` when it rebuilds `vectors-s5.jsonl.xz`.
