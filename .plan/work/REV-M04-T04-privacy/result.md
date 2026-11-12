## RESULT REV-M04-T04-privacy
status: done
summary: verdict: changes-required
reviewed: b2a69ae0ef203406e97eacbc2ec3c85f1e29a818
The original B1 probes now mask, but a near variant still leaves "John A. Smith" readable: a key path that runs on past the initial (the person's own admin UPN john.a.smith.adm). B2, A1, A2 and A3 are fixed. The budget holds and pseudonyms are unchanged. The exempt list holds no real names.
changes: none (review files only: .plan/work/REV-M04-T04-privacy/evidence-2.md, progress.md)
verification: .venv/bin/python -m pytest on the four verify files at HEAD: pass (279 passed, exit 0); B1/B2 probes and variants, differential against 4132208, budget scaling and exempt-list scans (evidence-2.md): done; full suite and 90,000-record benchmark: not run (the brief excludes them)
risks: B1 variant reaches every shareable output; 157 engine-written mapping keys are outside the exempt list (B2 class, no realistic name); the drift test couples every new src key to output_redaction.py
questions_for_g: none
### Findings
1 B1: original probes fixed (src/azure_tenant_audit/output_redaction.py:1643-1650). Variant not fixed: when the phrase with the initial is only a prefix (value ""), not a miss, the fallback never runs and "john smith" is never probed. "John Smith" with own UPN john.a.smith.adm, or with another person "John A. Smith-Jones" or UPN john.a.smith.brown: "John A. Smith" stays readable. B2: fixed for break_glass, emergency_access, data_protection and display_name (:1702), including the overlay route. Variant: users "Member Type" and "Org Unit" rename member_type and org_unit, because the generator misses keys passed as call keywords (src/auditex/google_workspace/normalize.py:39, :633).
2 A1 fixed (:1526-1549, :1867-1869); A2 fixed (:1615); A3 fixed (tests/test_redaction_scan_budget.py:331-344).
3 No new leak beyond the intended key exemption. A differential run against 4132208 gives 251 same and 13 different results, all intended. At most 6 probes per start by construction (each fallback costs one probe and lowers the cap by one). Window at most 6. Adversarial texts peak at 2.27 probes per token (was 2.00) and scale linearly. Each person keeps the same pseudonym, and every pseudonym still goes through _replacement and pseudonym() under the 32-byte key.
4 An exempt-named person is left readable only as the whole mapping key; values, list items, free text, joined, dotted and markup forms are all masked. 3,910 entries; no fixture name or common first-name pattern is exempt, and single words (lady, barlow) cannot match a two-token person key. Drift-test cost: about 1 s to parse all of src, and any new key under src, schemas or configs fails it until someone edits the 590-line constant in output_redaction.py by hand (there is no generator script).
B1-variant blocking: when a non-initial token follows a taken initial and grown is prefix-only, also probe bare+token. Record a hit as best and keep walking the longer path. One fallback per start, cap minus one. Add a test for "John Smith" with UPN john.a.smith.adm and for a recorded "John A. Smith-Jones".
Keyword-key advisory: also harvest keyword names of every call in src, or keys from the contract-smoke bundle, in the generator.
Generator advisory: add scripts/generate-d5-field-names.py, as generate-rule-packs.py works, so the drift test names a command to run.
Note-wording advisory: the vocabulary note says the same words elsewhere are left as written, which is wrong for these people; M04-T05 to reword it.
