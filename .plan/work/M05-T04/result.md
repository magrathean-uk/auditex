## RESULT M05-T04
status: done
summary: Read "Person names" in `docs/reference/security-privacy.md` (lines 497-595) and `[Unreleased]` in `CHANGELOG.md` (lines 8-43) against `src/azure_tenant_audit/output_redaction.py`. Both state the D5 boundary as implemented. Neither carries the D6 limit sentence outside `[1.3.0]`. Every number in the docs matches the code constants.
changes: none
verification: read-only inspection with grep and sed, pass; no tests run, as the brief asks for a read-through only
risks: none
questions_for_g: none

### Findings
1. D5 boundary stated, both documents:
   - Directory people: docs lines 499-505 match `_D5_PERSON_KINDS` and `_D5_PERSON_ODATA` (code lines 344-345, 371-373). CHANGELOG lines 12-14 say "everyone in the run's directory records".
   - Profiles: docs 507-508 and CHANGELOG 12-14 name the shareable, customer-pack and explainer profiles (code 27-30). The local profile is unchanged (docs 512).
   - Free text and ids: docs 507-512 and CHANGELOG 14 cover values, identifiers and mapping keys.
   - Group and role names: docs 508-510 and CHANGELOG 16-17.
   - Replacement forms: docs 528-535 and CHANGELOG 14-15 give `User <digest>` and `user-<digest>`. Code `_USER_PREFIX` is at 211, `_D5_ID_PREFIX` at 1149 and `TEXT_PLACEHOLDER` at 34.
   - Pseudonym scheme: docs 537-550 match `run_salt` (code 278-280) and `pseudonym` (273-275). CHANGELOG 17 says "run-path salt" and "pseudonymisation, not anonymisation".
   - Unmatched note: the docs wording at 552-558 equals the string in `unmatched_names_note` (code 1394-1397). The reason table at 560-569 matches `D5_REASONS` in code 1166-1168, in the same order.
2. D6 limit sentence: the only occurrence is `CHANGELOG.md:55`. That line is inside `[1.3.0]`, which starts at line 45, so it is historical and stays. The docs section carries no such sentence. Its limits list (docs 572-595) is the D5 one.
3. Numbers against code constants:
   - 16 keys per person: the per-person key cap constant in output_redaction.py is 16 (code 1134).
   - Six words: `_D5_MAX_KEY_TOKENS = 6` (code 1135).
   - 64 characters per word: `_D5_MAX_TOKEN_CHARS = 64` (code 1136).
   - Four letters and digits, for `too_short`: `_D5_MIN_KEY_CHARS = 4` (code 1136-1137, used at 1218).
   - 16 hex characters: `[:16]` (code 275).
   - Six probes per word: one for the first word plus at most five growth steps, from the `while width < 6` loop (code 1428-1462).
   - The separators `.` `_` `-` `'` match `_D5_SEPARATORS` (code 1138).

Cosmetic, no action needed: the code also accepts the curly apostrophe `’` and a comma form as separators. Docs 521 lists only the straight apostrophe, and the comma form is covered by the `Family, Given` wording at 517.

read-through: complete
