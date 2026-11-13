## RESULT REV-M04-T04
status: done
summary: verdict: changes-required
reviewed: 0adcc490f63b3fc43d43562001c6f26ddfbaee8b
Review completed by code inspection; execution was blocked by the sandbox. Five required changes follow.
changes: none; read-only sandbox prevented progress and evidence files
verification: git diff --check main...HEAD PASS; required verification and invented-name probes blocked by sandbox; historical test results were not independently reproduced
risks: readable names; whole-key allocation lacks a token bound; HTML peak ratio unverified
questions_for_g: none
### Findings

Criteria checklist:
- MET: M04-T03 precondition, `.plan/milestones/M04-d5-keyed-pseudonyms.md:66`; merged commit 2c36c94fea9a868741467970c98e3b403a0b7f16.
- NOT MET: masking and bounded-memory requirements, `.plan/milestones/M04-d5-keyed-pseudonyms.md:67`; findings 1-5 below. The streaming text walk itself retains six-probe and six-token limits.
- MET by inspection: keyed derivation and unchanged key handling, `.plan/milestones/M04-d5-keyed-pseudonyms.md:68`; context validates 32 bytes at `src/azure_tenant_audit/output_redaction.py:299`, and matcher replacements call `pseudonym(self.key, canonical)` at line 1725. Required test execution is UNTESTABLE here.
- NOT MET: exact-head dual privacy approval, `.plan/milestones/M04-d5-keyed-pseudonyms.md:69`; `.plan/work/REV-M04-T04-privacy/result.md:4` reviews an older head and requests changes.
- UNTESTABLE: verification at `.plan/milestones/M04-d5-keyed-pseudonyms.md:70`, blocked as recorded below.
- MET: files restriction, `.plan/milestones/M04-d5-keyed-pseudonyms.md:71`; only the named source file and two named test files changed. No outside paths.
- MET: design approval DoD, `.plan/milestones/M04-d5-keyed-pseudonyms.md:14`; `.plan/DECISIONS.md:33` records G's approval and seed strategy.
- UNTESTABLE: combined regression DoD, `.plan/milestones/M04-d5-keyed-pseudonyms.md:15`; not rerun.
- UNTESTABLE: contract-smoke DoD, `.plan/milestones/M04-d5-keyed-pseudonyms.md:16`; version difference confirmed at `src/azure_tenant_audit/contracts.py:25`, smoke not rerun.
- NOT MET: masking DoD, `.plan/milestones/M04-d5-keyed-pseudonyms.md:17`; uncounted readable cases below.
- UNTESTABLE: HTML peak DoD, `.plan/milestones/M04-d5-keyed-pseudonyms.md:18`.
- UNTESTABLE: milestone-close suite, smoke, digests and acceptance DoD, `.plan/milestones/M04-d5-keyed-pseudonyms.md:19`; skipped in this restricted review.
- NOT MET: merged-head review DoD, `.plan/milestones/M04-d5-keyed-pseudonyms.md:20`; T04 remains unmerged and unapproved.
- NOT MET on this frozen tree: documentation DoD, `.plan/milestones/M04-d5-keyed-pseudonyms.md:21`; `docs/reference/security-privacy.md:537` still describes the old scheme. T05's recorded read-through is later milestone work.

Privacy coverage, inferred from code rather than executed:
- MASKED: one, two and three initials, dotted or undotted, without competing prefixes; initials are skipped within the window at `src/azure_tenant_audit/output_redaction.py:1655`.
- READABLE, BLOCKING: two/three initials plus an admin sign-in prefix and trailing prose; finding 1. Repeating this in a long list repeats the leak without exceeding the probe budget.
- MASKED: Mr, Mrs, Ms, Miss, Mx, Dr, Prof, Professor, Sir, Dame, Lord, Lady, Rev and Revd, dotted/undotted and stacked before a supported name; `src/azure_tenant_audit/output_redaction.py:1267` and line 1684. Lower-case titles can remain, with the person's name masked.
- MASKED: ordinary exact snake-case, hyphenated and two/three-word joined mapping keys; READABLE, BLOCKING: four-word joined keys and inserted-title/initial keys, finding 3.
- MASKED: ASCII case, fullwidth letters, matching accented spellings, ASCII hyphens and straight/curly apostrophes; `src/azure_tenant_audit/output_redaction.py:1248` and line 1338. READABLE, BLOCKING: composed/decomposed equivalents, finding 2.
- MASKED: split given/family fields when a full name or address establishes the person, `src/azure_tenant_audit/output_redaction.py:2040`; READABLE, BLOCKING: parts-only user records, finding 4.
- COUNTED IN NOTE: exempt name-equal product keys and recorded unsupported separators/lengths, `src/azure_tenant_audit/output_redaction.py:1421` and line 1444. Their structured name fields remain pseudonymised.

Required changes:
1. `src/azure_tenant_audit/output_redaction.py:1645` and line 1677: budget exhaustion silently abandons a name. One invented user suffices: display name `Neral Vosk`, sign-in `neral.a.vosk.adm@example.invalid`, text `Neral A. B. Vosk wrote`. The six probes are `neral`, `neral a`, `neral a b`, `neral a vosk`, `neral a vosk wrote`, `neral vosk wrote`; the held `neral vosk` is then refused. Three initials fail similarly.
   Smallest safe repair: when an unresolved initial-bearing candidate cannot be checked within budget, withhold that text using the existing text placeholder. Cover both the miss-fallback boundary and deferred-fallback exhaustion. This adds no probes, window growth or index expansion; retain confirmed longer-name precedence.
   Add `test_two_and_three_initials_with_admin_upn_and_trailing_word_mask_or_withhold`, dotted/undotted and repeated-list cases. Change the readable expectation in `tests/test_redaction_scan_budget.py:425`; retain all budget assertions and the longer-name regressions at `tests/test_redaction_person_names.py:650`. The HTML workload's ordinary path stays unchanged, but its ratio still needs measurement.
2. `src/azure_tenant_audit/output_redaction.py:1249` and line 1338: tokenisation precedes Unicode normalisation. Recorded `Néral Vosk` does not match `Ne\u0301ral Vosk`; a decomposed accented initial also breaks the separator. Neither variant is counted. Include combining marks in complete tokens, normalise before initial classification, preserve source offsets, and add NFC/NFD name and initial regressions.
3. `src/azure_tenant_audit/output_redaction.py:1402` and line 1719: `NeralABVosk`, for recorded `Neral A. B. Vosk`, is neither indexed nor counted because joining stops at three words. For recorded `Neral Vosk`, `neral_a_vosk` and `dr_neral_vosk` also remain readable; `tests/test_redaction_person_names.py:686` pins this omission. Extend whole-key coverage to these supported name forms, or count unsupported forms; preserve product-field and suffix-key protection. Add explicit regressions.
4. `src/azure_tenant_audit/output_redaction.py:495`: `{"kind":"user","given_name":"Neral","surname":"Vosk"}` has no canonical full name/address, so `_person()` returns None. Discovery drops it and line 2040 never masks either part. Use usable given-plus-family names as the canonical fallback, including nested Google name parts; test structured parts and associated narrative.
5. `src/azure_tenant_audit/output_redaction.py:1713`: `whole()` allocates every token with `findall()` before rejecting more than six. A hostile structural key creates a token list proportional to its entire length. Reject impossible lengths first and scan incrementally, stopping at the seventh token without retaining an unrestricted list; add an oversized-key allocation regression.

BACKLOG disposition:
- `.plan/BACKLOG.md:23`: keyword-key harvesting (`member_type`, `org_unit`) may remain a follow-up: it renames fields but leaks no name. A generator script may also remain a maintenance follow-up.
- `.plan/BACKLOG.md:23`: vocabulary-note wording may remain for T05; `src/azure_tenant_audit/output_redaction.py:1575` inaccurately describes where those words remain readable.
- `.plan/BACKLOG.md:25`: probe-exhaustion defect MUST be fixed before merge, as `.plan/DECISIONS.md:359` requires. Its “limit” alternative is superseded by DEC-039.

Security: no added tenant writes, injection path, name-built regex, salt derivation or key disclosure found. HMAC and key-handling code are unchanged. Finding 5 is the additional memory concern.
Verification command, through the required hostload wrapper: `.venv/bin/python -m pytest tests/test_redaction_person_names.py tests/test_redaction_scan_budget.py tests/test_redaction_profiles_d3.py tests/test_redaction_keyed_pseudonyms.py && .venv/bin/python benchmarks/html_peak.py --records 90000 --profile shareable --baseline benchmarks/html-peak-baseline.json --max-ratio 1.15 --require-masked`.
First blocking line: `hostload.sh: line 92: cannot create temp file for here document: Operation not permitted`. The probe script's shell temporary file was also refused. No workaround was attempted.
### Defect classes
Probe-budget exhaustion returns readable names.
Unicode normalisation occurs after token boundaries.
Whole-key name variants escape masking and accounting.
Parts-only directory identities escape discovery.
Whole-key token allocation is unbounded by the matcher window.
