## RESULT INV4-d5
status: done
summary: D5 masking is in output_redaction.py (run salt = realpath digest, 16-hex pseudonyms, bounded matcher). Two other salt schemes exist: scuba_projection (manifest digest) and scubagear_export (purpose digest). The names parameter on Redactor.text is dead in effect and still passed at three call sites. Structural mapping keys are not masked, and middle initials break the matcher.
changes: .plan/work/INV4-d5/notes.md (new notes file only)
verification: Grep and Read on named ranges; `wc -l` on slice files (pass); one `rg` for salt call sites (pass). No tests, builds or tenant contact; the reviewer's 161-test claim is unverified here.
risks: The run salt changes if a run folder is moved or copied (inferred from realpath). A private per-run key would touch the manifest digest, schemas, CONTRACT_VERSION and the compare/pack rules. The output contract documents only the projection salt.
questions_for_g: Should a private per-run key be persisted in the run folder, or kept in memory and out of the bundle? The current docs forbid persistence.
### Findings
**1. exists**
- src/azure_tenant_audit/output_redaction.py (1909 lines): `pseudonym` 273-275; `run_salt` 278-280 (sha256 of realpath); `RedactionContext` 240-270; merged compare/drift context 1040-1096, first run's salt wins at 1084; D5 section 1125-1480; `_NameMatcher` 1401-1480; `Redactor.text` 1652-1677; mapping pass 1751-1800.
- src/auditex/scuba_projection.py: `_redact` 1530-1559; salt = sha256 of canonical manifest, 1583-1592.
- src/auditex/scubagear_export.py: `redaction_salt` 291-297; used 319-320, 632-634.
- src/azure_tenant_audit/run_files.py:24-33: salt-named files get the 32 MiB limit.
- src/azure_tenant_audit/contracts.py:21: `CONTRACT_VERSION = "2026-11-08"`.
- schemas/model_assessment.schema.json:369 and schemas/model_assessment-2026-10-29.schema.json:369: const `run-salted-sha256-v1`.
- Pack, notify and writer callers: src/auditex/reporting.py:1752, 2077; src/auditex/notify.py:655; src/auditex/output_writers.py:96.
- Tests: tests/test_redaction_person_names.py (salt tests ~501, ~510); tests/test_redaction_scan_budget.py:323-385; tests/test_redaction_profiles_d3.py:307-314.

**2. works** (by reading only)
- Budget tests assert probes ≤ tokens × 6 and window ≤ 6: tests/test_redaction_scan_budget.py:328-353 (Read).
- Probe count is one per token plus up to five extensions: output_redaction.py:1443-1462 (Read).
- Projection and run salts match code and docs: scuba_projection.py:1586, 1592 with docs/reference/output-contract.md:614-615; output_redaction.py:280 with docs/reference/security-privacy.md:537-543.
- Reviewer claim, not re-run: .plan/work/REV-M05-T03-privacy/result.md:9 (161 tests, contract-smoke pass at 215148d).

**3. broken**
- none found by reading.
- Line drift only: .plan/work/REV2-M05-T03/result.md:27 cites `:1592` for the names docstring; it is now output_redaction.py:1652-1656.

**4. dead candidates**
- `Redactor.text(names=...)`: output_redaction.py:1652; the body (1652-1677) never reads `names`. Still passed at 1732, 1785, 1789. REV2's follow-up removal is not done.
- `_D5_ID_NEIGHBOURS` (1147), `_D5_ID_JOINERS` (1148), `_D5_PLACEHOLDER_WORDS` (1150): used at 1490-1494 and 1211, so live.
- Schema versions 2026-10-27, -27.1, -28, -29 and the unversioned file: historical copies (inferred). The unversioned name is referenced from contracts.py, bundle_integrity.py and shipped_content.py (rg list, not read).
- Abandoned TODOs in the slice: none found.

**5. contradictions**
- Three "run salt" schemes: output_redaction.py:278-280 (realpath), scuba_projection.py:1583-1592 (manifest digest), scubagear_export.py:291-297 (purpose digest). Docs cover the first two (docs/reference/security-privacy.md:537-550; docs/reference/output-contract.md:613-616), not the third.
- docs/reference/output-contract.md:613-621 omits the D5 realpath salt used by customer packs, compare and drift.
- .plan/work/REV-M05-T03-privacy/result.md:10 says middle-initial and title spellings are counted as unmatched. Code: `J.` followed by a space breaks the chain (output_redaction.py:1177, 1453) and is counted as `separator` (1263-1264). D5_REASONS (1166-1168) has no title reason, so titles are keyed, not counted (inferred).
- output-contract.md:617-619 says no pseudonym table is persisted and the salt stays in memory. Consistent with code; run_files.py:26-31 anticipates salt files (inferred).

**6. open questions**
- Does the D5 suite pass at HEAD? `PYTHONPATH=src .venv/bin/python -m pytest tests/test_redaction_person_names.py tests/test_redaction_scan_budget.py tests/test_redaction_profiles_d3.py tests/test_scuba_projection.py tests/test_scubagear_export.py` (needs a .venv link; not run).
- Does a moved or copied run folder change pseudonyms? Inferred yes. Settle with a unit call of `run_salt` on a copied temp dir.
- Title and middle-initial behaviour: settle with `_person_keys` on "Dr Alice Smith" and `mask` on "Dr. Alice Smith" (not run).
- Private-key touch list (inferred): output_redaction.py:278, 1048, 1084; scuba_projection.py:1586-1592; scubagear_export.py:291-297; scuba_projection.py:1559 and the schema const; contracts.py:21; both docs; reporting.py:1752, 2077; output_writers.py:96; tests/fixtures/contract-smoke-digests.json (not checked).
- Not read: docs/development/scubagear-export-adapter.md (6 salt hits), src/auditex/mcp_server.py, src/auditex/notify.py D5 paths.
- Neighbour (one line): the model_assessment schema family sits with the retired model layer (M02); not inventoried.
