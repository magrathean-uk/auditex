## RESULT RETRO-M03
status: done
summary: 17 M03 ledger runs; 1.9234 USD recorded (Claude rows only, 7 codex2/astra rows have no cost, so unknown); 3339 s total.
summary: 4 non-zero exits, all blocked, across M03-T02 (2), M03-T03 (1) and M03-T05 (1). T03 and T05 later passed; M03-T02 ends blocked.
summary: Ledger and result.md disagree on M03-T02: milestone DoD item 1 says done with "6 passed", but the final row and result are blocked.
changes: .plan/RETRO.md (appended ## M03 only; numstat 53 added, 0 deleted), .plan/work/RETRO-M03/notes.md, .plan/work/RETRO-M03/evidence.md
verification: awk aggregation over the 17 M03 ledger rows, pass (0 malformed rows); git diff --numstat .plan/RETRO.md, pass (additions only)
risks: M03-T02 DoD item 1 evidence no longer matches its result file; the passing result was probably overwritten (inferred, not confirmed).
risks: M03-T03 and M03-T05 report different wheel and sdist sha256 for the same commit d9f050f; M03-T06 verified against the M03-T05 hashes.
risks: codex2 and astra spend is unrecorded, so the spend total understates the real figure.
questions_for_g: Where is the v3.9.1 vectors.jsonl kit (sha256 3515b6fa..., 26,898 rows)? Should the M03-T02 DoD item be reopened until it runs?
### Findings
- luna-explore.md (inferred for M03-T02): precheck required input paths and exit blocked with the paths searched, before run-job; backed by the M03-T02 blocked run.
- _footer.md: write each attempt to its own result file (for example result.attemptN.md) so a later blocked attempt cannot overwrite a done one; backed by M03-T02 done then blocked, and the lost causes for M03-T03 and M03-T05.
- terra-implement.md: verify each "since version X" or "first documented in" claim against the tagged source before handoff; backed by the M03-T01 review round on a wrong 1.2.4 claim.
- terra-implement.md (inferred for the release steps): pin SOURCE_DATE_EPOCH and require the publishing build's sha256 to match M03-T03 before tagging; backed by the M03-T03 vs M03-T05 hash mismatch.
