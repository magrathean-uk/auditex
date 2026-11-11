## RESULT REV-M05-T04
status: done
summary:
  verdict: approve
  reviewed: bdd90633b37d471f4f5f7d221e168d6f7a912873
  All three repairs confirmed; full D5 section rechecked.
changes: none
verification: Source trace and git diff --check passed; runtime assertions blocked by missing requests; suite and harness skipped for this read-only documentation review.
risks: clean-development doctor failed on a dead/unverifiable lifecycle-lock owner; no repairs made.
questions_for_g: none
### Findings
- Unmatched wording correctly preserves masking of retained accepted spellings, including separator and limit cases: src/azure_tenant_audit/output_redaction.py:1233, :1359.
- Salt and pseudonym construction correctly describe SHA-256(realpath UTF-8), then SHA-256(salt + NUL + canonical name UTF-8) truncated to 16 hex characters: src/azure_tenant_audit/output_redaction.py:273, :278.
- Harness wording matches child peak RSS measurement, baseline × 1.15 default and optional masking checks; the 2 GiB claim and dangling reference are removed.
- Non-blocking refinement: docs/reference/security-privacy.md:618 should label 64× / 4 GiB as an estimate rather than an upper bound; the scanner enforces byte budgets, not resident-memory limits.
