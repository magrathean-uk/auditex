## RESULT REV-M07-T18-codex
status: done
summary:
verdict: do-not-ship
reviewed: 7433269381e1, manifest check pass
One blocking classification defect and its missing regression case.
changes: none
verification: Python manifest checks pass (7r 367/367, 7s 369/369); diff, AST, hygiene and 12 construct hashes pass; static refusal counterexample fails; git status clean. Recorded mock 16/16 and comparison 341/341 results inspected. Kit execution skipped as instructed.
risks: full offline suite remains separate; live non-404 shapes remain unproven
questions_for_g: none
### Findings
1. blocking: kit/20261111-kit-7s/dt-r7s-ro/populate/_common.ps1:1914 returns true for a kit refusal quoting `status code does not indicate success: 404`, before reaching the refusal guard. An absence reader therefore treats a request never sent as absence. This text returned false on 7r. Smallest fix: move the refusal guard before status classification.
2. pass: kit/20261111-kit-7s/dt-r7s-ro/populate/_common.ps1:2993 supplies the shared value logic across all 13 status-read sites; retry, throttling and conflict handling are otherwise unchanged. Write failures still propagate.
3. pass: kit/20261111-kit-7s/dt-r7s-ro/compare.py:1002 accepts both specified schema dates and their existing minor-suffix convention, refusing others with exit 2; :1038 rejects unknown classes per row and gates value_rule to the newer schema. Scoring is unchanged; kit/20261111-kit-7s/dt-r7s-ro/tools/compare-fixtures/auditex-1.5.0-demo-model_assessment.json:1 contains nothing tenant-like.
4. pass: kit/20261111-kit-7s/dt-r7s-ro/populate/_common.ps1:1907 is its sole changed function; sign-in, sessions, retries, MaxRetry and service connections are unchanged. All 12 reviewed construct hashes match. kit/20261111-kit-7s/dt-r7s-ro/populate/README.md:49 and :56 are wording changes; expected verdicts and blueprint are byte-identical.
5. blocking coverage gap: kit/20261111-kit-7s/dt-r7s-ro/tools/mock-harness/Cases-Round7s.ps1:82 tests refusals without a parsed 404. Smallest fix: add numeric-404 refusal cases for all three markers and an absence-reader assertion. Otherwise the mock matches the live shape, retains the old shape, and recorded baseline failures support the claims. Existing tests, lint rules and allowances are unchanged; no wildcard allowance was added.
6. pass: kit/20261111-kit-7s/dt-r7s-ro/tools/mock-harness/Cases-Round7s.ps1:8 uses synthetic test data; changed-file hygiene passes. No further change affecting tenant selection, account checks, write replay, blueprint scope, rollback coverage or operator access was found.
