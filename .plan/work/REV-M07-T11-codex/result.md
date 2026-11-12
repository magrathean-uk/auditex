## RESULT REV-M07-T11-codex
status: done
summary:
verdict: ship
reviewed: 510f26e348fd, manifest check pass
Original blocking defects are closed. The literal any-exception guarantee retains one advisory gap.
changes: none
verification: Python SHA-256 and exact file-set checks pass, 367 files; all 32 construct hashes match; baseline comparisons pass; git status clean. Static review completed; saved logs record 8/8 new cases and 51/51 combined cases passing. No PowerShell, kit execution or network.
risks: Full offline suite remains separate; inherited non-create retries remain under DEC-014; same-operator browser fallback remains undetected.
questions_for_g: none
### Findings

1. closed: kit/20261111-kit-7r/dt-r7r-ro/populate/_common.ps1:1966 accepts only Ok, nonblank values; :1968 rejects unusable scopes; :1978 rejects every missing required field on either side.
2. open, advisory A1: session-read, reconnect and comparison exceptions now latch at kit/20261111-kit-7r/dt-r7r-ro/populate/_common.ps1:2045; the broader any-exception requirement still has an inner-catch bypass at :2038.
3. closed: kit/20261111-kit-7r/dt-r7r-ro/populate/_common.ps1:1239 classifies post-send GRAPH SESSION REFUSED as ambiguous before refusal-text matching; the pre-send NOT SENT classification retains precedence.
4. open for A1 coverage only: the eight additions at kit/20261111-kit-7r/dt-r7r-ro/tools/mock-harness/Cases-Round7r.ps1:258 assert the repaired scenarios, but omit throwing Get-MgRequestContext. Existing cases, verdicts, lint rules and allowances are unchanged; no wildcard added; all construct hashes match kit/20261111-kit-7r/dt-r7r-ro/tools/Test-KitConstructs.ps1:258.
5. closed: kit/20261111-kit-7r/dt-r7r-ro/LIMITS.md:224, kit/20261111-kit-7r/dt-r7r-ro/TRIAL-FACTS.md:11 and kit/20261111-kit-7r/dt-r7r-ro/populate/README.md:96 accurately describe mismatch handling and browser fallback.
6. closed: exactly the six declared files changed. No additional tenant-selection, create-replay or recovery defect found. Production code never clears a latched refusal after initialisation at kit/20261111-kit-7r/dt-r7r-ro/populate/_common.ps1:1944.
Advisory A1: kit/20261111-kit-7r/dt-r7r-ro/populate/_common.ps1:2038 returns a reason when Get-MgRequestContext throws; :2105 only warns during restore, allowing subsequent Graph requests. The session has already been proved and later creates still require MaxRetry 0, so no new harmful path is established. Smallest fix: let that exception reach the outer latch and add a restore-failure case.
