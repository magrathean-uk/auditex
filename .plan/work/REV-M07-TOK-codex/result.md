## RESULT REV-M07-TOK-codex
status: done
summary: verdict: ship; only requested repairs and supporting tests changed; earlier checks preserved; limits 3 and 4 stated at dt-live/phaseD/sitting-tokens.ps1:23 and behaviour unchanged (DEC-060).
reviewed: e46247d398c9
changes: none
verification: shasum PASS 5/5; both manifest hashes PASS; hash-matched baseline comparison PASS; PowerShell/tests not run, as prohibited.
risks: static review only; exact live scope sets remain unconfirmed.
questions_for_g: none
### Findings
1 fixed: dt-live/phaseD/sitting-tokens.ps1:133 requires expected scopes and rejects extras; tests at dt-live/phaseD/sitting-tokens-tests/run-tests.ps1:124.
2a/2b fixed: dt-live/phaseD/sitting-tokens.ps1:266 revalidates before publication; :275 clears incomplete publication; tests at dt-live/phaseD/sitting-tokens-tests/run-tests.ps1:116.
5 fixed: dt-live/phaseD/sitting-tokens-tests/run-tests.ps1:114 adds ageing, interruption, non-Fabric scope and detectable-consent regressions; previous assertions preserved.
