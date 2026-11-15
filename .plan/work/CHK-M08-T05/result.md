## RESULT CHK-M08-T05
status: done
summary: check: pass
checked: 6224e70fb925abb7c6104b3901d746e9d5f3b992
The verify line, the four extra test files and `make contract-smoke` all passed in one heavy-slot run (slot acquired after 811 s). The new guards hold under fakes, and the diff has no tenant write or content read.
changes: none
verification: hostload heavy slot, 1280 tests across the 11 files, no F or E, exit 0 - pass; `make contract-smoke` (5 offline bundles including Google, projection demo, bundle seal verified) - pass; `.plan/work/CHK-M08-T05/exercise.py` fakes exercise - pass
risks: `AdvancedRule` (rule definition text) is kept unminimised in the evidence and could name groups or addresses in its conditions; this is policy configuration, not content, and sits inside the output redaction profiles. The `Get-Command` allow-list entry is broader than the one probe that uses it, but the shared read guard still refuses every non-Get verb. Only fakes were used, so no live Connect-IPPSSession behaviour was seen.
questions_for_g: none
### Findings
- Item 1 pass: all 11 test files passed and `make contract-smoke` printed the projection-demo line, then `exit 0`; the log is at `.plan/work/CHK-M08-T05/verify.log`, and `.venv` link removed afterwards.
- Item 2, session credential: only a certificate token for the compliance audience (`azpacr`/`appidacr` of `2`, no `scp`) opens the session. A secret-minted, delegated, wrong-audience, no-credential-claim, opaque, garbage or integer-valued token starts no process.
- Item 2, what is sent: a certificate run starts 4 processes, each with one `Connect-IPPSSession`. The token travels in `AUDITEX_IPPS_ACCESS_TOKEN` only, never in argv or script text. The cmdlets sent are `Get-Command`, `Get-ProtectionAlert`, `Get-DlpCompliancePolicy` and `Get-DlpComplianceRule`.
- Item 2, runs without the session: secret, no-token and secret-minted-token runs start 0 compliance processes. All four reads record `skipped` with `ipps_session_not_opened`, and a secret run never requests the compliance token.
- Item 2, failed connect: the first read records `failed` and the other three are never invoked; all four carry `ipps_session_not_opened`. The adapter tests show a failed or skipped read withholds its section and never yields met.
- Item 2, no write cmdlet reachable: the read guard refuses `Set-`, `New-`, `Remove-` and `Enable-` verbs, `Import-Module` and a script-supplied `Connect-IPPSSession`, including chained after a `Get-`. `PowerShellGraphAdapter.run` of a write cmdlet in a compliance session starts no process (`command_refused`).
- Item 3 pass: the diff has no tenant write, POST, PATCH or content read. The reads return policy configuration only. DLP location entries other than `All` become `location`, `NotifyUser` becomes `recipient`, and a failed DLP read keeps only its output length. The only added scope is `Exchange.ManageAsApp` on Microsoft Exchange Online Protection, with the blast radius recorded in `configs/collector-permissions.json`.
