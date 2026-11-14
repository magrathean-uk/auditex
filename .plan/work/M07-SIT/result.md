## RESULT M07-SIT
status: partial
summary: Design built and mock-tested: a records driver holds one browser sign-in per Microsoft client and gives each kit script fresh tokens. Kit round 7t accepts those tokens for Exchange, Security & Compliance and Teams. Phase D drops to 16 touches (from 25 plus 2 passkey set-ups plus 2 or 3 portal visits); phase E drops to 6 (from 19). verify deferred: heavy slot busy (the kept-case regression of 87 case ids; every check the brief asked for passed).
changes: 20261111-kit-7s/dt-r7t (new, frozen), MANIFEST-7t.sha256, dt-r7t.diff, ROUND-7T.md, proof-7t, runs/m07sit-*; dt-live/phaseD/sitting-driver/ (Sitting.ps1, tests/, MANIFEST.sha256); .plan/work/M07-SIT/design.md, progress.md
verification: driver harness 39/39 pass; Cases-Round7t on dt-r7t 7/7 pass; the same cases on the proof copy of 7s fail 7/7 as designed; Test-ShapeLint and Test-KitConstructs rc 0 with the 7s counts; parse of 72 files through 20261111-kit-7r/pwsh-guarded 0 errors; dt-r7s-ro still 369/369 OK; kept-case regression deferred twice by hostload (rc 75)
risks: offline tests can't show which scp and aud the token connections get, or whether Get-ConnectionInformation shows the operator; each fails closed, and `-Apis` puts that step back on the 7s browser sign-in | 7t is tier A and not yet reviewed: it needs both providers, the kept-case regression and the full suite | after -Enforce Entra may refuse a refresh and ask for one more sign-in per client (at most 4)
questions_for_g: none
### Findings
design: a records driver in one long-lived pwsh window holds one browser sign-in per client (5, plus the kit's own Graph sign-in) and starts each kit script as its own child process; that child alone gets tokens minted at its launch. 7t Connect-DtExchange and Connect-DtTeams connect with -AccessToken(s) when those tokens are set. Running the scripts inside one pwsh process was rejected because Disconnect-ExchangeOnline clears the module's token cache.
kit-change: populate/_common.ps1 (Get-DtApiSpec, Connect-DtExchange, Connect-DtTeams only; no script line changed), tools/mock-harness/Cases-Round7t.ps1 (new), tools/mock-harness/Cases-Round7p.ps1 (one loader line)
part2-touches: 16 = Graph sign-in 1 + one per client 5 (Exchange, SharePoint, Teams, Fabric app, Azure PowerShell) + break-glass 6 + portal 2 + strict proofs 2 (Graph sign-in after -Enforce, Cloud PC); dry runs, -Apply runs, the check before -Enforce and -Enforce itself need 0
part3-touches: 6 = ScubaGear 5 + browser sign-out 1; both verify runs, New-ScubaConfig and the collection need 0; 10 if the driver window was closed overnight
cannot-cut: first Graph sign-in: the kit's Graph session comes only from the SDK's own browser sign-in, and E7 removed the saved one
cannot-cut: one sign-in per client (5): a refresh token is bound to one user and one client (Learn), and the kit fixes the client for each API
cannot-cut: break-glass sign-in with a temporary pass, passkey creation and proof sign-in, 2 accounts (6, one private window): a new account has no other credential, the key is made on G's device, and registering a key doesn't prove it signs in
cannot-cut: 2 portal settings: Graph documents no update for Microsoft-managed CA policies, and the Teams org-wide app settings can only be set in the portal
cannot-cut: strict proofs (2): a fresh passkey sign-in under the enforced rules is the thing tested, and a refresh can't show it
cannot-cut: ScubaGear (5): the pinned oracle signs in with its own hash-pinned code, and feeding it tokens would change the oracle
cannot-cut: browser sign-out: a Global Administrator session must not stay in the default browser
cannot-cut: +4 in a new phase E window: refresh tokens live only in the driver's memory and are never written to disk
harness: pass 46/46 (driver 39/39, Cases-Round7t 7/7; 7/7 fail on the 7s code as designed)
frozen: 20261111-kit-7s/dt-r7t f692ea3eca22
frozen: dt-live/phaseD/sitting-driver 4656851860a5
sources: https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/connect-exchangeonline https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/connect-ippssession https://learn.microsoft.com/en-us/powershell/module/microsoftteams/connect-microsoftteams https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/disconnect-exchangeonline https://learn.microsoft.com/en-us/entra/identity-platform/refresh-tokens https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation
