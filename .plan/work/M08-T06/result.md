## RESULT M08-T06
status: done
summary: One app-only certificate re-collection (run m08e3, after M08-T13) answers 62 of the 64 rows met or not met; MS.AAD.3.4 carries a named tenant reason (Microsoft retired the migration state) and PP 2.3 stays not assessed by product design. The kit comparison agrees on 83 of 90 decided rows; the seven disagreements are listed under Findings.
changes: .plan/work/M08-T06/result.md; run bundles and the kit comparison stay in the internal records folder (phaseE/runs, phaseE/compare-m08e3.*)
verification: run-manifest valid, tenant matches; 27 collectors (defender dropped by --probe-first: alerts service not provisioned on the trial); rule assessment 102 rows; kit compare.py from the 7t live copy (gate passed, no fallback), exit 0
risks: DNS rows were excluded from the kit comparison (no frozen verify file); the run is partial (defender, audit logs and site permissions in app mode)
questions_for_g: none
product-commit: 880c418ffe9fcc49462538d080545d2ceb844df6
run-mode: app-only certificate
run-manifest: 2583d5c75bfa2d45f419f0c7981204ffaee1a5e1c168b99f6deca32d717dd2d6
rows-in-scope: 64
rows-decided: 62
rows-named-tenant-reason: 1
rows-product-design: 1
rows-product-gap: 0
kit-compare: recorded
row: MS.TEAMS.1.1v1 not-met manifest:2583d5c75bfa
row: MS.TEAMS.1.2v2 met manifest:2583d5c75bfa
row: MS.TEAMS.1.3v1 met manifest:2583d5c75bfa
row: MS.TEAMS.1.4v1 met manifest:2583d5c75bfa
row: MS.TEAMS.1.5v1 not-met manifest:2583d5c75bfa
row: MS.TEAMS.1.6v1 not-met manifest:2583d5c75bfa
row: MS.TEAMS.1.7v2 met manifest:2583d5c75bfa
row: MS.TEAMS.2.1v2 not-met manifest:2583d5c75bfa
row: MS.TEAMS.2.2v2 met manifest:2583d5c75bfa
row: MS.TEAMS.2.3v2 not-met manifest:2583d5c75bfa
row: MS.TEAMS.4.1v1 met manifest:2583d5c75bfa
row: MS.TEAMS.5.1v2 not-met manifest:2583d5c75bfa
row: MS.TEAMS.5.2v2 not-met manifest:2583d5c75bfa
row: MS.TEAMS.5.3v2 not-met manifest:2583d5c75bfa
row: MS.POWERBI.1.1v1 not-met manifest:2583d5c75bfa
row: MS.POWERBI.2.1v1 met manifest:2583d5c75bfa
row: MS.POWERBI.3.1v1 not-met manifest:2583d5c75bfa
row: MS.POWERBI.4.1v1 met manifest:2583d5c75bfa
row: MS.POWERBI.4.2v1 not-met manifest:2583d5c75bfa
row: MS.POWERBI.5.1v1 met manifest:2583d5c75bfa
row: MS.POWERBI.6.1v1 not-met manifest:2583d5c75bfa
row: MS.POWERBI.7.1v1 met manifest:2583d5c75bfa
row: MS.POWERPLATFORM.1.1v1 met manifest:2583d5c75bfa
row: MS.POWERPLATFORM.1.2v1 not-met manifest:2583d5c75bfa
row: MS.POWERPLATFORM.2.1v1 met manifest:2583d5c75bfa
row: MS.POWERPLATFORM.2.2v1 met manifest:2583d5c75bfa
row: MS.POWERPLATFORM.2.3v1 product-design:no-baseline-text manifest:2583d5c75bfa
row: MS.POWERPLATFORM.3.1v1 not-met manifest:2583d5c75bfa
row: MS.POWERPLATFORM.5.1v1 met manifest:2583d5c75bfa
row: MS.POWERPLATFORM.6.1v1 not-met manifest:2583d5c75bfa
row: MS.SECURITYSUITE.3.1v1 met manifest:2583d5c75bfa
row: MS.SECURITYSUITE.3.2v1 not-met manifest:2583d5c75bfa
row: MS.SECURITYSUITE.3.3v1 met manifest:2583d5c75bfa
row: MS.SECURITYSUITE.3.4v1 not-met manifest:2583d5c75bfa
row: MS.SECURITYSUITE.4.1v1 met manifest:2583d5c75bfa
row: MS.AAD.3.3v2 met manifest:2583d5c75bfa
row: MS.AAD.3.4v1 tenant-reason:migration-state-retired manifest:2583d5c75bfa
row: MS.AAD.3.5v2 not-met manifest:2583d5c75bfa
row: MS.AAD.3.6v1 not-met manifest:2583d5c75bfa
row: MS.AAD.5.2v1 met manifest:2583d5c75bfa
row: MS.AAD.5.3v1 met manifest:2583d5c75bfa
row: MS.AAD.5.5v1 not-met manifest:2583d5c75bfa
row: MS.AAD.5.6v1 met manifest:2583d5c75bfa
row: MS.AAD.5.7v1 not-met manifest:2583d5c75bfa
row: MS.AAD.7.4v1 not-met manifest:2583d5c75bfa
row: MS.AAD.7.5v1 met manifest:2583d5c75bfa
row: MS.AAD.7.6v1 met manifest:2583d5c75bfa
row: MS.AAD.7.7v1 not-met manifest:2583d5c75bfa
row: MS.AAD.7.8v1 met manifest:2583d5c75bfa
row: MS.AAD.7.9v1 not-met manifest:2583d5c75bfa
row: MS.EXO.3.1v1 not-met manifest:2583d5c75bfa
row: MS.EXO.4.1v1 not-met manifest:2583d5c75bfa
row: MS.EXO.4.2v1 not-met manifest:2583d5c75bfa
row: MS.EXO.4.3v1 not-met manifest:2583d5c75bfa
row: MS.EXO.4.4v1 not-met manifest:2583d5c75bfa
row: MS.EXO.7.1v1 met manifest:2583d5c75bfa
row: MS.SHAREPOINT.1.1v1 not-met manifest:2583d5c75bfa
row: MS.SHAREPOINT.1.2v1 met manifest:2583d5c75bfa
row: MS.SHAREPOINT.1.3v1 met manifest:2583d5c75bfa
row: MS.SHAREPOINT.2.1v1 not-met manifest:2583d5c75bfa
row: MS.SHAREPOINT.2.2v1 met manifest:2583d5c75bfa
row: MS.SHAREPOINT.3.1v1 not-met manifest:2583d5c75bfa
row: MS.SHAREPOINT.3.2v1 met manifest:2583d5c75bfa
row: MS.SHAREPOINT.3.3v2 not-met manifest:2583d5c75bfa
### Findings
finding: kit compare m08e3: agree 83, disagree 7, unknown (known gap) 6, DNS excluded 6; agreement on decided rows 92.2%.
finding: AAD 2.1, 3.6, 3.9 expected met, got not met: the DT policies stay report-only (DEC-084, no -Enforce); the product reads the tenant correctly.
finding: AAD 9.1 expected met, got not met: the policy was never created (no agent SKU, DEC-008 named gap).
finding: SS 4.1 expected not met, got met: phase D could not disable 'Messages have been delayed' (kit finding, DEC-091).
finding: TEAMS 5.1 expected met, got not met: the org-wide Microsoft apps setting is portal-only and was left manual (DEC-091); app-only cannot read the unified settings.
finding: AAD 7.5 expected not met, got met: the kit expects direct GA and bg assignments without StartDateTime to fail; needs a look (product or kit) in a later round.
finding: PP 3.1 is now decided (not met, tenant isolation off) through M08-T04's read; DEC-061 had it not assessed by design (DEC-094).
