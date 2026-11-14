## RESULT M07-K7T
status: done
summary: 05 sends no write for a null policyMigrationState (MANUAL not applicable, Learn source) and carries on; any other state unchanged.
10 creates MS.AAD.9.1 only when a usable SKU carries ENTRA_CONDITIONAL_ACCESS_FOR_AGENTS or AGENT_365, or the policy exists; otherwise no create, MANUAL named gap (DEC-008), no intent.
An open 9.1 intent is resolved by the kit's unchanged absent procedure, never followed by a create. 90-verify, 99-rollback and EXPECTED-VERDICTS checked: no change required (stated in ROUND-7T.md).
Frozen dt-r7t-ro; only the 4 intended files differ from dt-r7s-ro. Partial earlier folder moved aside as 20261114-kit-7t-partial.
Notes: kit 20261114-kit-7t/ROUND-7T.md; .plan/work/M07-K7T/notes.md.
changes: kit 20261114-kit-7t/dt-r7t(-ro): populate/05-entra-settings.ps1, populate/10-conditional-access.ps1, tools/mock-harness/Cases-Round7p.ps1 (one loader line), tools/mock-harness/Cases-Round7t-Live.ps1 (new); 20261114-kit-7t/ROUND-7T.md, MANIFEST.sha256; no repo file
verification: new cases on dt-r7t 6/6 pass (runs/new-7t-2) pass; on 7s code 4/6 fail as designed (runs/old-7t-1); host slot --wait 5400: kept 7q-7s plus new 89/89 pass (runs/kept-7p7t-1) pass; check-suite-7l --quick against the frozen snapshot and manifest OVERALL PASS 7 steps pass; shape lint 271 allowlisted, 0 stale; constructs 0 findings pass; dt-r7s-ro 369/369 OK, dt-r7t-ro 370/370 OK pass; full suite not run (gate's)
risks: Graph's 400 carries no reason text; the licence cause is the documented requirement, not read off the answer.
10 now requests Organization.Read.All (read-only; already consented by 00-identity) for the subscribedSkus read.
BLUEPRINT.md, LIMITS.md:166 and TRIAL-FACTS.md:21 still say 9.1 is created or to stop for G; on the live tenant 90-verify and ScubaGear read 9.1 not met against the expected met (the DEC-008 gap).
questions_for_g: none
### Findings
fix: populate/05-entra-settings.ps1:229
fix: populate/10-conditional-access.ps1:148
resolve-9.1: confirm no policy of that name exists, add "intent-8def1240": "absent" to the existing intent-resolution.json in dt-live/phaseD/state, run 10 -Apply with dt-r7t-ro (first empty read, stop), rerun after 600 s: intent closes and no create is sent
sources: https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-methods-manage https://learn.microsoft.com/en-us/graph/api/resources/authenticationmethodspolicy?view=graph-rest-beta https://learn.microsoft.com/en-us/entra/identity/conditional-access/agent-id https://mc.merill.net/message/MC1395007 https://learn.microsoft.com/en-us/entra/id-protection/concept-risky-agents https://learn.microsoft.com/en-us/graph/api/subscribedsku-list?view=graph-rest-1.0
new-cases: 6 fail-on-previous 4
all-cases: pass
quick-checks: pass
changed-files: populate/05-entra-settings.ps1, populate/10-conditional-access.ps1, tools/mock-harness/Cases-Round7p.ps1, tools/mock-harness/Cases-Round7t-Live.ps1 (new)
frozen: kit/20261114-kit-7t/dt-r7t-ro 79decd3c1177 370
full-suite-command: cd 20261114-kit-7t && bash check-suite-7l.sh --mock-timeout 28800 --snapshot dt-r7t-ro --manifest MANIFEST.sha256 dt-r7t full-1 <OPA 1.20.2> <ScubaGear 2446ad7 checkout>
