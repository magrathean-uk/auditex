# Backlog
<!-- Triaged ideas and unscheduled tasks. Promotion into a milestone is a change-control event. -->

## Now
- Kit wording advisory from the 7q confirmation (REV-M07-T10-codex item 5): `populate/README.md:9` diagnoses directory replication from the HTTP status alone; word it "can be directory replication". Round 7r's brief asks its author to clear it; drop this line when M07-T12 shows it cleared.
- Kit wording advisory from the 7q confirmation (REV-M07-T10-opus item 3): `99-rollback.ps1:736-737` say "absent-resolved intent" for a refused intent too; word it "absent- or refused-resolved intent". Same handling as the line above.

## Next
- Product integration of a model explainer, only after G's build pick in M03: the options M03-T04 lists (the template stays the default and the fallback; no model verdict; local only).
- Hugging Face upload of a build that passed its bar, only on G's yes (publishing; the card names no infrastructure).
- The 7 entries in `configs/explainer-baselines.json` (109) that the template (102 policies) does not use: diff the keys and keep, document or bring for the deletion gate (INV4-explainer, inferred).
- Whether the customer-pack builder emits `policy_explanations` (`src/auditex/reporting.py:100` lists the section; builder untraced, INV4-explainer).
- A Ruff format hook, after the wider rule set lands.
- Historical schema copies `schemas/model_assessment-2026-10-2*.json`: confirm which readers still need them; any removal goes through the deletion gate (INV4-d5, inferred).

## Later
- Answer the SCuBA Google Workspace baselines from the Google provider (today an internal control map with no value-rule path).
- Live-tenant work, parked until G raises it: certificate auth live acceptance (`wt/collect-certauth-1`), presets, IPPS, Teams coverage, the day-one run, `-Enforce`, and the SS 2.1 `TargetedUsersToProtect` live wire-shape gate.
- Dummy-tenant kit: round 7q is the accepted kit (12 Nov 2026: both providers ship on the frozen copy, full offline suite 9 of 9 steps; DEC-008 items without the shared sign-in, DEC-010). Round 7l was accepted on 8 Nov. Round 7r, the gate, the hand-over, bringing the older live kit folder to the accepted round (previous state kept), phase D's record and the rollback are milestone M07 (plan amendment 2). Still parked: rounds 7m, 7n and 7o; the shared sign-in opener (its own round and gate, only if G asks). The live run on the trial tenant belongs to the tenant session, on G's sign-ins.
- Hosted CI or merging `wt/github-build-tags-20261108`, only if G asks.
- Housekeeping, only with G: the worktrees and `wt/*` branches left by the pre-plan development rounds, and the development kit's superseded folders (ship-plan scratch tree, superseded v8 and v10 rounds, the cancelled V11 plan); triage and bring G an exact removal list or a script G runs.
