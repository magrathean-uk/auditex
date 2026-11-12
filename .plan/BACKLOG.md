# Backlog
<!-- Triaged ideas and unscheduled tasks. Promotion into a milestone is a change-control event. -->

## Now
- Before any M03 scoring: re-express the clean held-out inputs in the product's collected form, or report scores per verdict state (through the 1.4.0 value rules only 209 of 501 rows keep their sealed label; DEC-013, M02-T05). Promote into M02 as a task by plan amendment.

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
- Dummy-tenant kit: round 7q is the accepted kit (12 Nov 2026: both providers ship on the frozen copy, full offline suite 9 of 9 steps; DEC-008 items without the shared sign-in, DEC-010). Round 7l was accepted on 8 Nov. The older live kit folder was not overwritten; bringing it to 7q (keeping the previous state) is a follow-up. Still parked: rounds 7m, 7n and 7o; the shared sign-in opener (its own round and gate, only if G asks). The live run on the trial tenant belongs to the tenant session, on G's sign-ins.
- Hosted CI or merging `wt/github-build-tags-20261108`, only if G asks.
- Housekeeping, only with G: the worktrees and `wt/*` branches left by the pre-plan development rounds, and the development kit's superseded folders (ship-plan scratch tree, superseded v8 and v10 rounds, the cancelled V11 plan); triage and bring G an exact removal list or a script G runs.
