# Backlog
<!-- Triaged ideas and unscheduled tasks. Promotion into a milestone is a change-control event. -->

## Now
- Kit advisories from the 7r re-confirmation (both ship at 510f26e348fd), for a later kit round: (1) REV-M07-T11-codex A1: when `Get-MgRequestContext` throws in the read-back the helper returns a reason and the restore only warns, so that exception does not latch the refusal (`populate/_common.ps1:2038`, `:2105`); let it reach the outer latch and add a restore-failure case. (2) REV-M07-T11-opus: the "GRAPH SESSION REFUSED" match at `_common.ps1:1239` is not anchored, so a pre-send refusal inside a create action classifies as ambiguous; also require the "raised after the create request was sent" suffix. Both err on the safe side.
- Kit, inherited from 7q and kept out of round 7r by DEC-014 (REV-M07-T11-codex item 2, REV-M07-T11-opus item 2): only Graph creates are sent with SDK retries off; updates, deletes and three POSTs (assignLicense, members/$ref, the rollback's PIM adminRemove) go out with the default three retries. A later kit round applies the retry-off proof to every write; until then LIMITS states it.

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
