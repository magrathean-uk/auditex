## RESULT M02-T06
status: blocked
summary: Blocked because `kit-check twins --heldout heldout/collected` cannot pass honestly on the collected set, and changing checks/twins.py is forbidden by the brief.
summary: Prototype (no kit write): kept 228/501 in collected form (met 92, not_met 111, not_applicable 15, not_assessed 10); 209 unchanged, 19 changed by three value-preserving transforms (single object to list, the product's default scuba_config, DNS rdata to list). The pinned Rego reproduces all 19 labels. 273 dropped (met 125, not_met 139, not_applicable 9).
summary: The drops empty 66 of 188 cells. twins.py `_coverage` knows only three reasons for an uncovered cell: per-policy cap, twin or contradicted candidates, or "no generated input". None is true for these cells, so the only record the check accepts would be false.
summary: The fallback is closed too: every verdict state keeps rows, and the criteria allow per-state scoring only when one would not.
changes: none in the kit or the repository; .plan/work/M02-T06/{notes.md,progress.md,proto_reexpress.py} (work notes only)
verification: brief verify command not run (no result to verify while blocked); prototype checks: 1.4.0 wheel sha256 equals WHEEL_SHA256 pass; T05 agreement 209/501 reproduced pass; pinned Rego (OPA 1.20.2, ScubaGear 2446ad7) reproduces label and outcome on 19/19 transformed rows pass
risks: Minor point if option A goes ahead: the kept set is one row over the 3 per cent share cap (7/228). One drop counted as its own reason fixes it (227 rows, largest 6). twins.py also requires measures.json to say task M02-T02. | The scratch 1.4.0 venv is in the session's throwaway build folder, so a rerun must reinstall the wheel there.
questions_for_g: Pick one. A (recommended): allow a reviewed change to checks/twins.py (its DEC-003 manifest line) so a derived --heldout folder can give a cell the reason "every sealed row was dropped by re-expression", checked against its dropped.json and the M02-T02 sealed rows; take the measures task from the folder; and allow cap-trim drops with their own reason. Then this task builds the collected set and checks/collected.py as specified. B: amend M02-T06 to the per-state fallback on the sealed 501 even though every state keeps rows.
### Findings
prototype-kept: 228/501 (identity 209, transformed 19)
prototype-kept-states: met 92, not_met 111, not_applicable 15, not_assessed 10
prototype-dropped-states: met 125, not_met 139, not_applicable 9, not_assessed 0
prototype-drop-reasons: section not collected 126, item value unusable 68, sharing capability unusable 11, section empty 10, environment field 9, DNS record 8, other 41
prototype-cells: 122/188 kept (66 emptied by drops), policies 78/102
prototype-rego-reproduction: 19/19 transformed rows
blocker: checks/twins.py _coverage has no truthful reason for a cell emptied by re-expression
gpu-hours: heldout 0
Details: .plan/work/M02-T06/notes.md
