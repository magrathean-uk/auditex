## RESULT M01-FU
status: done
summary: Six task rows and acceptance blocks written (M01-T07 to M01-T12), each with binary criteria, owner, size, tags, dependencies, verify and files.
All six depend on M01-T04 being merged, because they edit its `tests/test_read_boundaries.py` tables. M01-T10 also waits on G's answer on G10.
FU-6 uses an explicit content deny-list in `read_guard._allowed_word`. The guard accepts any `Get-*` today, and about 50 shipped `Get-*` cmdlets would make a full allow-list a maintenance burden.
changes: .plan/work/M01-FU/tasks.md
verification: none; read-only recon of the repo (grep and read) only
risks: M01-T04 is not merged to `main`, so `tests/test_read_boundaries.py` doesn't exist on this checkout and the `_TEXT_EXPOSURES` row edits can't be checked until it lands.
risks: Shared files remain. `tests/test_read_boundaries.py` is edited by T07, T08, T09, T10 and T11 (one row or scope entry each), so those merge one at a time. `src/auditex/google_workspace/client.py` is edited by T07 and T09, so T09 waits for T07.
risks: M01-T08 touches many files (collector, config, normalise, adapter, docs, two demo JSONs, three tests). If rule-pack drift or `make contract-smoke` fails, it may need splitting.
questions_for_g: Same three as M01-T04, none new. G10: keep the read and strip `payload` after receipt (recommend yes); T10 stays blocked until you answer. G3 and G4: keep the post-receipt discard (recommend yes). G7: accept `PrependSubject` as kept (recommend accept).

### Findings
| id | owner | size | tags | depends on | files |
|---|---|---|---|---|---|
| M01-T07 | codex | S | tier-a | M01-T04 | `client.py`, `test_google_workspace.py`, `test_read_boundaries.py` |
| M01-T08 | terra | S | tier-a | M01-T04 | `exchange_policy.py`, `collector-definitions.json`, `normalize.py`, `scuba_adapters_exchange.py`, `api-call-catalog.md`, two demo JSONs, three tests, `test_read_boundaries.py` |
| M01-T09 | codex | S | tier-a | M01-T04, M01-T07 | `client.py`, `test_google_workspace.py`, `test_read_boundaries.py` |
| M01-T10 | terra | S | tier-a, g-gate | M01-T04, G's G10 answer | `data_minimisation.py`, `intune.py`, `intune_depth.py`, two tests, `test_read_boundaries.py` |
| M01-T11 | terra | S | tier-a | M01-T04 | `auth.py`, `collectors.py`, `scope_catalog.py`, two guides, `test_scope_catalog.py`, `test_setup_guide.py`, `test_read_boundaries.py` |
| M01-T12 | codex | M | tier-a | M01-T04 | `read_guard.py`, `tests/test_read_guard_content_cmdlets.py` |

Shared files: `tests/test_read_boundaries.py` (T07 to T11) and `client.py` (T07 and T09). T12 uses a new test file because `tests/test_read_guard.py` belongs to M01-T03.
