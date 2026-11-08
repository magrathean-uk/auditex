## RESULT M01-T02
status: done
summary: Inventory rewritten with all 11 review items fixed; it now has 76 rows, each in exactly one class, and none `unclassified`.
The review's two class-definition gaps are resolved as explicit interpretations: Google reads go in class 1 and SMTP in class 5. The orchestrator must confirm both in the DECISIONS.md entry.
Section E now lists named operations only, with no module-wide SDK exemptions. Power Platform is moved out of the exception table.
changes: none committed. The owned file `.plan/work/M01-T02/transport-inventory.md` sits in the orchestrator checkout and is git-ignored by `.plan/work/.gitignore`. It is not trackable by pathspec, and the worktree status is empty.
verification: the verify command `test -s .plan/work/M01-T02/transport-inventory.md && ! grep -n '| unclassified |' ...` passed, run against the owned file path. It was not run on a committed head, because nothing is committed.
risks: 1) The gates in A4/A5/C2/C3 do not stop content reads (arbitrary `Get-*`, any Graph GET path); T04 must carry that boundary. 2) The Google default scopes include non-read-only ones, which T04 must accept explicitly or change. 3) Token endpoints use an unpinned, operator-configured authority.
questions_for_g: Amend ARCHITECTURE class 1 to name the Google Workspace read APIs and class 5 to name SMTP? Recommended: yes. The alternative is to leave the text and keep the inventory interpretations.

### Findings (review items)
1. Missing auth_runtime.py:51 launcher: fixed, new row C22 (class 8) with callers :194-196, :248 and :255.
2. graph.py:800 batch call: fixed, A6 now records :800 as class 3, and :788 is noted as body construction only.
3. model_serving.py:197 `Request`: fixed, split into A20a (:197) and A20b (:199), both class 6.
4. graph.py:520 two classes: fixed, split into A4a (GET, class 1) and A4b (`$batch` POST, class 3).
5. Overstated PowerShell guard: fixed, C2 and C3 now state that `read_guard` accepts any `Get-*` and name the content-read exposure.
6. Content boundary limitation: fixed, added to A4, A5 and the section F limitations.
7. Section E minimality: fixed, `power_platform.py:67` is moved out to a "not in this table" note.
8. Module-wide SDK allowances: fixed, replaced with named operations (graph.py:433 and :439; auth.py:122 and :125; the lazy service-account refresh identified by its credential construction sites).
9. Definition mismatch: answered, Google is class 1 and SMTP class 5 by explicit interpretation. SMTP is kept out of the T03 HTTP exceptions, and the question for G is raised above.
10. Token destination and gate: fixed, A1 and A2 now describe the operator-configurable authority (no pinning or redirect hardening) and the Exchange and Teams scopes; A11 lists Cloudflare as the default only, with redirects followed.
11. SDK coordinates: fixed, Google `build` is at client.py:118 and :142, and `run_local_server` is at auth.py:125.
