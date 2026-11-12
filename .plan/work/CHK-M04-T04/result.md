## RESULT CHK-M04-T04
status: done
summary: At 0adcc49 all 41 B1 probes (original and variant) mask, and the author's script (67 of 67) reproduces. Of the other probes, 36 of 38 mask. The two that don't are the reviewer's B2 variant, where the engine-written keys `member_type` and `org_unit` are renamed to `user-<hex>`. No name part stays readable in either case. The four focused test files pass (284) and lint passes.
changes: none (branch untouched; my script and output are in the work folder, plus a git-ignored `.venv` link)
verification: focused tests (4 files) pass, 284 passed 0 failed; make lint pass; own probes `.plan/work/CHK-M04-T04/probes.py` run; author's `probes-b1-variant.py` 67 of 67 pass
risks: the `member_type` and `org_unit` key renaming is unchanged from the reviewer's second report; it breaks consumers reading those keys, but leaks no name | none else
questions_for_g: none

### Findings
probes-b1: 41 of 41 mask
probes-other: 36 of 38 mask
script-faithful: no: the author's script drops the evidence.md B1 probe "John B. Smith" and the original-probe texts "John A. Smith wrote" for the recorded John A. Jones case. It uses "John Brown" as the other person for the john.a.smith.brown variant (evidence-2 does not name one), and adds a "Report by" text. It also omits the B2 `member_type` and `org_unit` variant, the two readable A1 orders for "Jane Doe" and "Dr. Jane Doe", and the item-1 comma and title forms beyond its subset. I covered all of these in my script, and the results are in `.plan/work/CHK-M04-T04/evidence.md`.
focused-tests: 284 passed, 0 failed
lint: pass
Readable probes: none. All 41 B1 outputs are masked; none left "John", "Smith", "Jane" or "Doe" readable.
Key-renamed probes (not readable): users "Member Type" and "Org Unit" with keys `member_type` and `org_unit` -> `{'user-b1cb8719216b52b4': {...}}` and `{'user-897cab2b3f412c0f': {...}}`.
