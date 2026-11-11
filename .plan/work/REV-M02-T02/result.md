## RESULT REV-M02-T02
status: done
summary:
verdict: approve
reviewed: 98aae5e1789d
501 rows; 102/102 policies; 188/314 cells; 0 blocking findings.
changes: none
verification: PASS: 12/12 sealed hashes, engine pins, OPA stdin replay, in-memory checker replay, 43/43 in-memory selftests. Native temporary-file checks blocked by read-only; rebuild and copy suites skipped.
risks: Nonblocking coverage, manifest-assurance and future-regeneration limits.
questions_for_g: none
### Findings
1. closed - Labels, outcomes and input hashes reproduce 501/501.
2. closed - All 10/10 not-assessed labels reproduce from their own inputs.
3. closed - Availability matches: 0/501 against 14,547 compared rows; independent probe agrees; deciding-input projections preserve 10/10 full rule results.
4. limit, nonblocking - 126/314 cells uncovered, including 92 not-assessed cells. README: yes.
7. closed - Rehashed false rule hashes, coverage reasons and seed counts rejected 3/3. Remaining limit: no-generated-input claims require regeneration. README: yes.
8. passed - Soundness: 0/3,435 conflicting pack keys; 0/3,849 combined keys. Old recount reproduces exactly: training 171, validation 95, either 174; twin-free 261. Earlier records retained 2/2.
9. Nearest-neighbour probe - Decisive 216/501; full 205/501; policy majority 189/501. Nonblocking baseline limitation. README references the probe but omits these rates.
10. new, limit, nonblocking - Future regeneration retains 1 reproducible name-abstraction collision with 2 verdicts; the soundness gate rejects it. Sealed-set conflicts: 0. README: no.
