## RESULT REV-M04-T01
status: done
summary: verdict: changes-required
  reviewed: 8b18c94ba27c
changes: none
verification: PASS SHA-256 comparison and clean git status; static review completed; FAIL clean-development doctor (dead/unverifiable lifecycle-lock owner), no repairs; builds and suites excluded by brief.
risks: temporary-key disclosure; mixed pseudonyms under Q3(d); lifecycle ownership remains unverified.
questions_for_g: Q1, Q2 and Q3; recommendations below.
### Findings
- R1 finding 1: closed for published keys, §3.6. Cached binds, ordinary admission and stdin now synchronise registration; the new temporary-file gap is below.
- R1 finding 4: closed, §3.4 steps 3-8. Creation requires locking; waiting creators recheck and reuse the published key.
- R1 finding 5: open for G, §§3.9/15 Q3. The disagreement is correctly escalated. Choosing the behaviour is required before implementation; it is not an implicit §17 waiver.
- R1 P1: closed, §§3.4-3.5. Failed key-file fsync prevents publication; later failures retain the published key.
- R1 P2: closed, §3.4 step 6. Existing ignore content is validated; replacement uses a fully written temporary.
- R1 file scope: closed, §13. CHANGELOG.md, registry descriptions, hint tests and the privacy-list dependency are allocated.
- R2 N1, unsupported directory fsync: closed as specified, §3.4 step 9; its crash-durability consequence remains L3.
- R2 N1, reader using a subsequently removed key: closed, §§3.4-3.5. Atomic publication and retention replace the proposed reader lock.
- R2 N1, storage without locking: closed, §§3.3-3.4. No creation occurs; the collection fallback is explicit. L2 can stand as a named limit.
- R2 N2: closed, §13. The security-privacy.md control-file-limit passage is included.
- R2 N3: closed, §§1/3.3/8/15 Q2 and tests 7/11. Local-report consequences are explicit.
- R2 item 3: closed, §13. Each Q3 option has its additional files: (a) descriptions; (b) hints, tests and privacy list; (c)/(d) CLI and product manual.
- R2 risk 1: open, §17 L1. Unmeasured test impact can stand as a design limit; implementation still needs its required checks.
- R2 risk 2: open, §17 L3-L4. Unverified network durability and cross-host locking can stand as named storage limits.
- R1 tooling risk: open, §16. Lifecycle ownership remains an external operational issue; it does not block this design review.
- New blocking, §§3.4 step 7/3.6: an ordinary guarded reader can admit `.pseudonym.key.*.tmp` before publication, obtain its bytes, then watch that inode become the run key. Only the final name is synchronised. Protect temporary identities across processes and stdin before exposing secret bytes; test a paused creator.
- New limit, §§3.4/17 L3: the run directory is not fsynced after creating `operator-inputs`, and a directory-fsync EIO leaves a readable key. Crash-loss risk therefore extends beyond unsupported directory fsync. Broaden L3 and qualify the “durable” invariant; this can stand as an explicit storage limit.
- New blocking if Q3(d), §§3.5/3.9: a command can use its session key, then switch to a concurrently prepared file key on a later context lookup. One customer pack can contain different pseudonyms for the same person. Pin the selected key throughout the operation; L6 currently covers only differences between sessions.
- New blocking decision-text accuracy, §§13(a)/15: MCP hints do not guarantee approval prompts on every call. Also, keyless 1.5.0 runs inherit Q3, so the unconditional new-run promises and “cost falls only” on older runs are inaccurate. Descriptions must cover every keyless run.
- G Q1: recommend `seed`, the narrow label-only digest exception, additive schema enum and bounded test-update rule after the blockers above are resolved. These preserve strong regression checks and reproducible customer reports.
- G Q2: recommend A. Creating the key during collection gives normal completed runs stable identities and supports reporting from read-only archives; retain the explicit no-lock exception.
- G Q3: recommend (c). One preparation step gives old runs stable customer reports and accurate read-only hints. Choose (d) only if session-varying archive reports are acceptable and the concurrent-preparation defect is fixed.
