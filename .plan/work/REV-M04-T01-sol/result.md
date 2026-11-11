## RESULT REV-M04-T01-sol
status: done
summary: verdict: changes-required
  reviewed: 8b18c94ba27c
  All 14 round-2 items are closed. One new blocking defect, fixed by one line G's DEC can carry with no further review: Linux NFS answers flock on a directory with an error the design does not map to `nolock`, so under option A every collection onto Linux NFS would fail to seal. Three new limits. The Q3 options and their section 13 files are accurate.
changes: .plan/work/REV-M04-T01-sol/evidence-3.md only
verification: sha256 of design.md checked (8b18c94ba27c); source reads of guarded_io, run_files, cli_guard, output, private_io, finalize, mcp_registry, output_redaction, cli; flock(2) man page read; no builds, installs or tests run
risks: (1) after the B1 fix, runs collected onto Linux NFS have no key, and only Q3 (d) can render them in place; (2) test impact of revision 3 is not measured (L1); (3) the 3.6 claim about the key temporary is wrong (L-a)
questions_for_g: Q1, Q2 and Q3 as in the design; recommendations below
### Findings
- R1-1 cached contexts: closed (3.6 `_sync_pseudonym_keys` runs at the cached bind, at stdin admission and in `_check_file`; test 9).
- R1-4 fallback without flock: closed (3.4 steps 3, 5 and 8; test 6); its error mapping is incomplete, see B1.
- R1-5 read-only hint: closed as a design item; it is now G's Q3 (15, 3.9, 13).
- R1-P1 reader uses a discarded key: closed (3.4 steps 7-9 and the invariant; test 6); for the durability wording see L-b.
- R1-P2 empty `.gitignore`: closed (3.4 step 6; test 6).
- R1 file scope: closed (13: CHANGELOG.md on M04-T05; registry and hint tests under Q3 (b)).
- R2-N1: folder fsync errors closed (3.4 step 9); a reader racing removal closed (published after fsync, never removed); deletion without flock closed (no creation without a lock).
- R2-N2 security-privacy.md:287-288: closed (13).
- R2-N3 local reports need the key: closed (1, 3.3, 8, Q2; tests 7 and 11).
- R2 item 3 files: closed (13). R2 risk 1: closed as limit L1 plus the test-update rule. R2 risk 2: closed as L3.
- B1, blocking (3.4 step 3, 3.3, 7): Linux NFS emulates flock with fcntl locks, and LOCK_EX needs a descriptor open for writing (flock(2)). A directory descriptor never is, so the lock fails (NFSv4: EBADF). That error is not mapped, so finalisation fails. Fix: every flock error except EWOULDBLOCK/EAGAIN/EINTR is `nolock`, raised before anything is written; test 6 adds EBADF and EINVAL; L2 names Linux NFS.
- L-a, limit (3.6): the claim "a key published after it cannot be that descriptor" is wrong for `.pseudonym.key.<hex>.tmp`, which becomes the key inode. An ordinary guarded read naming it between write and rename gets the key. Pair-writer temporaries have the same exposure today, and it falls inside the section 2 boundary. Fix: register the temporary in the creator's context before writing its bytes, correct the sentence and name the limit in 17.
- L-b, limit (3.4 invariant, L3): between the rename and the folder fsync, and on macOS without F_FULLFSYNC, a visible key is not yet durable; widen L3.
- L-c, limit or a one-line fix (3.5, 3.9 (d)): one context can resolve a run to its session key and later find a key that `prepare-key` has just published, so one output mixes two pseudonyms for a person. Fix: a context keeps the first key it resolved for each run.
- Q3 text and section 13 per option: accurate (the 13 tools match the registry; (b) lists its hint pins and the doc list; (c) and (d) list cli.py and the product manual). Add to every option that, after B1, "storage without locking" includes Linux NFS.
- G Q1: approve, with the B1 line in the DEC. Reports re-render identically, the regression gate keeps full strength, and the only accepted digest change is the scheme name in two demo files.
- G Q2: option A. Every new run gets its key at collection, so no report or read-only tool ever writes into a new run, and runs on read-only archives can still be reported.
- G Q3: option (d). No tool marked read-only ever writes, there are no approval prompts and no refusals, and old runs (and runs on network storage without locking) still render. The cost: until `auditex report prepare-key` has been run once, an old run's pseudonyms change from one session to the next. Under (a), (b) or (c) such runs cannot be reported at all until they are copied.
