## RESULT M04-T03
status: done
summary: DEC-024 class closure. Re-discovery after the open now covers run_files reads (rooted at the key folder or above a nested run), each file of a removed tree, and regular-file stdin (found through its descriptor path).
A keyless run with a missing, null, non-string or empty run id gets a key for one guard context only, never kept for the process. The contract says so.
Review items: REV-M04-T03 result 3 blocking A1 fixed (run_files.py:83) and blocking A3 fixed. Advisory: whole-file keyed JSON assertion restored; _write_private regression added. Items 1 and 5 were already closed and stay closed.
Privacy result 2 advisories: run_files fixed, nested tree fixed, missing run id fixed. private_io replace window answered by the regression: no replacement is possible (the folder exists before discovery; with a manifest the bound run's resync refuses the write; without one, discovery refuses).
Not in the criteria and left as they are: a re-collected run keeping the same run id, and a JSON-list copy edge. Full verify deferred: heavy slot busy (hostload exit 75).
changes: src/azure_tenant_audit/guarded_io.py, src/azure_tenant_audit/run_files.py, src/azure_tenant_audit/output_redaction.py, tests/test_redaction_keyed_pseudonyms.py, docs/reference/output-contract.md (commits e3e35f0, 5ebdd81, 2b74f7c)
verification: make lint pass. All 19 pytest files in the verify list plus 13 guard test files pass: 3190 passed, 0 failed (.plan/work/M04-T03/focused-r6*.log). Static parts of the verify command pass (seed strategy, barred files, no added schemas, enum greps, historical literals).
Negative cases, each with its fix reverted (.plan/work/M04-T03/revert-probes-r6.log): run_files and tree "Failed: DID NOT RAISE UnsafeRunFileError"; stdin "assert b'ADMITTED\n' == b'REFUSED\n'"; run id: all 5 cases fail with equal keys; _write_private with the resync removed "DID NOT RAISE"; DEC-023 read, overwrite and remove each fail.
Deferred to the executing check: make test, make contract-smoke, compare-run-outputs digests.
risks: Regular-file stdin now needs a path the platform reports (F_GETPATH on Darwin, /proc on Linux); without one it is refused. remove_guarded_tree now refuses a tree holding a run that does not bind.
Same-run-id re-collection into a reused folder still shares the process key (privacy advisory, outside the criteria).
The full suite and contract-smoke have not run on this head.
questions_for_g: none
### Findings
Entry-point table at head 2b74f7c (full text: .plan/work/M04-T03/entry-points-r6.md). Columns: entry point | re-discovery after open | test, or why it cannot reach the key.
1 guarded_io.open_guarded_file :1020 (read_guarded_bytes, pinned first open, harden_tree, copy_private_file source, cli_guard._pin) | guarded_io.py:1035 | test_dec_023_a1[read]
2 open_pinned_binary re-use :1119 | no new open | re-checks the descriptor row 1 admitted; a key is always a fresh inode
3 open_private_output :1150 (copy_run_file destination, sinks, evidence_db publish) | guarded_io.py:1182 | test_dec_023_a1[overwrite]
4 remove_guarded_output :1207 | guarded_io.py:1221 | test_dec_023_a1[remove]
5 remove_guarded_tree root :1238 | guarded_io.py:1253 | test_dec_023_a1[remove-folder]
6 remove_guarded_tree, each file (a run nested inside the tree) | guarded_io.py:1271 (new) | test_dec_024_removing_a_tree_never_removes_a_nested_runs_key
7 run_files.open_run_file :42 (read, hash, copy_run_file) | run_files.py:83 (new) | test_dec_024_a_run_file_read_re_discovers_after_the_open[key-folder, nested-run]
8 admit_stdin :942 (read_guarded_stdin: auth, guided, demo) | guarded_io.py:957 (new, descriptor path) | test_dec_024_stdin_from_a_key_is_refused_with_no_run_bound; a pipe or tty has no file to discover
9 private_io._write_private :73 (write_private_*, copy_private_file) | none of its own (file not owned) | test_dec_024_write_private_cannot_overwrite_...[bound-run, manifest-later]
10 private_io.make_private_dirs :21 | none needed | directories only; never opens, replaces or removes a file
11 cli_guard._admit_destination :208 | none (file barred) | read-only pre-check; the write goes through row 3 or 9
12 output_redaction scanners :731, :823, :874, :934 | none needed | open only *.json under normalized/; key names never match; hard links refused
13 evidence_db build directory :182, :276, :283 | none needed | its own new folder with fixed sqlite names; publish via rows 3 and 4
14 output.py writer private pairs :442-487 | none needed | fixed sensitive-users, partner-domains and .gitignore names only
15 GuardContext bind_run, sync, pseudonym_key, create, gitignore, verified_* | n/a | the key's own reader and creator; only pseudonym_key returns its bytes
