## RESULT CHK-M04-T03
status: done
summary:
check: pass
checked: 2b74f7c52b7b827313911f289584444b93d0b219
Verify exit 0: focused pytest 2496 passed, `make test` 22929 passed, `make contract-smoke` ran, and all 43 digests match.
Negative cases: 11 of 11 failed as they must.
changes: none
verification:
- Verify command from the M04-T03 acceptance block, run as a recorded job under `hostload.sh`: exit 0, pass. The first launch was killed by my own 10-minute background limit at about 10 per cent, so I restarted it with a longer limit.
- `auditex report prepare-key <missing dir>`: exit 2, pass
- `auditex report prepare-key <empty dir>`: exit 2, pass
- `auditex report prepare-key` (no argument): exit 2, pass
- `auditex report prepare-key <dir> extra`: exit 2, pass
- `auditex report prepare-key --run <dir>`: exit 2, pass
- `auditex report prepare-ke <dir>` (abbreviated subcommand): exit 2, pass
- `pseudonym(16-byte key, ...)`: ValueError, pass
- Key file of 10 bytes, 33 bytes, mode 0644 or a symlink: `UnsafeRunFileError` for each, pass
- `jsonschema.validate` of a bad `strategy` against the `model_assessment` enum and a bad `reason` against the `bundle_hashes` enum: both rejected, pass
risks: `git status --porcelain` is clean, so the verify changed no tracked path. The `.venv` link I made in the worktree is git-ignored.
questions_for_g: none
### Findings
- `prepare-key` on a missing or empty directory: expected refusal, got exit 2 with "Refusing run-dir: unsafe input."
- `prepare-key` with no argument, an extra argument, `--run` or the abbreviated `prepare-ke`: expected argument error, got exit 2 with "invalid arguments".
- `pseudonym()` with a 16-byte key: expected a refusal, got ValueError.
- Key file of 10 bytes, 33 bytes, mode 0644 or a symlink to `/etc/hosts`: expected a refusal, got `UnsafeRunFileError` each time.
- `model_assessment` strategy enum and `bundle_hashes` `excluded` reason enum: a bogus value is rejected by both.

Evidence is in `.plan/work/CHK-M04-T03/evidence.md`.
