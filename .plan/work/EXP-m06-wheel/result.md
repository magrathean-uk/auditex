## RESULT EXP-m06-wheel
status: done
summary: The wheel hash depends on the umask of the shell running `make dist`, because `tar -xf` applies it to the exported sources and the zip records the file modes. A build under umask 077 gives the gated 81ea5c2f, and one under umask 022 gives 289508b7, which is the wheel now in `dist/`. Only the zip mode bits differ, so contents and RECORD are identical. The sdist is unaffected.
changes: none (builds only under $TMPDIR; notes.md and progress.md written to the work directory)
verification: six fresh-clone `make dist` builds of a1c6b5e, run through the heavy slot, plus a member-by-member wheel comparison: pass
risks: Shipping 289508b7 means the pre-publication gates and release smoke ran on a different file, unless G accepts that the contents are identical. `scripts/check-reproducible-build.py` cannot see umask differences. `make dist` stays umask-sensitive until a follow-up fix.
questions_for_g: none

### Findings
1. Cause (measured). I built from fresh clones of a1c6b5e with the main `.venv` Python and `SOURCE_DATE_EPOCH` unset:
   - umask 077 (builds A, B and E; E also with TZ=Asia/Tokyo): wheel 81ea5c2f00bca2d0a880f4fe2527a7a917329396aaaba207c1da00f6ce444eba. Members are mode 0600, so this is the gated wheel. TZ made no difference.
   - umask 022 (build C): 289508b7b0e6e401b35b33530047b84a32a67116313c66e6be3b014ba81b8ece. Members are mode 0644, and it is byte-identical to the wheel now in the candidate `dist/` (`cmp`).
   - umask 002 (build D): ac35b94be0e4dcc0345c1c0108ab8a822e9dcfba007e9826053dbe7aa84957ea.
   - Between 81ea5c2f and 289508b7 all 307 member names, sizes, content hashes and RECORD are identical. Only `external_attr` differs, on 305 members: 0600 against 0644. All zip timestamps are 2026-11-14 03:57:28 in every build.
   - The gated build ran under umask 077. The `make dist` re-run at about 07:55 ran under 022, which I infer from the mode bits. The venv's setuptools 84.2.1 and wheel 0.48.0 have not changed since 26 Oct, and a leftover `build/` folder is not involved because `make dist` builds in a fresh export.
2. Correct artefact (inferred). The wheel gated by the M06-T02 steps is 81ea5c2f. 289508b7 is functionally identical, since pip only honours the executable bit. The sdist is unaffected (measured): 959e825f2bcd769222789c1b5fc3fff8f2acbfc955ba6c9473c6807563b6ee1a in all six builds, because `check-reproducible-build.py --normalise-sdist` forces modes to 0644 or 0755.
3. Reproducible-build check (measured and inferred). It would not have caught this. `scripts/check-reproducible-build.py` builds twice in the same process and shell, so umask and environment are the same both times, and it compares only the raw wheel and sdist bytes. It has no umask or cross-environment case. The step-7 log shows the pair identical at 81ea5c2f.
4. Smallest safe way to ship (measured). Nothing needs re-gating if you restore the gated wheel:
   - Run `(umask 077; make PYTHON=<main .venv python> VENV=<main .venv> dist)` in the candidate worktree, then confirm `shasum -a 256 dist/*.whl` prints 81ea5c2f.
   - I did not run this in the worktree, because the brief said not to touch `dist/`. A build under umask 077 in a clone gave 81ea5c2f, and the sdist stays 959e825f.
   - If the 0644 wheel is ever preferred, the whole wheel gate would have to be re-run.
   - Suggested follow-up, not for this release: add `umask 022` to `make dist`, and make the reproducible-build check build once under a different umask.
