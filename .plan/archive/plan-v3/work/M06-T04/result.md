## RESULT M06-T04
status: done
summary: All seven steps passed with no retries. The signed tag v1.4.0 (object 45dcd2d5dd806d2b2ad50c33d3ae06b976778c79) points at 5843f0b4977c410f484502d424b6151d54d7be94 and is the only ref pushed.
The release at https://github.com/magrathean-uk/auditex/releases/tag/v1.4.0 is not a draft or prerelease and lists exactly two assets, with GitHub digests equal to the local hashes.
Uploaded wheel sha256: cd66fe86c9723031f3d114e02c89faeb3eeb81480739780aa9bd87d9639b0497
Uploaded sdist sha256: d41f154a116cf006839ac87d6dfb889f830ef4002258d03596106e33c7272554
changes: none (tracked files untouched; git-ignored `.venv` link and `dist/` created in the worktree; evidence in .plan/work/M06-T04/evidence.md)
verification: HEAD, local tag and remote tag preconditions pass; `make dist` pass, both hashes match the gate record; `bash scripts/release-smoke.sh dist` pass ("release smoke ok"); `gh auth status` pass (github.com, repo scope); `git tag -v v1.4.0` with a temporary allowed-signers file pass (Good "git" signature, ED25519 SHA256:mJ3ux0ijg8cGLHuLbdvZcYcTmhfchnTe1AWzE0XD6pQ); `git push origin refs/tags/v1.4.0:refs/tags/v1.4.0` pass, `git ls-remote` shows the tag and peeled commit; `gh release create ... --verify-tag` pass; `gh release view v1.4.0 --json assets,url` pass
risks: The session-start hook reported a clean-development lifecycle registration failure. I did not run `clean-development doctor`, as instructed, and it did not affect this task.
questions_for_g: none
