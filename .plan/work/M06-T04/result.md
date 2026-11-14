## RESULT M06-T04
status: done
summary: Release 1.5.0 is tagged and published on the candidate under DEC-052. The release step's first rebuild gave a different wheel hash (289508b7..., file modes 0644) because it ran under umask 022; the gates had built under umask 077 (modes 0600), with identical contents and RECORD (EXP-m06-wheel). Rebuilt under the gates' umask, both files equal the gated hashes, so case 1 of the manager's ruling applied and nothing was re-gated. The signed tag needed no touch or passphrase.
changes: tag v1.5.0 (local and origin); GitHub release v1.5.0 with two assets; .plan/work/M06-T04/{result.md, logs/dist.log, logs/dist-umask077.log}
verification: rebuild under umask 077 in the candidate worktree: wheel and sdist equal the M06-T02 record; git tag -v v1.5.0 with a per-command allowed-signers setting: Good "git" signature; v1.5.0 peels to the candidate; origin carries the same tag object and peels to the candidate; gh release view: two assets, not draft, not pre-release; fresh download of both assets: hashes equal the M06-T02 record
risks: this machine has no allowed-signers file, so a bare git tag -v fails here for every SSH-signed tag (v1.4.0 too); the verify was run with GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=gpg.ssh.allowedSignersFile pointing at a temporary file holding the signing key. make dist is umask-sensitive (BACKLOG).
questions_for_g: none
### Findings
candidate: a1c6b5e6e54e1fcc8fb224868a7e8467c723d262
tag: v1.5.0 e7d2e3ead17e8da617e786d3c993a1e6ae68b446
release: https://github.com/magrathean-uk/auditex/releases/tag/v1.5.0
uploaded-wheel-sha256: 81ea5c2f00bca2d0a880f4fe2527a7a917329396aaaba207c1da00f6ce444eba
uploaded-sdist-sha256: 959e825f2bcd769222789c1b5fc3fff8f2acbfc955ba6c9473c6807563b6ee1a
first-rebuild-wheel-sha256 (not published): 289508b7b0e6e401b35b33530047b84a32a67116313c66e6be3b014ba81b8ece (umask 022)
