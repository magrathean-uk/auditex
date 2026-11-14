# STATE
<!-- The only file read at every session start. Max 40 lines. Rewritten by checkpoint.sh and by small edits. -->
overall: 82% (was 80%)
milestone: M03-explainer-training 20%
plan_version: v4
release_scope: 1.5.0 (wider Ruff set, contract-test and gate-doc fixes, keyed per-run D5 pseudonyms plus middle initials and titles, v3 DEC-008/009 scanner follow-ups, review follow-ups, microsoft-skills deletion gate, signed tag plus GitHub release on G's yes naming 1.5.0) beside Track B (explainer model research on Isambard-AI to a judged build and G's pick, stage caps inside the 20,000 GPU-hour allocation per DEC-002; no model in 1.5.0)
last_checkpoint: 8abf9cb 2026-11-14T07:57:40Z

## Next tasks
- M03-T02 Train three seeds of the chosen base on data v2 (terra)
- M03-T03 Build, hash and judge the final explainer build (terra)
- M03-T04 Write the recommendation and the product-integration options (sol)

## Blockers
- Host: quiet window until 00:30 GMT on 14 Nov (manager): until then nothing that takes a heavy slot. From 00:30 GMT heavy steps run again under the usual rule: one heavy slot through hostload.sh, load 12 or less (PLAN_LOAD_MAX=12).
- Track A: 1.5.0 is RELEASED (DEC-052): signed tag v1.5.0 on a1c6b5e, pushed; GitHub release https://github.com/magrathean-uk/auditex/releases/tag/v1.5.0 with exactly the gated wheel (81ea5c2f...) and sdist (959e825f...); a fresh download matches. M06-T05 (independent check of the published files, install and version) is running; then tick M06 item 10 and close M06 with its retro.
- Track B: stopped and on hold (DEC-053, G on 14 Nov: "master data collection etc first ... talk about training AFTER"). The pilot failed (M03-T06: 18 wins of 190, 139 needed; 5.57 GPU-hours). Nothing in M03 moves; amendment 4 (parked case) stays unmerged at bf19a3f. Training is discussed again after phase D. GPU-hours used: about 306 of 20,000.

## Pending G decisions
- Questions go to the team-manager chat with a recommendation and an evidence path, never to G here (DEC-036); its rulings and relayed words count as his. It wants messages only for decisions, blockers, G's hands or eyes, reserved actions and results it asked for.
- Phase D (M07) has first call after the release (DEC-020, DEC-053): kit 7r accepted (manifest 510f26e348fd); the manager asks G for a sitting and opens the tenant chat (in this checkout, no worktree, no /plan). When the tenant chat has the note, record M07-T14 (`handover: kit/20261111-kit-7r/dt-r7r-ro 510f26e348fd`). The tenant is not populated yet: only read-only checks have run.

## Re-baselines
- from 100% (plan v3 closed at 1.4.0) to 4% (plan v4 scope and weights, DEC-001, approved by G on 11 Nov 2026)
- from 13% to 12% (plan amendment 1: M00-T06 and one new M00 item for the as-of date, DEC-005)
- from 36% to 35% (plan amendment 2: milestone M07 at weight 12, M02-T06, new weights; DEC-018)
- from 53% to 52% (plan amendment 3: the data round adds two M03 items, the pilot and data v2; DEC-037)
- from 63% to 62% (M04-T06 added, DEC-045), then from 64% to 65% (M04-T06 stopped for 1.5.0 and its item removed, DEC-048)

## Quota snapshot
<!-- quota:begin -->
claude 57% orchestrator
claude-1 73% ok
claude-2 50% shared
claude-3 69% ok
claude-4 40% ok
claude-5 76% ok
codex 93% hot
codex2 89% hot
<!-- quota:end -->
