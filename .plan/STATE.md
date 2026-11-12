# STATE
<!-- The only file read at every session start. Max 40 lines. Rewritten by checkpoint.sh and by small edits. -->
overall: 46% (was 42%)
milestone: M02-explainer-data-and-judging 75%
plan_version: v4
release_scope: 1.5.0 (wider Ruff set, contract-test and gate-doc fixes, keyed per-run D5 pseudonyms plus middle initials and titles, v3 DEC-008/009 scanner follow-ups, review follow-ups, microsoft-skills deletion gate, signed tag plus GitHub release on G's yes naming 1.5.0) beside Track B (explainer model research on Isambard-AI to a judged build and G's pick, stage caps inside the 20,000 GPU-hour allocation per DEC-002; no model in 1.5.0)
last_checkpoint: 13e817d 2026-11-12T21:39:57Z

## Next tasks
- none

## Blockers
- none
- Host order (G's team-manager chat, 12 Nov, until WGEX says its lab refresh is merged): start a job that takes a heavy slot only while `hostload.sh status` shows one slot held by label M03-T13, or, while WGEX is paused for the clean-dev window, only if both slots are free at that moment. Applies to the M04-T03 executing check and merge, and to M02-T06.

## Pending G decisions
- M04-T04 (branch at b2a69ae, not merged): the privacy review, one repair and one re-check are spent; B2 and the three advisories are fixed, but one blocking variant of B1 remains (a name with a middle initial stays readable when a recorded key runs on past the initial, such as the person's own admin sign-in name). Choice for G: one more narrow repair accepted by rerunning the reviewer's own probes (recommended; the reviewer gave the fix and two tests, and the Codex review still follows), or park it for a Codex author after the reset.
- Kit 7r is accepted (both providers ship, suite 9 of 9; manifest 510f26e348fd). The hand-over note is written (records folder, dt-live/HANDOVER-kit-7r.md) but not delivered: the tenant chat is not open. G opens it (or a new tenant chat) and points it at the note; phase D then runs on G's go and sign-ins.
- Recommendation no, G to confirm: whether training rows must also agree with each other on verdict (6 keys, 16 rows; DEC-026).
- M03-T01 (base comparison) waits only for G's budget look (caps: basecmp 1,024, large 2,048, build 64 GPU-hours; used so far about 60 of 20,000). The training data is complete: 3,005 rows placed (2,738 train, 267 validation) of 3,767 cases, 766 dropped by the checks, one cell (MS.EXO.2.2v3 not_met) listed missing; verify passes (M02-T03 round 3, 12 Nov).
- For G when convenient: the CSV `pseudonym_notice` row on keyless runs (DEC-021); whether the kit README's connection check should prove a browser sign-in (DEC-014).

## Re-baselines
- from 100% (plan v3 closed at 1.4.0) to 4% (plan v4 scope and weights, DEC-001, approved by G on 11 Nov 2026)
- from 13% to 12% (plan amendment 1: M00-T06 and one new M00 item for the as-of date, DEC-005)

- from 36% to 35% (plan amendment 2: milestone M07 at weight 12, M02-T06, new weights; DEC-018)

## Quota snapshot
<!-- quota:begin -->
claude 18% orchestrator
claude-1 63% ok
claude-2 49% shared
claude-3 55% ok
claude-4 6% ok
claude-5 74% ok
codex 91% hot
codex2 85% hot
<!-- quota:end -->
