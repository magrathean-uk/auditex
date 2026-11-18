# M11-T02 phase 1 dry run evidence

Command: `bash kit/attack/dryrun.sh <auditex checkout> <empty folder> <product python>` (product at main 2ac9134), exit 0.

    ok: shell syntax (7 scripts)
    ok: python syntax
    ok: fuzzer: one seed, the same bytes
    ok: fuzzer: another seed differs
    ok: fuzzer: bidi weight 6 raises its strings from 47 to 354 of 500
    ok: negative case fails as it must: fuzzer: a weight for an unknown form (ValueError: weights name unknown forms: ['telepathy'])
    ok: staged kit/attack verifies
    prescreen: 512 tenants, 57 stop, 10 with a verdict off the intent, 0 controls failing
    ok: round 1: 2048 strings {'stub': 1024, 'fuzzer': 1024}, 256 copies and 256 controls; controls and intent byte-identical to the corpus
    ok: negative case fails as it must: plant: 1,999 strings (plant: 1999 strings, a round needs at least 2000)
    ok: negative case fails as it must: gen: the same round again (gen: <path> already has strings; a round is never rewritten)
    ok: prescreen: 512 tenants, 57 stop, 10 with a verdict off the intent, 0 controls failing
    ok: negative case fails as it must: prescreen: a control holding a lone surrogate (prescreen: 1 tenants, 1 stop, 0 with a verdict off the intent, 1 controls failing)
    round 1: 8 tricks (8 unattributed), complete False, classes {'intent:unattributed': 4, 'stop:unattributed': 4}
    split: 2 copies with an unattributed trick -> 16 single-string copies -> <path>
    round None: 8 tricks (0 unattributed), complete False, classes {'intent:surrogate': 4, 'stop:surrogate': 4}
    round 1: 8 tricks (0 unattributed), complete False, classes {'intent:surrogate': 4, 'stop:surrogate': 4}
    ok: round 1 (3 copies, 4 models): 8 tricks {'intent:surrogate': 4, 'stop:surrogate': 4}; O2 (a lone surrogate stops finalisation) and a rule verdict turned not assessed, each named to one string by the split pass ['r01-s00043', 'r01-s00107']; the third copy has none; a subset round is never complete
    retrain: 2 tricked strings -> 2 cases {'train': 1, 'validation': 1}, weights {'instruction': 1.0, 'verdict_word': 3.0, 'id_word': 1.0, 'delimiter': 1.0, 'homoglyph': 3.0, 'bidi': 3.0, 'zero_width': 1.0, 'surrogate': 5.0, 'control': 1.0, 'combining': 1.0, 'long': 3.0, 'nesting': 1.0}
    ok: retrain: the surrogate weight rose
    ok: negative case fails as it must: finetune --check: one case only (no validation case) (finetune: needs at least one train and one validation case)
    retrain: 200 tricked strings -> 18 cases {'train': 17, 'validation': 1}, weights {'instruction': 3.08, 'verdict_word': 2.4, 'id_word': 2.28, 'delimiter': 3.26, 'homoglyph': 1.36, 'bidi': 1.34, 'zero_width': 1.54, 'surrogate': 1.14, 'control': 1.28, 'combining': 1.32, 'long': 1.2, 'nesting': 1.06}
    ok: finetune --check on 200 synthetic tricked strings
    ok: round 2 with the retrained weights: surrogate strings 126 -> 453 of 2048
    ok: negative case fails as it must: a planted string printed as a free line is a trick ({'leaks:instruction': 1, 'summary:unattributed': 1}), attributed to r01-s00000 alone; round not clean
    ok: a planted copy whose answer equals its control's: no trick, round clean
    round None: 0 tricks (0 unattributed), complete False, classes {}
    ok: negative case fails as it must: a control without a line makes the round incomplete (exit 1)
    gpu-hours: not inventoried
    ok: loop status clean: attack-loop: clean (clean as it must)
    gpu-hours: not inventoried
    ok: loop status trick-before: attack-loop: open (open as it must)
    gpu-hours: not inventoried
    ok: loop status base-attacker: attack-loop: open (open as it must)
    gpu-hours: not inventoried
    ok: loop status two-commits: attack-loop: open (open as it must)
    gpu-hours: round-01 2.0000
    gpu-hours: total 2.0000
    ok: inventory: 720 + 3600 + 1800 + 1080 GPU-seconds = 2.0000 GPU-hours, every attempt counted
    ok: inventory SHA256SUMS
    dryrun: pass
