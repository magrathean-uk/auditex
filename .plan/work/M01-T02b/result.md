## RESULT M01-T02b
status: done
summary: Copied the three replay-kit files to ~/dev/machine/records/auditex/replay-kit/v3.9.1/ and wrote README.md there. Its env var is AUDITEX_TEST_VALUE_RULE_VECTORS_V391.
changes: ~/dev/machine/records/auditex/replay-kit/v3.9.1/{vectors.jsonl, a2-vectors.jsonl, a2-label-overrides.jsonl, README.md}
verification: shasum -a 256 on the three copies (pass, all match the pins); wc -lc (pass: vectors.jsonl 26898 lines / 70580540 bytes, a2-vectors.jsonl 3 / 5069, a2-label-overrides.jsonl 190 / 109345)
risks: none
questions_for_g: none
