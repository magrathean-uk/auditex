## RESULT M01-T07
status: blocked
summary: Request-level masks exclude the text needed to derive the existing length and presence fields, so live collected output cannot also remain byte-identical.
changes: none
verification: Not run; the acceptance criteria conflict.
risks: clean-development doctor failed: lifecycle lock has a dead or unverifiable owner; GUI environment and DerivedData routing also differ from expected values.
questions_for_g: Should live Gmail output omit the derived length and presence fields when their source text is excluded, while preserving existing offline fixture behaviour?
