## RESULT M04-T05
status: done
summary: Applied all three fix-2 items to the limits list in docs/reference/security-privacy.md. Probing the matcher on the branch head confirms each changed sentence and the rest of the list. All criteria met, including the previous rounds' items, which the re-check found correct.
1 fixed: removed the decomposed-initial clause. The zero-width space and fullwidth full stop stay, and both are still readable when probed.
2 fixed: the several-initials item now says the whole string is withheld as `<redacted-text>`, or the name is masked when the full name is recorded. Matches tests/test_redaction_person_names.py:812-817.
3 fixed: the trailing-mark limit now says the old matcher masked this name when the mark was a separate character, but left the mark after the pseudonym. Probed on 8a72e59^, the code before M04-T04: the precomposed form stayed readable even then, so the sentence covers only the separate-mark form.
changes: docs/reference/security-privacy.md (commit c55748e)
verification: verify doc greps (prepare-key and pseudonym.key in security-privacy.md, prepare-key in product-manual.md and CHANGELOG.md): pass. The `read-through: complete` grep reads result.md, which is written from this block; the previous job-2/result.md passes it. make lint: pass (compileall, Ruff "All checks passed!"). Matcher probes of every limit with an example, read-only through the main .venv: all match the doc. git status --porcelain: empty.
risks: The item 3 wording rests on one probe of the pre-M04-T04 code, not on a test. The several-initials line now describes masking inside a list headed "These limits stand", which reads slightly unevenly.
questions_for_g: none
### Findings
read-through: complete
Removed-term survivors: "decomposed" is still at :584 (spellings that match) and :644 (the `Zoe Vosk` limit), and both are still true. "several middle initials" is still at :609, in the reworded item.
