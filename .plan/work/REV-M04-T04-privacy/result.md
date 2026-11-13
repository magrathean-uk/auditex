## RESULT REV-M04-T04-privacy
status: done
summary: verdict: approve
reviewed: d7b44247c103ba17d204be71b778184080691dd3
All 41 earlier B1 probes are now masked, against 9 of 41 at b2a69ae. No plain name in a common form is left readable, the budget holds, pseudonyms are unchanged and nothing is dropped.
One narrow new readable case: a name with an extra combining mark after its last letter. Withholding reaches the whole string, which in the final pass is the whole rendered file. Detail in .plan/work/REV-M04-T04-privacy/evidence-3.md.
changes: none (review files only: .plan/work/REV-M04-T04-privacy/evidence-3.md, progress.md)
verification: probe scripts under $TMPDIR, run on HEAD and on b2a69ae: earlier probe set pass (41/41 B1); new-behaviour probes done; budget fuzz over 1.38M texts pass; old/new corpus of 725 rows done; prose and hostile-key probes done. Full suite, benchmark and contract-smoke not run (the brief excludes them).
risks: the final pass can reduce a whole report or pack file to "<redacted-text>" without saying why; a stray combining mark after a name's last letter now stays readable; none else
questions_for_g: none
### Findings
1 Earlier probes: B1 41 of 41 masked (9 of 41 at b2a69ae). The other 38 are identical to b2a69ae, pseudonyms included. The member_type and org_unit renames are still there (over-masking, the earlier advisory).
2 The placeholder is the constant "<redacted-text>": it shows no length, no position and no user, only which field, item or key was withheld, plus "#n" counts inside one mapping. Parts-only records are masked in their full forms (src/azure_tenant_audit/output_redaction.py:496-497). Composed and decomposed spellings are masked both ways in six scripts (:1251-1255). Joined keys up to six tokens are masked, and title or initial snake keys are withheld (:1726-1766). A 10 MB key is returned before any regex runs, with 0 bytes traced and 0 probes (:1734).
3 No regression against the limits you set: at most 6 probes per start, window at most 6, 0 changed pseudonyms, pseudonym() under the 32-byte key unchanged, and withheld keys keep their values. New readable case: an extra trailing combining mark (22 of 725 corpus rows). Separately, a name recorded decomposed and written without its accent is no longer masked; it had been masked by accident. Neither is a common form.
4 Over-masking trigger: any token that starts a directory key (a first name, a sign-in token, even "a" from a.vosk) followed by at least 4 single letters inside the window, joined by space, comma, dot, hyphen, underscore or apostrophe. Where a key holds an initial, 2 letters are enough ("Neral A. Vosk, B. Vosk"). Reach is the whole string, and in the markup final pass the whole Markdown, HTML, CSV or pack file. Rate: 0 of 9 ordinary sentences, only deliberate letter runs (3 of 12 test sentences), and 0.48% of letter-dense random text. A reader cannot tell that a name caused it.
### Stated limits
Withheld: the whole string (a field, list item or key, or a whole rendered file in the final pass) when a name start is followed by more initials than the six-token window resolves, as in "First A B C D E Last".
Readable: "Vosk Taren" in "Neral A B C D Vosk Taren" when another user is known only as "Neral" (the window ends on a non-initial).
Readable: a name whose last letter carries an extra combining mark the recorded spelling lacks ("Orin Pasḱ"); it was masked before this change.
Readable: the accent-dropped spelling of a name recorded in decomposed form ("Zoe Vosk" for a decomposed "Zoë Vosk"), within the documented dropped-diacritics limit.
Readable: a name with an invisible character inside it (zero-width joiner, soft hyphen, combining grapheme joiner, variation selector), or with a combining mark after a space.
Readable mapping keys: camel-joined with a title or initial (DrNeralVosk, NeralAVosk), suffixed (neral_vosk_adm), reversed (vosk_neral), with an edge initial (a_neral_vosk) or with middle names as initials (orin_t_m_pask).
Readable mapping keys: over six tokens, or with a token over 64 characters, stay as written.
Withheld mapping keys: snake or hyphen keys whose title- or initial-stripped form is a person (dr_neral_vosk, neral_x_vosk) become "<redacted-text>", with "#n" on collision and the value kept.
Parts-only records: the given and family fields are withheld. "N. Vosk" and either part on its own stay readable. Parts with stray spaces or a different case take their own pseudonym.
