# Ordinary English word list

`english-words.txt` contains 419 ordinary words authored for this Auditex
checker port on 5 November 2026. Source: original Auditex test vocabulary;
licence: Apache-2.0, as for this repository. No system dictionary, third-party
word-list extraction, training identifiers or adversarial proper names were
copied into this list. It is a small heuristic vocabulary, not a dictionary.

The words cover ordinary grammar, audit prose, numbers and spatial language.
Numbers and settings still pass the independent specifics whitelist. A common
word used as a group or person's name is not automatically a safe identifier.
No code adds words learned from candidates or benign/mutation failures.

SHA-256 of the UTF-8 file, including its final newline:
`b619cca2de479ba35eb5a2c4fd7f3012089b503dd2bca29ccdcf6ff647d70ee9`

Only check b's sentence-initial proper-name heuristic uses this list. Other
proper-name, identifier, setting, acronym and phrase checks remain active.
Missing, empty, duplicate, unsorted or malformed lists fail setup. The tests
explicitly deny access to `/usr/share/dict/words`; Linux needs no replacement
system dictionary. A real Linux run remains an integration check.

The author reviewed these ordinary words for this port. Product-owner approval
and independent review are pending; this file does not imply their approval.

Integration adjudication: added analytics, an ordinary English noun for systematic data analysis. W19 still misses its intended c/d checks; no product or tenant name was added.
