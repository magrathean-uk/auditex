"""Text normalisation shared by every checker.

Order of operations for matching (plan section 3: "after Unicode NFKC and case folding"):
  1. NFKC (folds full-width letters and digits, ligatures, non-breaking and exotic spaces, compatibility dashes are kept for step 3);
  2. delete zero-width and bidi-control characters and the soft hyphen (they split words invisibly: "non​-compliant");
  3. fold single-script look-alikes (Cyrillic and Greek letters that render like Latin letters) to Latin;
  4. map every dash-like character (hyphen, non-breaking hyphen, figure, en, em, horizontal bar, minus, small and full-width hyphen) to "-";
  5. straighten curly quotes and apostrophes; collapse whitespace; casefold (optional).
Mixed-script words are reported separately (check S fails them: they are an evasion, not prose).
"""
import re
import unicodedata
from functools import lru_cache

ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍‎‏⁠⁡⁢⁣⁤﻿­᠎‪‫‬‭‮⁦⁧⁨⁩"))
DASHES = "‐‑‒\u2013\u2014―−﹘﹣－⁃⸺⸻"
DASH_MAP = {ord(c): "-" for c in DASHES}
QUOTE_MAP = {ord(c): "'" for c in "‘’‛ʼ′`´"}
QUOTE_MAP.update({ord(c): '"' for c in "“”„‟″"})
# Cyrillic and Greek letters that are visually Latin (a deliberately small, documented table; NFKC does not touch them)
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "һ": "h", "ѕ": "s", "ԁ": "d", "ԛ": "q", "ԝ": "w", "к": "k", "м": "m", "т": "t", "н": "h",
    "в": "b", "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P",
    "С": "C", "Т": "T", "Х": "X", "У": "Y", "І": "I", "Ј": "J", "Ѕ": "S",
    "ο": "o", "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ρ": "p", "υ": "u", "χ": "x",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N",
    "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
}
CONF_MAP = {ord(k): v for k, v in CONFUSABLES.items()}
_WS = re.compile(r"\s+")


@lru_cache(maxsize=1024)
def script_of(ch):
    if ch.isascii():
        return "latin" if ch.isalpha() else None
    name = unicodedata.name(ch, "")
    if name.startswith("CYRILLIC"):
        return "cyrillic"
    if name.startswith("GREEK"):
        return "greek"
    if name.startswith("LATIN"):
        return "latin"
    return "other" if ch.isalpha() else None


def mixed_script_words(text):
    """Words (whitespace tokens) that mix Latin with Cyrillic or Greek letters. Computed on the NFKC text, before look-alike folding."""
    out = []
    t = unicodedata.normalize("NFKC", text).translate(ZERO_WIDTH)
    for w in t.split():
        scripts = {script_of(c) for c in w} - {None}
        if len(scripts) > 1 and ("latin" in scripts) and (scripts & {"cyrillic", "greek"}):
            out.append(w)
    return out


@lru_cache(maxsize=8192)
def norm(text, fold=True):
    t = unicodedata.normalize("NFKC", text).translate(ZERO_WIDTH)
    t = t.translate(CONF_MAP).translate(DASH_MAP).translate(QUOTE_MAP)
    t = _WS.sub(" ", t).strip()
    return t.casefold() if fold else t


_ABBR = (("e.g.", "e․g․"), ("i.e.", "i․e․"), ("U.S.", "U․S․"), ("etc.", "etc․"), ("vs.", "vs․"), ("approx.", "approx․"),
         ("No.", "No․"), ("St.", "St․"), ("Inc.", "Inc․"), ("Ltd.", "Ltd․"))
_SENT = re.compile(r"([.!?][\"')\]]*)\s+(?=[A-Z0-9(\"'])")


def sentence_split(text):
    """Sentences of `text` (case preserved). A full stop, question or exclamation mark (optionally followed by closing quotes or brackets) and whitespace, then a capital
    letter, digit, bracket or quote, ends a sentence; common abbreviations are protected."""
    t = text.strip()
    for a, b in _ABBR:
        t = t.replace(a, b)
    out, last = [], 0
    for m in _SENT.finditer(t):
        out.append(t[last:m.end(1)])
        last = m.end()
    out.append(t[last:])
    return [p.replace("\u2024", ".").strip() for p in out if p.strip()]


def words(text):
    """Whitespace-delimited word count (the unit of the plan's 80-word and 30-word limits)."""
    return len(text.split())
