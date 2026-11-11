"""Extraction of 'specifics' (things a text could invent) and the tokenisation rules for each class (checks b, d and e).

Rules (applied to the NFKC, zero-width-free, dash-folded text with case kept; keys are case-folded):
  Identifier classes, extracted first and masked so that nothing inside them is re-read as a number or a name:
    url      scheme://..., www.... ; email (local@domain, including the report's masked form ***@domain); guid (8-4-4-4-12 hex) and bare 32-hex;
    ipv4 (with optional /prefix); domain (labels ending in a known top-level domain: gTLDs, onmicrosoft, a short list of country codes);
    policy_id (MS.AAD.3.2v1, also without the v suffix); hex (8 or more hex digits with at least one digit and one letter a to f).
  Name classes:
    cmdlet     Verb-Noun with an approved PowerShell verb and a capitalised noun (Get-MgUser);
    parameter  -Capitalised (-AuditDisabled; the dash may have been an en dash);
    snake      a_b_c identifiers;  camel  lowerCamel, UpperCamel with two humps and acronym-led names (EnableAdminConsentRequests, M365Environment);
    quoted     text inside straight or curly double quotes or paired single quotes.
  Numbers: digits (thousands separators and one decimal point allowed; a trailing %, unit letter or ordinal suffix is dropped; not when glued to a letter on
    the left, so e1, v37, M365 and MS.AAD ids are not numbers) and number words two..ninety, hundred, thousand, million, dozen (compound twenty-one too).
    "one" is deliberately NOT extracted (too common as a pronoun) - a documented limit. "Microsoft 365", "Office 365" and "M365" are product names, not numbers.
HEURISTIC classes (prose; in chk_b): acronym, proper_noun, phrase, prose_setting.
"""
import re
from dataclasses import dataclass
from functools import lru_cache

from .textnorm import norm

SAFE_PHRASES = re.compile(r"\b(?:microsoft|office)\s+365\b|\bm365\b", re.I)
URL = re.compile(r"\b(?:https?|ftps?|mailto|file)://[^\s)>\]\"']+|\bwww\.[^\s)>\]\"']+", re.I)
EMAIL = re.compile(r"[\w.+*'%-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
GUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b|\b[0-9a-f]{32}\b", re.I)
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
TLDS = ("com|net|org|gov|edu|mil|int|info|biz|io|co|uk|eu|de|fr|nl|ie|us|ca|au|ch|se|no|fi|dk|be|at|es|it|pl|cz|example|test|local|internal|onmicrosoft|microsoft|cloud|xyz|online|site|tech|dev")
DOMAIN = re.compile(rf"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:{TLDS})\b", re.I)
POLICY_ID = re.compile(r"\bMS\.[A-Z]+\.\d+(?:\.\d+)*(?:v\d+)?\b", re.I)
HEX = re.compile(r"\b(?=[0-9a-f]*\d)(?=[0-9a-f]*[a-f])[0-9a-f]{8,}\b", re.I)
VERBS = ("Get|Set|New|Remove|Add|Clear|Connect|Disconnect|Enable|Disable|Export|Import|Invoke|Install|Uninstall|Update|Test|Start|Stop|Grant|Revoke|Find|Select|Write|Read|Out|"
         "Format|Where|ForEach|Register|Unregister|Send|Reset|Restart|Resolve|Show|Sync|Copy|Move|Rename|Save|Search|Publish|Approve|Confirm|Deny|Suspend|Resume|Wait|Use|Unlock|"
         "Lock|Join|Split|Merge|Compare|Convert|ConvertTo|ConvertFrom|Measure|Protect|Unprotect|Initialize|Mount|Dismount|Optimize|Repair|Request|Submit|Switch|Trace|Undo|Redo|"
         "Block|Unblock|Push|Pop|Limit|Edit|Debug|Backup|Restore|Compress|Expand|Complete|Enter|Exit|Hide|Watch|Assert|Build|Deploy|Receive|Ping|Sort|Group|Skip|Take|Unpublish")
CMDLET = re.compile(rf"(?<![\w-])(?:{VERBS})-[A-Z][A-Za-z0-9]+\b")
PARAM = re.compile(r"(?<![\w-])-[A-Z][A-Za-z0-9]+\b")
SNAKE = re.compile(r"\b[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)+\b")
CAMEL = re.compile(r"\b(?:[a-z]+[A-Z][A-Za-z0-9]*|[A-Z][a-z0-9]+[A-Z][A-Za-z0-9]*|[A-Z]{2,}[a-z][A-Za-z0-9]*)\b")
QUOTED = re.compile(r"\"([^\"]{2,80})\"|(?<![\w])'([^']{2,60})'(?![\w])")
NUM = re.compile(r"(?<![A-Za-z0-9_.])(\d{1,3}(?:,\d{3})+|\d+)(?:\.(\d+))?(?![\d])")
NUMWORDS = {"two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13,
            "fourteen": 14, "fifteen": 15, "sixteen": 16, "seventeen": 17, "eighteen": 18, "nineteen": 19, "twenty": 20, "thirty": 30, "forty": 40, "fifty": 50,
            "sixty": 60, "seventy": 70, "eighty": 80, "ninety": 90, "hundred": 100, "thousand": 1000, "million": 10 ** 6, "billion": 10 ** 9, "dozen": 12}
NUMWORD_RX = re.compile(r"\b(?:(?:twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety)-(?:one|two|three|four|five|six|seven|eight|nine)|{})\b".format("|".join(NUMWORDS)), re.I)
IDENT_CLASSES = ("url", "email", "guid", "ipv4", "domain", "policy_id", "hex")


@dataclass(frozen=True, slots=True)
class Spec:
    cls: str
    raw: str
    key: str
    start: int
    end: int

    def __repr__(self):
        return f"Spec({self.cls},{self.raw!r})"


def _mask(t, a, b):
    return t[:a] + " " * (b - a) + t[b:]


def numword_value(w):
    w = w.casefold()
    if "-" in w:
        a, b = w.split("-")
        return str(NUMWORDS[a] + {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9}[b])
    return str(NUMWORDS[w])


def num_key(m):
    whole = m.group(1).replace(",", "")
    whole = whole.lstrip("0") or "0"
    return whole + ("." + m.group(2) if m.group(2) else "")


def extract(text):
    """-> list[Spec] over `text`. Identifier classes are masked after extraction so that their parts are not read again."""
    return list(_extract(text))


@lru_cache(maxsize=4096)
def _extract(text):
    t = norm(text, fold=False)
    t = SAFE_PHRASES.sub(lambda m: " " * len(m.group(0)), t)
    specs = []
    for m in QUOTED.finditer(t):
        inner = m.group(1) or m.group(2)
        specs.append(Spec("quoted", inner, norm(inner), m.start(), m.end()))
    for cls, rx in (("url", URL), ("email", EMAIL), ("guid", GUID), ("ipv4", IPV4), ("domain", DOMAIN), ("policy_id", POLICY_ID), ("cmdlet", CMDLET)):
        for m in list(rx.finditer(t)):
            raw = m.group(0).rstrip(".,;:")
            if cls == "email":
                last = raw.rsplit(".", 1)[-1].casefold()
                if not (last in TLDS.split("|") or (len(last) in (2, 3) and last.isalpha())):
                    continue                     # OData annotation keys such as includeTargets@odata.context are not e-mail addresses
            specs.append(Spec(cls, raw, raw.casefold(), m.start(), m.start() + len(raw)))
            t = _mask(t, m.start(), m.end())
    for m in list(HEX.finditer(t)):
        specs.append(Spec("hex", m.group(0), m.group(0).casefold(), m.start(), m.end()))
        t = _mask(t, m.start(), m.end())
    for cls, rx in (("parameter", PARAM), ("snake", SNAKE), ("camel", CAMEL)):
        for m in list(rx.finditer(t)):
            specs.append(Spec(cls, m.group(0), m.group(0).casefold(), m.start(), m.end()))
            if cls != "parameter":
                t = _mask(t, m.start(), m.end())
    for m in NUM.finditer(t):
        specs.append(Spec("number", m.group(0), num_key(m), m.start(), m.end()))
    for m in NUMWORD_RX.finditer(t):
        specs.append(Spec("number", m.group(0), numword_value(m.group(0)), m.start(), m.end()))
    specs.sort(key=lambda s: s.start)
    return tuple(specs)


def keys_by_class(text):
    d = {}
    for s in extract(text):
        d.setdefault(s.cls, set()).add(s.key)
    return d


def identifiers(text):
    """Identifier-class tokens of `text` (check d): the set of case-folded url, email, guid, ipv4, domain and hex tokens. An e-mail's domain is added as a domain."""
    res = set()
    for s in extract(text):
        if s.cls in ("url", "email", "guid", "ipv4", "domain", "hex"):
            res.add(s.key)
            if s.cls == "email":
                res.add(s.key.split("@", 1)[1])
    return res
