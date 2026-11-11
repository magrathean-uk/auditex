"""Check b: no invented specifics (EXACT for numbers, identifiers, cmdlets, parameters, names; HEURISTIC for prose).

Every specific of the explanation and the steps (specifics.extract) must be in the prompt's whitelist W (context.Whitelist), compared case-folded:
  identifiers (url, email, guid, ipv4, domain, hex, policy_id), cmdlet, parameter, snake, camel, quoted : key must be in W's names (any class);
  number: key in W's numbers, or equal to a derived count (the length of a list or map in the evidence view, the number of cited sections or evidence items).
HEURISTIC prose classes (reported with klass heuristic; they gate after adjudication):
  acronym        2+ capital letters not in W (UK, US, EU, MFA only if in W; a short safe list is allowed);
  proper_noun    a capitalised word inside a sentence, absent from W's vocabulary and from a short safe list;
  phrase         two or more consecutive capitalised words not found in W (exact substring, else token-sort ratio >= 0.9 against a same-length window of W);
  prose_setting  'the <words> setting|option|toggle|policy|...' whose content words are not all in W's vocabulary.
"""
import difflib
import re

from .specifics import extract
from .textnorm import norm, sentence_split

EXACT_CLASSES = ("url", "email", "guid", "ipv4", "domain", "hex", "policy_id", "cmdlet", "parameter", "snake", "camel", "quoted")
SAFE_WORDS = {"uk", "us", "eu", "ok", "id", "ids", "it", "pm", "am", "microsoft", "microsoft 365", "english", "internet", "windows", "scubagear", "cisa", "powershell", "instructions"}
SAFE_ACRONYMS = {"uk", "us", "eu", "ok", "id", "ids", "it", "pm", "am", "cisa", "shall", "should", "ms"}
STOP_FIRST = {"the", "this", "that", "these", "those", "no", "an", "a", "it", "its", "if", "in", "on", "for", "to", "so", "as", "all", "any", "each", "every", "some", "both", "one", "none",
              "not", "only", "also", "because", "since", "while", "when", "where", "which", "what", "there", "here", "then", "however", "therefore", "thus", "your", "their", "our", "they", "we",
              "you", "he", "she", "i", "but", "and", "or", "by", "with", "from", "of", "at", "is", "are", "was", "were", "be", "been", "has", "have", "had", "do", "does", "did", "can", "may",
              "will", "would", "should", "could", "must", "shall", "run", "select", "click", "open", "navigate", "go", "sign", "check", "confirm", "ensure", "collect", "export", "enable", "disable",
              "turn", "set", "review", "repeat", "add", "remove", "grant", "update", "re-run", "rerun", "use", "see", "note", "make", "keep", "wait", "once", "after", "before", "until", "ask", "give",
              "provide", "create", "delete", "configure", "choose", "save", "apply", "verify", "retry", "try", "start", "stop"}
PROSE_SETTING = re.compile(r"\b(?:the|a|an)\s+((?:[a-z][a-z0-9'-]*\s+){1,3})(?:setting|settings|option|options|toggle|switch|flag|parameter|property|attribute|feature|control|rule)\b")
GENERIC = {"shows", "show", "says", "said", "does", "did", "do", "than", "then", "also", "still", "already", "even", "least", "most", "less", "another", "rest", "remaining", "every", "how", "there", "here", "because", "since", "while", "when", "where", "this", "that", "same", "new", "existing", "other", "each", "current", "default", "global", "custom", "your", "their", "tenant", "organisation", "organization",
           "relevant", "required", "specific", "affected", "following", "above", "below", "first", "last", "next", "previous", "single", "whole", "full", "main", "only", "such", "any",
           "its", "of", "in", "on", "for", "to", "and", "or", "with", "by", "at", "as", "an", "a", "the", "is", "are", "was", "be", "has", "have", "which", "whether", "if", "not",
           "no", "all", "some", "both", "one", "two", "evidence", "policy", "requirement", "baseline", "microsoft", "listed", "shown", "named", "stated", "mentioned", "given", "noted"}
CAPWORD = re.compile(r"[A-Z][A-Za-z0-9'-]*")


def _f(code, klass, text, detail=""):
    return {"code": code, "klass": klass, "text": text, "detail": detail}


def token_sort_ratio(a, b):
    ta, tb = " ".join(sorted(a.split())), " ".join(sorted(b.split()))
    return difflib.SequenceMatcher(None, ta, tb).ratio()


def _phrase_in_W(W, phrase):
    p = norm(phrase)
    if p in W.text:
        return True, 1.0
    toks = p.split()
    k = len(toks)
    wt = W.tokens()
    best = 0.0
    if k == 0 or len(wt) < k:
        return False, best
    for i in range(len(wt) - k + 1):
        win = wt[i:i + k]
        if sorted(win) == sorted(toks):
            return True, 1.0
        if win[0] != toks[0] and win[-1] != toks[-1] and not (set(win) & set(toks)):
            continue
        r = token_sort_ratio(" ".join(toks), " ".join(win))
        if r > best:
            best = r
        if best >= 0.9:
            return True, best
    return False, best


def prose_flags(W, text, english_words):
    """HEURISTIC prose classes for one text. -> list of (code, text, detail)."""
    flags = []
    text = norm(text, fold=False)
    for sent in sentence_split(text):
        toks = re.findall(r"[A-Za-z0-9][A-Za-z0-9'_-]*|[^\sA-Za-z0-9]", sent)
        i = 0
        runs = []
        while i < len(toks):
            if CAPWORD.fullmatch(toks[i]) and not toks[i].isupper():
                j = i
                while j < len(toks) and CAPWORD.fullmatch(toks[j]) and not toks[j].isupper():
                    j += 1
                runs.append((i, j))
                i = j
            else:
                i += 1
        for a, b in runs:
            run = toks[a:b]
            if re.search(r"[a-z]+[A-Z]", " ".join(run)) or any("_" in x for x in run):
                continue                                            # camel and snake names are exact classes
            if a == 0:
                # sentence-initial: the first word's capital carries no signal; a leading generic word is dropped
                if run[0].casefold() in STOP_FIRST or len(run) == 1 and run[0].casefold() in W.words:
                    run = run[1:]
                    if not run:
                        continue
            if len(run) >= 2:
                phrase = " ".join(run)
                ok, r = _phrase_in_W(W, phrase)
                if not ok:
                    # the same run without its first word (a sentence-initial verb or determiner that a capital hides)
                    if a == 0 or True:
                        ok2, _ = _phrase_in_W(W, " ".join(run[1:])) if len(run) > 2 else (False, 0)
                        if ok2 and run[0].casefold() in STOP_FIRST:
                            continue
                    flags.append(("phrase_not_in_view", phrase, f"best token-sort ratio {r:.2f}"))
            else:
                w = run[0]
                wl = w.casefold().strip("'")
                parts = [x for x in re.split(r"[-']", wl) if len(x) >= 3 and x not in ("ll", "ve", "re")]
                if wl in W.words or wl in SAFE_WORDS or len(wl) < 3 or all(x in W.words or x in SAFE_WORDS or x in STOP_FIRST for x in parts):
                    continue
                if a == 0:
                    ew = english_words
                    if ew and len(wl) >= 4 and wl not in ew and wl.rstrip("s") not in ew and wl not in STOP_FIRST:
                        flags.append(("proper_noun_not_in_view", w, "sentence-initial word not in the view and not in the English word list"))
                    continue
                flags.append(("proper_noun_not_in_view", w, ""))
    for m in re.finditer(r"\b[A-Z]{2,}[A-Z0-9]*\b", text):
        w = m.group(0)
        if w.casefold() in W.words or w.casefold() in SAFE_ACRONYMS or w.casefold() in W.names:
            continue
        flags.append(("acronym_not_in_view", w, ""))
    low = norm(text)
    for m in PROSE_SETTING.finditer(low):
        words_ = [w for w in re.findall(r"[a-z0-9']+", m.group(1)) if w not in GENERIC]
        missing = [w for w in words_ if w not in W.words and w.rstrip("s") not in W.words and (w + "s") not in W.words]
        if missing:
            flags.append(("prose_setting_not_in_view", m.group(0), "words not in the view: " + ", ".join(missing)))
    return flags


def check_b(ctx, out):
    W = ctx.W
    fails, notes = [], []
    texts = [("explanation", out.explanation)] + [(f"step {i}", s) for i, s in enumerate(out.steps)]
    for where, txt in texts:
        if not txt:
            continue
        for sp in extract(txt):
            if sp.cls in EXACT_CLASSES:
                if sp.key not in W.names and not (sp.cls == "quoted" and W.has_substring(sp.raw)):
                    # an e-mail whose domain is in the view is still invented as a whole address; a bare local part is not a token
                    fails.append(_f("invented_" + sp.cls, "exact", sp.raw, where))
            elif sp.cls == "number":
                if sp.key not in W.numbers and sp.key not in W.counts:
                    fails.append(_f("invented_number", "exact", sp.raw, where))
                elif sp.key not in W.numbers:
                    notes.append(f"derived count {sp.raw} in {where}")
        for code, t, d in prose_flags(W, txt, ctx.res.english_words):
            fails.append(_f(code, "heuristic", t, f"{where}; {d}" if d else where))
    exact = [f for f in fails if f["klass"] == "exact"]
    return {"pass": not fails, "klass": "exact" if exact else ("heuristic" if fails else "exact"), "failures": fails, "notes": notes}
