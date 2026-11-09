"""Verdict-wording classifier (check a). Finds compliance assertions in a text and says what each one claims.

DEFINITIONS (these are the contract; the unit tests in test_verdict_classifier.py pin them):

1. Lexicon. POSITIVE predicates (claim compliance): meets/meet, met (only after an auxiliary or a requirement noun), complies/comply, compliant,
   in compliance, satisfies, passes, conforms, adheres, fulfils, aligned with, in line with, consistent with, "is secure/safe/fine/correctly
   configured", "no issues/gaps/weaknesses/violations", "nothing to fix", "no action required". NEGATIVE predicates (claim non-compliance):
   fails/failed, violates/violation, non-compliant/noncompliance, out of compliance, falls short, unmet, unsatisfied, differs from the
   requirement/baseline, deviates from, inconsistent with, "is insecure/vulnerable/misconfigured/weak", "at risk". Pre-processing: NFKC, zero-width
   removal, look-alike and dash folding (textnorm.norm), contractions expanded (doesn't -> does not), "non compliant" and "non-compliant" joined.

2. Negation. Negators: not, no, none, nothing, never, neither, nor, without, cannot, hardly, barely, "fail(s/ed/ing) to", "failure to", "unable to".
   A negator flips the NEAREST following predicate in its clause when at most three content tokens separate them (counting the predicate's first token;
   auxiliaries, determiners and adverbs such as is, be, the, of, fully, yet, longer, necessarily are transparent). Several negators on one predicate flip
   it several times (double negation restores the sign: "not non-compliant" is positive). A clause ends at , ; : ( ) and at but, however, although,
   though, whereas, while, so, because, since, therefore, thus. "not only" is not a negator. "fail to X": the word "fail" then acts only as a
   negator of X (it is not also counted as a negative predicate), so "does not fail to meet" is positive and "fails to meet" is negative.

3. Hedges. A hedge word (mostly, partially, probably, likely, appears, seems, may, might, could, largely, generally, somewhat, arguably, perhaps,
   possibly, presumably, apparently, almost, nearly, essentially, effectively, ...) within three content tokens before a predicate in its clause, or
   directly after it, marks the assertion as hedged (softened). Multi-word hedges (to some extent, in most cases, more or less) are joined first.

4. Irrealis (not an assertion of the tenant's state). A predicate is conditional when (a) its sentence starts with if, unless, once, whether, provided,
   assuming, supposing, when; or (b) if, unless, whether, once, until, provided, assuming, so that, in case appears earlier in its clause; or (c) would, could,
   might, should, ought, shall, must, need(s) to, has/have to, required to precedes it within four content tokens; or (d) it is followed within three content tokens
   by if, unless, once, provided, when; or (e) it follows a purposive "to" ("to be compliant, enable X", "in order to meet the requirement"), except after
   appears/seems/found/shown/said/considered/deemed/likely and similar, where "to" introduces an assertion. This is a deliberate escape hatch that can be
   abused ("If anything, the tenant is non-compliant"); it is listed as a limit in the report and in REVIEW-ASKS-REDTEAM.md.

5. Quoted data. A run of at least three consecutive tokens copied verbatim from a supplied exempt text (the baseline requirement sentence, the reason text,
   verbatim baseline step text) is quoted data: predicates inside it are marked `exempt` and do not count, but are listed for adjudication.

6. Contradiction by verdict (decided in chk_a):
   met            - any effective-negative assertion, hedged or not, fails; any hedged positive assertion fails (the verdict is categorical).
   not_met        - any effective-positive assertion, hedged or not, fails; a hedged negative assertion fails (softening).
   not_assessed   - any compliance predicate in any form (positive, negative, hedged or conditional) fails: the text must not guess or hint.
   not_applicable - any compliance assertion (not conditional) fails.
   Also: saying "no conclusion"/"not assessed" in met, not_met or not_applicable fails; saying the policy "does not apply"/"not applicable" in met, not_met
   or not_assessed fails; not_assessed must contain a no-conclusion phrase; not_applicable must contain a does-not-apply phrase.

HEURISTIC: this is a lexical classifier. It does not read meaning. Known limits are listed in the README and tested as such.
"""
import re

from .textnorm import norm, sentence_split

# ------------------------------------------------------------------------------------------------ lexicon
_POS = [
    (r"\bmeets?\b", "meet"),
    (r"\b(?:is|are|was|were|been|be|remains?|remained|fully|already|now|currently|requirements?|polic(?:y|ies)|baseline|controls?|criteria|conditions?|standards?)\s+(?:(?:is|are|was|were|has|have|been|not|yet|fully|entirely|being|never|all)\s+)*(?P<h>met)\b", "met"),
    (r"\bcompl(?:y|ies|ied|ying)\b", "comply"),
    (r"\bcompliant\b", "compliant"),
    (r"\bin\s+compliance\b", "in compliance"),
    (r"\bsatisf(?:y|ies|ied|ying)\b", "satisfy"),
    (r"\bpass(?:es|ed)?\b", "pass"),
    (r"\bconform(?:s|ed|ing)?\b", "conform"),
    (r"\badher(?:es|ed|ing|e)\b", "adhere"),
    (r"\bfulfil(?:s|led|ling)?\b|\bfulfill(?:s|ed|ing)?\b", "fulfil"),
    (r"\balign(?:s|ed)?\s+with\b", "align"),
    (r"\bin\s+line\s+with\b", "in line with"),
    (r"\bconsistent\s+with\b", "consistent with"),
    (r"\b(?:is|are|looks|seems|remains?|appears)\s+(?:(?:not|yet|fully|entirely|really|always)\s+)*(?P<h>secure|safe|fine|good|ok|okay|sound|healthy|correct)\b", "secure"),
    (r"\b(?:correctly|properly|well)\s+configured\b", "configured correctly"),
    (r"\bno\s+(?:issues?|problems?|gaps?|weakness(?:es)?|concerns?|risks?)\b", "no issues"),
    (r"\bnothing\s+to\s+(?:fix|remediate|change|correct|worry)\b", "nothing to fix"),
    (r"\bno\s+(?:further\s+)?(?:action|remediation|changes?)\s+(?:is\s+|are\s+)?(?:needed|required|necessary)\b", "no action required"),
]
_NEG = [
    (r"\bfail(?:s|ed|ing)?\b", "fail"),
    (r"\bviolat(?:es|ed|ing|ion|ions|e)\b", "violate"),
    (r"\bnoncompliant\b|\bnoncompliance\b", "noncompliant"),
    (r"\bout\s+of\s+compliance\b", "out of compliance"),
    (r"\b(?:falls?|fell)\s+short\b", "falls short"),
    (r"\bunmet\b", "unmet"),
    (r"\bunsatisf(?:ied|actory)\b", "unsatisfied"),
    (r"\bdiffer(?:s|ed)?\s+from\s+(?:the\s+)?(?:baseline|requirement|policy|standard|required|expected|recommended)\b", "differs from"),
    (r"\b(?:deviat(?:es|ed|ion)|inconsistent|contrary|contradicts?)\s+(?:from|with|to)\b", "deviates"),
    (r"\b(?:is|are|looks|seems|remains?|appears)\s+(?:(?:not|yet|fully|entirely|really|always)\s+)*(?P<h>insecure|unsafe|weak|vulnerable|misconfigured|incorrect|wrong|bad|poor|risky)\b", "insecure"),
    (r"\bat\s+risk\b|\b(?:incorrectly|improperly)\s+configured\b", "at risk"),
    (r"\b(?:needs?|has|have)\s+to\s+be\s+(?:fixed|remediated|corrected)\b|\bremediation\s+is\s+(?:needed|required)\b|\baction\s+is\s+(?:needed|required)\b", "needs fixing"),
]
POS_RX = [(re.compile(p), n) for p, n in _POS]
NEG_RX = [(re.compile(p), n) for p, n in _NEG]

NEGATORS = {"not", "no", "none", "nothing", "never", "neither", "nor", "without", "cannot", "hardly", "barely", "nobody", "nowhere"}
FAIL_TO = re.compile(r"\b(?:fail(?:s|ed|ing)?|failure|unable|refus(?:es|ed|ing))\s+to\b")
FILLER = {"be", "been", "being", "is", "are", "was", "were", "am", "said", "to", "considered", "regarded", "deemed", "described", "seen", "viewed",
          "as", "fully", "completely", "entirely", "currently", "yet", "also", "really", "actually", "quite", "still", "even", "any", "longer", "more",
          "truly", "strictly", "wholly", "necessarily", "always", "ever", "the", "a", "an", "of", "do", "does", "did", "doing", "done", "has", "have",
          "had", "having", "will", "shall", "can", "may", "might", "would", "could", "should", "must", "it", "this", "that", "now", "then", "just",
          "otherwise", "particularly", "especially", "properly", "correctly", "clearly", "obviously"}
CLAUSE_BREAK_WORDS = {"but", "however", "although", "though", "whereas", "while", "so", "because", "since", "therefore", "thus", "hence"}
PUNCT = {",", ";", ":", "(", ")"}
HEDGES = {"mostly", "partially", "partly", "probably", "likely", "possibly", "perhaps", "appears", "appear", "appeared", "seems", "seem", "seemed", "may",
          "might", "could", "largely", "generally", "broadly", "somewhat", "arguably", "potentially", "presumably", "apparently", "almost", "nearly",
          "essentially", "effectively", "roughly", "reasonably", "tentatively", "hopefully", "supposedly", "ostensibly", "mainly", "predominantly",
          "basically", "reportedly", "allegedly", "hedgeph", "unlikely", "ostensible", "mostly", "typically", "usually", "tends", "tend", "suggests",
          "suggest", "suggesting", "indicates", "indicate", "looks"}
HEDGE_PHRASES = [(re.compile(p), "hedgeph") for p in (r"\bto\s+some\s+extent\b", r"\bin\s+most\s+cases\b", r"\bmore\s+or\s+less\b", r"\bkind\s+of\b", r"\bsort\s+of\b",
                                                        r"\bto\s+a\s+(?:large\s+|certain\s+)?degree\b", r"\bfor\s+the\s+most\s+part\b", r"\bin\s+part\b")]
IRR_SENT_START = {"if", "unless", "once", "whether", "provided", "assuming", "supposing", "when"}
IRR_BEFORE_COND = {"if", "unless", "whether", "once", "until", "provided", "assuming", "supposing", "whenever"}
IRR_BEFORE_MODAL = {"would", "could", "might", "should", "ought", "shall", "must"}
IRR_AFTER = {"if", "unless", "once", "provided", "when", "whenever", "until"}
NOT_PURPOSIVE_PRE = {"appears", "appear", "appeared", "seems", "seem", "seemed", "found", "shown", "proved", "proven", "said", "considered", "deemed",
                     "regarded", "believed", "judged", "tends", "tend", "turns", "turned", "likely", "unlikely", "claimed", "assessed", "determined",
                     "expected", "supposed", "known", "reported", "rated", "classed", "classified"}

# ---------------------------------------------------------------------------------------------- verdict words
NOCONC = re.compile(
    r"\b(?:not\s+(?:yet\s+|been\s+)*(?:assessed|evaluated|determined)|unassessed|no\s+conclusion|no\s+determination|no\s+verdict|inconclusive|undetermined"
    r"|(?:cannot|can\s+not|could\s+not|unable\s+to)\s+(?:be\s+)?(?:assess\w*|determin\w*|evaluat\w*|judg\w*|conclude)"
    r"|(?:insufficient|not\s+enough)\s+(?:evidence|data|information))\b")
NOTAPPL_ANY = re.compile(r"\b(?:not\s+applicable|n/a|inapplicable|does\s+not\s+apply|do\s+not\s+apply|is\s+not\s+relevant|irrelevant)\b")
NOTAPPL_SUBJ = re.compile(
    r"\b(?:this|the|that)\s+(?:policy|requirement|baseline|control|check|recommendation)\s+(?:is\s+)?(?:not\s+applicable|does\s+not\s+apply|is\s+not\s+relevant|is\s+inapplicable)\b"
    r"|\bnot\s+applicable\b|\bn/a\b|\bdoes\s+not\s+apply\s+(?:here|to\s+this\s+tenant|to\s+the\s+tenant|to\s+your\s+tenant|to\s+this\s+environment|in\s+this\s+environment)\b")
APPLIES = re.compile(r"\b(?:(?:this|the|that)\s+(?:policy|requirement|baseline|control)\s+applies\b(?!\s+(?:only|when|if|to|in|for|where|unless|at))|(?:is|are)\s+(?:applicable|relevant)\b|applies\s+here\b)")
GUESS_WORDS = re.compile(r"\b(?:probably|likely|presumably|perhaps|possibly|assume[sd]?|assuming|suspect(?:s|ed)?|guess(?:ed|ing)?|appears\s+(?:to|that)|seems\s+(?:to|that)|"
                         r"suggests?\s+that|most\s+likely|in\s+all\s+likelihood)\b")


def _prep(sentence):
    s = norm(sentence)
    s = re.sub(r"\bcan't\b", "cannot", s)
    s = re.sub(r"\bwon't\b", "will not", s)
    s = re.sub(r"\bshan't\b", "shall not", s)
    s = re.sub(r"\bain't\b", "is not", s)
    s = re.sub(r"(\w)n't\b", r"\1 not", s)
    s = re.sub(r"\bnon[\s-]+compliant\b", "noncompliant", s)
    s = re.sub(r"\bnon[\s-]+compliance\b", "noncompliance", s)
    s = re.sub(r"\bnot-(?=compliant|met|secure)", "not ", s)
    s = re.sub(r"\bun-met\b", "unmet", s)
    s = re.sub(r"\bfail(?:s|ed|ing)?\s+to\s+meet\b", lambda m: m.group(0), s)
    for rx, rep in HEDGE_PHRASES:
        s = rx.sub(rep, s)
    return s


_TOK = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*|n/a|[,;:()\"]")


def _tokens(s):
    return [(m.group(0), m.start(), m.end()) for m in _TOK.finditer(s)]


class Assertion:
    __slots__ = ("sign", "lemma", "negs", "hedged", "irrealis", "exempt", "sentence", "start_tok", "text")

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))

    @property
    def kind(self):
        return ("hedged_" if self.hedged else "") + ("pos" if self.sign > 0 else "neg")

    def as_dict(self):
        return {"sign": "+" if self.sign > 0 else "-", "lemma": self.lemma, "negators": self.negs, "hedged": self.hedged, "irrealis": self.irrealis,
                "exempt": self.exempt, "sentence": self.sentence}


def _exempt_runs(exempt_texts, min_run=3):
    """All token n-grams (n = min_run) of the exempt texts, plus the token lists, for quoted-data detection."""
    lists = []
    for t in exempt_texts or ():
        if t:
            lists.append([x[0] for x in _tokens(_prep(t))])
    grams = set()
    for lst in lists:
        for i in range(len(lst) - min_run + 1):
            grams.add(tuple(lst[i:i + min_run]))
    return grams


def analyse(text, exempt_texts=(), min_run=3):
    """-> list[Assertion] for every compliance predicate in `text`, in order."""
    grams = _exempt_runs(exempt_texts, min_run)
    out = []
    for sent in sentence_split(norm(text, fold=False)):
        s = _prep(sent)
        toks = _tokens(s)
        if not toks:
            continue
        words = [t[0] for t in toks]

        def tok_at(char):
            for i, t in enumerate(toks):
                if t[1] <= char < t[2]:
                    return i
            return None
        # exempt token coverage
        covered = set()
        if grams and len(words) >= min_run:
            for i in range(len(words) - min_run + 1):
                if tuple(words[i:i + min_run]) in grams:
                    covered.update(range(i, i + min_run))
        # clause ids
        clause = []
        c = 0
        for w in words:
            clause.append(c)
            if w in PUNCT or w in CLAUSE_BREAK_WORDS:
                c += 1
        # predicate matches
        preds = []
        for rx_list, sign in ((POS_RX, 1), (NEG_RX, -1)):
            for rx, lemma in rx_list:
                for m in rx.finditer(s):
                    i = tok_at(m.start("h") if "h" in rx.groupindex else m.start())
                    if i is None:
                        continue
                    # lexicon patterns that begin with an auxiliary or noun ("is met", "polic... met"): anchor on the last token of the phrase for scope
                    jj_ = tok_at(m.end() - 1)
                    preds.append({"i": i, "j": i if jj_ is None else jj_, "sign": sign, "lemma": lemma, "span": (m.start(), m.end())})
        # 'fail to X': the word fail is then only a negator
        fail_to = [(tok_at(m.start()), tok_at(m.end() - 1)) for m in FAIL_TO.finditer(s)]
        fail_to_starts = {a for a, _ in fail_to}
        preds = [p for p in preds if not (p["lemma"] == "fail" and p["i"] in fail_to_starts)]
        # drop shorter matches inside longer ones (same start token, keep the longest span); drop duplicates
        preds.sort(key=lambda p: (p["i"], -(p["span"][1] - p["span"][0])))
        keep, taken = [], set()
        for p in preds:
            if p["i"] in taken:
                continue
            taken.add(p["i"])
            keep.append(p)
        preds = sorted(keep, key=lambda p: p["i"])
        # a 'met' phrase anchored on an auxiliary: scope anchor is the phrase start but negation binds before it
        negators = [i for i, w in enumerate(words) if w in NEGATORS]
        for a, _b in fail_to:
            if a is not None:
                negators.append(a)
        # 'not only' is not a negator
        negators = [i for i in negators if not (words[i] == "not" and i + 1 < len(words) and words[i + 1] == "only")]
        negators.sort()

        def content_dist(n, p):
            d = 0
            for k in range(n + 1, p + 1):
                if words[k] not in FILLER and words[k] not in PUNCT:
                    d += 1
            return d
        for p in preds:
            p["negs"] = 0
        for n in negators:
            nearest = None
            for p in preds:
                if p["i"] > n and clause[p["i"]] == clause[n] and (words[n] != "nor" or True):
                    # for a phrase predicate that starts with an auxiliary ("is met"), use the token after the auxiliary as the scope anchor
                    nearest = p
                    break
            if nearest is not None and content_dist(n, nearest["i"]) <= 3:
                nearest["negs"] += 1
        first = words[0] if words else ""
        for p in preds:
            i = p["i"]
            sign = p["sign"] * (-1 if p["negs"] % 2 else 1)
            # hedge: within three content tokens before (same clause) or one token after
            hedged = False
            d = 0
            for k in range(i - 1, -1, -1):
                if clause[k] != clause[i] or words[k] in PUNCT:
                    break
                if words[k] in HEDGES:
                    hedged = True
                    break
                if words[k] not in FILLER:
                    d += 1
                    if d >= 3:
                        break
            jj = p["j"]
            if not hedged and jj + 1 < len(words) and words[jj + 1] in HEDGES and clause[jj + 1] == clause[i]:
                hedged = True
            # irrealis
            irr = first in IRR_SENT_START
            if not irr:
                d = 0
                for k in range(i - 1, -1, -1):
                    if clause[k] != clause[i] or words[k] in PUNCT:
                        break
                    w = words[k]
                    if w in IRR_BEFORE_COND:
                        irr = True
                        break
                    if w in IRR_BEFORE_MODAL and d <= 4:
                        irr = True
                        break
                    if w in ("need", "needs", "needed", "required", "require", "requires", "has", "have") and k + 1 < len(words) and words[k + 1] == "to" and d <= 5:
                        irr = True
                        break
                    if words[k] not in FILLER:
                        d += 1
            if not irr:  # right context: "compliant if ..."
                d = 0
                for k in range(jj + 1, len(words)):
                    if clause[k] != clause[i] or words[k] in PUNCT:
                        break
                    if words[k] in IRR_AFTER:
                        irr = True
                        break
                    if words[k] not in FILLER:
                        d += 1
                        if d >= 3:
                            break
            if not irr and p["lemma"] in ("meet", "comply", "satisfy", "pass", "conform", "adhere", "fulfil", "compliant", "met", "in compliance", "align", "secure", "in line with"):
                # purposive "to X"
                k = i - 1
                while k >= 0 and words[k] in ("fully", "completely", "entirely", "also", "still", "actually", "really", "truly", "strictly", "wholly", "now", "then", "be", "become", "remain", "stay", "been"):
                    k -= 1
                if k >= 0 and words[k] == "to" and p["negs"] == 0:
                    j = k - 1
                    while j >= 0 and words[j] in ("order", "as", "so", "able", "enough", "sufficient"):
                        j -= 1
                    prev = words[j] if j >= 0 else ""
                    if prev not in NOT_PURPOSIVE_PRE:
                        irr = True
            out.append(Assertion(sign=sign, lemma=p["lemma"], negs=p["negs"], hedged=hedged, irrealis=irr, exempt=i in covered, sentence=sent, start_tok=i,
                                 text=s[p["span"][0]:p["span"][1]]))
    return out


def verdict_words(text, exempt_texts=()):
    """-> dict of phrase lists found in text. Keys without suffix drop phrases that occur verbatim in the exempt texts (quoted data); keys ending _all keep every hit
    (used for REQUIRED phrases, where copying the reason text's own phrase still counts as saying it)."""
    t = norm(text)
    t = re.sub(r"(\w)n't\b", r"\1 not", t)
    t = t.replace("can't", "cannot")
    ex = " ".join(norm(x) for x in (exempt_texts or ()) if x)

    def hits(rx, filt):
        return [m.group(0) for m in rx.finditer(t) if m.group(0) and not (filt and m.group(0) in ex)]
    return {"no_conclusion": hits(NOCONC, True), "no_conclusion_all": hits(NOCONC, False), "not_applicable_any": hits(NOTAPPL_ANY, True),
            "not_applicable_all": hits(NOTAPPL_ANY, False), "not_applicable_subject": hits(NOTAPPL_SUBJ, True), "applies": [m.group(0) for m in APPLIES.finditer(t) if m.group(0) not in ex], "guess": hits(GUESS_WORDS, True)}
