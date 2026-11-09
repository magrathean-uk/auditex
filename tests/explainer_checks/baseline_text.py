"""Independent reader of the pinned ScubaGear baselines (read only) for the checkers.

Independent of step 3's parser on purpose: it shares only the file set. For each policy it returns
  statement   the requirement sentence(s) (text before the badge or comment line of the policy section)
  lines       the Instructions section as plain-text lines (code fences kept as written, one line per code line)
  units       sentences of those lines (a code line is one unit)
  xref        policy ids named inside the Instructions text (cross-references such as "see MS.X.1.1v1 Instructions")
Also portal_vocab(): bold labels, link texts and "Sign in to the ... ." portal names found in any Instructions section.
"""
import re

from .textnorm import sentence_split

_HEAD = re.compile(r"^#{2,4}\s+(MS\.[A-Z]+\.\d+\.\d+v\d+)(\s+Instructions)?\s*$")
_ANYHEAD = re.compile(r"^#{1,6}\s")
_PID = re.compile(r"MS\.[A-Z]+\.\d+\.\d+v\d+")
_BOLD = re.compile(r"\*\*([^*]+)\*\*")
_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")


def plain(s):
    s = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", s)
    s = _LINK.sub(r"\1", s)
    s = re.sub(r"<(https?://[^>]*)>", "", s)
    s = re.sub(r"</?(?:pre|b|i|code|br|u|em|strong)\s*/?>", " ", s)
    s = s.replace("\\>", ">").replace("\\<", "<").replace("\\_", "_").replace("\\*", "*").replace("\\[", "[").replace("\\]", "]")
    s = s.replace("\\|", "|")
    s = _BOLD.sub(r"\1", s)
    s = re.sub(r"(?<![\w*])\*\*?([^*\n]+?)\*\*?(?![\w*])", r"\1", s)
    s = re.sub(r"(?<![\w])_([^_\n]+)_(?![\w])", r"\1", s)
    s = s.replace("`", "")
    return re.sub(r"\s+", " ", s).strip()


def load(read_text):
    """Parse a {relative_file: raw_markdown} mapping, or callable plus .files.

    Test fixtures are supplied by part 1; no runtime parser or live checkout.
    """
    files = sorted(read_text if isinstance(read_text, dict) else read_text.files)
    read = read_text.__getitem__ if isinstance(read_text, dict) else read_text
    pols, instr, bold, links, portals = {}, {}, set(), set(), set()
    for filename in files:
        if filename.rsplit("/", 1)[-1] == "removedpolicies.md":
            continue
        cur = None
        fence = False
        for line in read(filename).splitlines():
            m = _HEAD.match(line)
            if m:
                cur = (m[1], bool(m[2]))
                (instr if cur[1] else pols).setdefault(cur[0], [])
                fence = False
                continue
            if _ANYHEAD.match(line):
                cur = None
                continue
            if cur is None:
                continue
            (instr if cur[1] else pols)[cur[0]].append(line)
            if cur[1]:
                for b in _BOLD.findall(line):
                    bold.add(plain(b))
                for link in _LINK.findall(line):
                    links.add(plain(link))
                for pm in re.finditer(r"[Ss]ign in to the ([^.]+?)\.", plain(line)):
                    portals.add(pm.group(1).strip())
    res = {}
    for pid in pols.keys() | instr.keys():
        stmt = []
        for line in pols.get(pid, []):
            if line.startswith("[![") or line.startswith("<!--"):
                break
            if line.strip():
                stmt.append(plain(line))
        lines = []
        fence = False
        cur_item = None
        item_start = re.compile(r"^\s*(?:\d+\.|[-*])\s+")

        def flush():
            nonlocal cur_item
            if cur_item is not None:
                t = plain(cur_item)
                if t:
                    lines.append((t, False))
                cur_item = None
        for line in instr.get(pid, []):
            st = line.strip()
            if st.startswith("```"):
                flush()
                fence = not fence
                continue
            if "<pre>" in st or "</pre>" in st:
                st = re.sub(r"</?pre>", "", st).strip()
                if not st:
                    flush()
                    continue
            if fence:
                t = plain(st)
                if t:
                    lines.append((t, True))
                continue
            if not st:
                flush()
                continue
            if st.startswith(">"):
                st = st.lstrip("> ").strip()
            if item_start.match(line):
                flush()
                cur_item = item_start.sub("", line, count=1).strip()
            elif cur_item is not None:
                cur_item += " " + st
            else:
                cur_item = st
        flush()
        units = []
        for t, code in lines:
            if code:
                units.append(t)
            else:
                units.extend(sentence_split(t))
        text = " ".join(t for t, _ in lines)
        xref = [x for x in dict.fromkeys(_PID.findall(text)) if x != pid]
        res[pid] = {"statement": " ".join(stmt), "lines": [t for t, _ in lines], "line_groups": lines, "units": units, "xref": xref, "self_ref": pid in _PID.findall(text)}
    out = {"policies": res, "bold": bold, "links": links, "portals": portals}
    return out


def portal_vocab(baselines):
    return {x.casefold() for key in ("bold", "links", "portals") for x in baselines[key] if x}


def instruction_range(raw, policy_id, labels=None):
    """Independent selection of top-level numbered items, retaining descendants.

    Selection happens on raw markdown before plain-text parsing. A pointer with
    labels=None keeps the preamble as well as every numbered item. This tests
    ranges, rather than merely proving a chosen substring exists in a target.
    """
    lines, active, selected, fence = [], False, labels is None, False
    labels = None if labels is None else set(labels)
    for line in raw.splitlines():
        heading = _HEAD.match(line)
        if heading:
            active = heading[1] == policy_id and bool(heading[2])
            continue
        if active and _ANYHEAD.match(line):
            break
        if not active:
            continue
        if line.strip().startswith('```'):
            fence = not fence
        numbered = None if fence else re.match(r'^(\d+)\.\s+', line)
        if numbered and labels is not None:
            selected = numbered[1] in labels
        if selected:
            lines.append(line)
    tiny = f'## {policy_id}\n\n### {policy_id} Instructions\n' + '\n'.join(lines)
    return load({'range.md': tiny})['policies'][policy_id]['lines']
