"""Pinned public baseline text for the deterministic explainer.

Runtime loads vendored JSON through an injected resource reader. Markdown parsing
is a build-time operation only. Text cleaning and item grouping are adapted from
the frozen explainer S/A/baselines.py; baseline prose has separate CISA/Microsoft
attribution in the generated index and docs/provenance/explainer-baselines.md.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re
from typing import Any, Callable

BaselineIndex = dict[str, Any]
Unit = dict[str, Any]
ReadText = Callable[[str], str]
SOURCE_COMMIT = "2446ad723b7f55031cc02c8aca244d731d468cba"
BASELINE_DIR = "PowerShell/ScubaGear/baselines"
BASELINE_FILES = ("aad.md", "exo.md", "powerbi.md", "powerplatform.md",
                  "securitysuite.md", "sharepoint.md", "teams.md")
RESOURCE = "configs/explainer-baselines.json"
CAP = 6000

_HEAD = re.compile(r"^#{2,4}\s+(MS\.[A-Z]+\.\d+\.\d+v\d+)(\s+Instructions)?\s*$")
_ANYHEAD = re.compile(r"^#{1,6}\s")
_CRIT = re.compile(r"<!--\s*Policy:\s*(MS\.[A-Z]+\.\d+\.\d+v\d+);\s*Criticality:\s*([A-Za-z0-9/ -]+?)\s*-->")
_TOP_NUM = re.compile(r"^(\d+)\.\s+(.*)$")
_TOP_BUL = re.compile(r"^[-*]\s+(.*)$")
_NEST_NUM = re.compile(r"^\s+(\d+)\.\s+(.*)$")
_NEST_BUL = re.compile(r"^\s+[-*]\s+(.*)$")
_LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")
_IMG = re.compile(r"!\[[^\]]*\]\([^)]*\)")
_ESC = {"\\*": "\x00a", "\\_": "\x00u", "\\`": "\x00t"}

# Instructions that point at another policy's Instructions (read from the baselines, 5 Nov 2026): policy -> (target, top-level numbered items named by the
# pointer, or None for the whole Instructions). Items are the numbered steps of the target (nested sub-items follow their parent).
XREF = {"MS.EXO.4.2v1": ("MS.EXO.4.1v1", None), "MS.EXO.4.3v1": ("MS.EXO.4.1v1", None), "MS.EXO.4.4v1": ("MS.EXO.4.1v1", None),
        "MS.SECURITYSUITE.1.2v1": ("MS.SECURITYSUITE.1.1v1", None), "MS.SECURITYSUITE.6.2v1": ("MS.SECURITYSUITE.6.1v1", None),
        "MS.SECURITYSUITE.7.2v1": ("MS.SECURITYSUITE.7.1v1", None), "MS.SECURITYSUITE.7.3v1": ("MS.SECURITYSUITE.7.1v1", None),
        "MS.SECURITYSUITE.3.2v1": ("MS.SECURITYSUITE.3.1v1", ("9",)), "MS.SECURITYSUITE.3.3v1": ("MS.SECURITYSUITE.3.1v1", ("16", "17", "18")),
        "MS.SECURITYSUITE.3.4v1": ("MS.SECURITYSUITE.3.1v1", ("19", "20")), "MS.EXO.6.2v1": ("MS.EXO.6.1v1", ("5",)),
        "MS.AAD.7.9v1": ("MS.AAD.7.8v1", None),
        # follow-up B (5 Nov 2026): the four pointers the first 12 rows left out. AAD 7.2 says "Follow the instructions for policy MS.AAD.7.1v1" (twice, whole
        # Instructions); Power Platform 1.2 "up to step 3" of 1.1, 2.2 "steps one through 11" of 2.1, 3.2 "steps one and two" of 3.1.
        "MS.AAD.7.2v1": ("MS.AAD.7.1v1", None),
        "MS.POWERPLATFORM.1.2v1": ("MS.POWERPLATFORM.1.1v1", ("1", "2", "3")),
        "MS.POWERPLATFORM.2.2v1": ("MS.POWERPLATFORM.2.1v1", tuple(str(i) for i in range(1, 12))),
        "MS.POWERPLATFORM.3.2v1": ("MS.POWERPLATFORM.3.1v1", ("1", "2"))}


def plain(s):
    """Plain customer text from one baseline line or paragraph (not for code)."""
    s = _IMG.sub("", s)
    s = _LINK.sub(r"\1", s)
    s = re.sub(r"<(https?://[^>]*)>", "", s)
    s = re.sub(r"<([^>\s]+@[^>\s]+)>", r"\1", s)
    s = re.sub(r"</?(pre|b|i|u|em|strong|code|br)\s*/?>", " ", s)
    if s.lstrip().startswith(">"):
        s = re.sub(r"(^|\s)>\s*", r"\1", s, count=1)
    s = s.replace("\\>", ">").replace("\\<", "<").replace("\\[", "[").replace("\\]", "]").replace("\\|", "|")
    for k, v in _ESC.items():
        s = s.replace(k, v)
    s = re.sub(r"\*\*([^*]+)\*\*", r"\1", s)
    s = re.sub(r"(?<![\w*])\*([^*\n]+?)\*(?![\w*])", r"\1", s)
    s = re.sub(r"(?<![\w])_([^_\n]+)_(?![\w])", r"\1", s)
    s = s.replace("`", "")
    for k, v in _ESC.items():
        s = s.replace(v, k[1])
    s = s.replace("\u2014", "-").replace("\u2013", "-")      # no en or em dashes in customer text (a cmdlet parameter written with an en dash becomes valid)
    return re.sub(r"\s+", " ", s).strip()


def plain_code(s):
    """A code line: characters as written, HTML emphasis tags dropped, dashes folded, whitespace collapsed."""
    s = re.sub(r"</?(pre|b|i|u|em|strong|code|br)\s*/?>", "", s)
    return re.sub(r"\s+", " ", s.replace("\u2014", "-").replace("\u2013", "-")).strip()


def _code_lines(raw_lines):
    """Keep comment boundaries; join only explicit PowerShell continuations.

    The caller retains the whole executable block as one source unit. Comment
    lines remain PowerShell comments, never prose or standalone bare commands.
    """
    out, carry = [], ""
    for l in raw_lines:
        t = plain_code(re.sub(r"</?pre>", "", l))
        if carry:
            t = (carry + " " + t).strip()
            carry = ""
        if t.endswith("`"):
            carry = t[:-1].rstrip()
            continue
        out.append(t)
    if carry:
        out.append(carry)
    return out


def canon(x):
    return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _parse_all(sources):
    """{policy_id: {"file", "statement": {text, file, line}, "instr_heading_line", "instructions": [item]}}; item = {kind: num|bul|para|pre, level: 0|1,
    label ("9" for numbered items), raw, text (plain), lines (pre only: plain code lines), file, line_start, line_end}."""
    sect = {}
    for fname, text in sorted(sources.items()):
        cur = None
        raw_fence = raw_html = False
        for i, line in enumerate(text.splitlines(), 1):
            # A command/comment can look like a markdown heading. Keep the
            # entire block in Instructions before interpreting headings.
            if cur and cur[1] and (raw_fence or raw_html or line.lstrip().startswith("```") or "<pre>" in line):
                sect[cur[0]]["lines"].append((i, line, fname))
                if line.lstrip().startswith("```") and not raw_html:
                    raw_fence = not raw_fence
                elif not raw_fence:
                    if "<pre>" in line:
                        raw_html = True
                    if "</pre>" in line:
                        raw_html = False
                continue
            m = _HEAD.match(line)
            if m:
                cur = (m[1], bool(m[2]))
                d = sect.setdefault(cur[0], {"statement": None, "lines": [], "file": fname})
                if cur[1]:
                    d["instr_heading_line"] = i
                continue
            if _ANYHEAD.match(line):
                cur = None
                continue
            if cur is None:
                continue
            d = sect[cur[0]]
            if not cur[1]:
                if d["statement"] is None and line.strip() and not line.startswith(("[![", "<!--", "- _", " ")):
                    d["statement"] = {"text": plain(line), "file": fname, "line": i}
                elif d["statement"] is not None and not d.get("stmt_done"):
                    if line.strip() and not line.startswith(("[![", "<!--", "- _", " ")):
                        d["statement"]["text"] += " " + plain(line)
                        d["statement"]["line_end"] = i
                    else:
                        d["stmt_done"] = True
                continue
            d["lines"].append((i, line, fname))
    res = {}
    for pid, d in sect.items():
        steps = []
        in_pre = False
        last_blank = True
        for i, line, fname in d["lines"]:
            if not line.strip():
                last_blank = True
                continue
            nl = last_blank
            last_blank = False
            kind = level = label = body = None
            for k, rx, lv in (("num", _TOP_NUM, 0), ("bul", _TOP_BUL, 0), ("num", _NEST_NUM, 1), ("bul", _NEST_BUL, 1)):
                m = rx.match(line)
                if m and not in_pre:
                    kind, level, body = k, lv, m.group(m.lastindex)
                    label = m.group(1) if k == "num" else None
                    break
            if kind:
                steps.append({"kind": kind, "level": level, "label": label, "raw": body, "file": fname, "line_start": i, "line_end": i})
                continue
            stripped = line.strip()
            if stripped.startswith("```"):
                if in_pre == "code":
                    in_pre = False
                else:
                    in_pre = "code"
                    steps.append({"kind": "pre", "level": 0, "label": None, "raw": "", "file": fname, "line_start": i, "line_end": i, "lines": []})
                steps[-1]["line_end"] = i
                continue
            if in_pre == "code":
                steps[-1]["lines"].append(stripped)
                steps[-1]["raw"] += " ; " + stripped
                steps[-1]["line_end"] = i
                continue
            if "<pre>" in line:
                in_pre = "html"
                steps.append({"kind": "pre", "level": 0, "label": None, "raw": "", "file": fname, "line_start": i, "line_end": i, "lines": []})
                rest = re.sub(r"</?pre>", "", stripped).strip()
                if rest:
                    steps[-1]["lines"].append(rest)
                    steps[-1]["raw"] += " ; " + rest
            elif in_pre == "html":
                steps[-1]["raw"] += " ; " + stripped
                steps[-1]["lines"].append(stripped)
                steps[-1]["line_end"] = i
            else:
                t = stripped
                if t.startswith(">"):
                    t = t.lstrip("> ").strip()
                if steps and not nl and steps[-1]["kind"] in ("para", "num", "bul"):
                    steps[-1]["raw"] += " " + t
                    steps[-1]["line_end"] = i
                else:
                    steps.append({"kind": "para", "level": 0, "label": None, "raw": t, "file": fname, "line_start": i, "line_end": i})
            if in_pre == "html" and "</pre>" in line:
                in_pre = False
        for s in steps:
            if s["kind"] == "pre":
                s["lines"] = [x for x in _code_lines(s["lines"]) if x]
                s["text"] = "\n".join(s["lines"])
            else:
                s["text"] = plain(s["raw"])
        res[pid] = {"file": d["file"], "statement": d["statement"], "instructions": [s for s in steps if s.get("text")], "instr_heading_line": d.get("instr_heading_line")}
    return res


def item_lines(item):
    """Executable blocks are indivisible; navigation preformatted lines are prose."""
    if item["kind"] == "pre" and not command_block(item["text"]):
        return [x for x in item["lines"] if x]
    return [item["text"]] if item["text"] else []


def command_block(text):
    """Distinguish executable pre blocks from preformatted portal navigation."""
    return bool(re.search(r"(?m)^\s*(?:\$[A-Za-z_]|[A-Za-z]+-[A-Za-z]+\b)", text))


def build_baselines(read_text: ReadText) -> BaselineIndex:
    """Extract the pinned markdown at build time; the caller verifies its checkout.

    Paths passed to read_text are relative to the upstream repository root.
    The removed-policy file is hashed and attributed, but is not an active policy.
    """
    names = (*BASELINE_FILES, "removedpolicies.md")
    files = {f"{BASELINE_DIR}/{name}": read_text(f"{BASELINE_DIR}/{name}") for name in names}
    files["LICENSE"] = read_text("LICENSE")
    sources = {name: files[f"{BASELINE_DIR}/{name}"] for name in BASELINE_FILES}
    parsed = _parse_all(sources)
    policies = {}
    for name, text in sorted(sources.items()):
        statements, criticalities, current = {}, {}, None
        for line in text.splitlines():
            match = _HEAD.match(line)
            if match:
                current = None if match[2] else match[1]
                if current:
                    if current in statements:
                        raise ValueError(f"duplicate policy: {current}")
                    statements[current] = []
                continue
            if _ANYHEAD.match(line):
                current = None
                continue
            if current:
                statements[current].append(line)
            match = _CRIT.search(line)
            if match:
                criticalities[match[1]] = match[2].title() if match[2].isupper() else match[2]
        for pid, lines in statements.items():
            if pid in policies:
                raise ValueError(f"duplicate policy: {pid}")
            statement = []
            for line in lines:
                if line.startswith(("[![", "<!--")):
                    break
                if line.strip():
                    statement.append(line.strip())
            units = []
            for item in parsed[pid]["instructions"]:
                for text_line in item_lines(item):
                    units.append({
                        "text": text_line, "kind": item["kind"],
                        "label": item["label"], "level": item["level"],
                        "source": {"file": name, "line_start": item["line_start"],
                                   "line_end": item["line_end"], "policy_id": pid},
                    })
                    if item["kind"] == "pre" and command_block(item["text"]):
                        units[-1]["command"] = True
            policies[pid] = {"requirement": plain(" ".join(statement)),
                             "criticality": criticalities.get(pid), "instructions": units}
    if len(policies) != 109:
        raise ValueError(f"expected 109 baseline policies, found {len(policies)}")
    attribution_files = {}
    for name in names:
        text = files[f"{BASELINE_DIR}/{name}"]
        attribution_files[f"{BASELINE_DIR}/{name}"] = {
            "source_url": f"https://github.com/cisagov/ScubaGear/blob/{SOURCE_COMMIT}/{BASELINE_DIR}/{name}",
            "source_links": sorted(set(re.findall(r"https?://[^\s)<>\]]+", text))),
            "notices": [line for line in text.splitlines()
                        if "Portions of this document are adapted" in line
                        or "Information is subject to standard copyright rules" in line
                        or 'being provided "as is"' in line],
        }
    result = {
        "schema_version": 1, "source_commit": SOURCE_COMMIT,
        "source_sha256": {path: hashlib.sha256(text.encode("utf-8")).hexdigest()
                          for path, text in sorted(files.items())},
        "attribution": {
            "creators": ["CISA SCuBA / ScubaGear", "Microsoft"],
            "repository": "https://github.com/cisagov/ScubaGear",
            "licences": [
                {"name": "CC0 1.0 Universal", "url": "https://creativecommons.org/publicdomain/zero/1.0/",
                 "scope": "ScubaGear repository dedication; see upstream LICENSE"},
                {"name": "CC BY 4.0", "url": "https://creativecommons.org/licenses/by/4.0/",
                 "scope": "Microsoft documentation portions identified in baseline headers"},
            ],
            "changes": "Plain-text extraction of requirements and Instructions; markdown formatting, link destinations and images omitted from prose; dashes and whitespace normalised; code continuations joined; executable blocks and PowerShell comment line boundaries preserved as indivisible units. Navigation pre blocks remain separate lines. Cross-referenced units appended in baseline order. Other baseline sections and removed policies omitted from the runtime policy index. SECURITYSUITE.1.2's self-pointer explicitly resolves to SECURITYSUITE.1.1.",
            "notice": "TLP:CLEAR remains subject to copyright. Provided as is; no CISA or Microsoft endorsement is implied.",
            "files": attribution_files,
        },
        "xrefs": [{"policy_id": pid, "target": target,
                   "labels": list(labels) if labels is not None else None}
                  for pid, (target, labels) in sorted(XREF.items())],
        "policies": dict(sorted(policies.items())),
    }
    _validate(result)
    # Fail generation if an explicit target label ceases to exist.
    for row in result["xrefs"]:
        _resolved_units(result, row["policy_id"])
    return result


def _validate(index: BaselineIndex) -> None:
    """Reject broken vendored data instead of inventing baseline text."""
    if not isinstance(index, dict) or type(index.get("schema_version")) is not int or index["schema_version"] != 1:
        raise ValueError("unsupported baseline schema")
    if index.get("source_commit") != SOURCE_COMMIT:
        raise ValueError("baseline source commit mismatch")
    hashes = index.get("source_sha256")
    expected_files = {f"{BASELINE_DIR}/{name}" for name in (*BASELINE_FILES, "removedpolicies.md")} | {"LICENSE"}
    if not isinstance(hashes, dict) or set(hashes) != expected_files or any(
        not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) for value in hashes.values()
    ):
        raise ValueError("invalid baseline source hashes")
    if not isinstance(index.get("attribution"), dict) or not index["attribution"]:
        raise ValueError("missing baseline attribution")
    expected_xrefs = [{"policy_id": pid, "target": target, "labels": list(labels) if labels else None}
                      for pid, (target, labels) in sorted(XREF.items())]
    if index.get("xrefs") != expected_xrefs:
        raise ValueError("baseline cross-reference contract mismatch")
    policies = index.get("policies")
    if not isinstance(policies, dict) or len(policies) != 109:
        raise ValueError("invalid baseline policy inventory")
    for pid, policy in policies.items():
        if not isinstance(pid, str) or not re.fullmatch(r"MS\.[A-Z]+\.\d+\.\d+v\d+", pid):
            raise ValueError("invalid baseline policy id")
        if (not isinstance(policy, dict) or set(policy) != {"requirement", "criticality", "instructions"}
                or not isinstance(policy.get("requirement"), str)
                or not (policy.get("criticality") is None or isinstance(policy["criticality"], str))
                or not isinstance(policy.get("instructions"), list)):
            raise ValueError(f"invalid baseline policy: {pid}")
        for unit in policy["instructions"]:
            if (not isinstance(unit, dict) or set(unit) not in ({"text", "kind", "label", "level", "source"},
                    {"text", "kind", "label", "level", "source", "command"})
                    or ("command" in unit and (unit["command"] is not True or unit["kind"] != "pre"))):
                raise ValueError(f"invalid baseline unit: {pid}")
            source = unit["source"]
            if (not isinstance(unit["text"], str) or not unit["text"]
                    or unit["kind"] not in ("num", "bul", "para", "pre")
                    or not (unit["label"] is None or isinstance(unit["label"], str))
                    or type(unit["level"]) is not int or unit["level"] not in (0, 1)
                    or not isinstance(source, dict)
                    or set(source) != {"file", "line_start", "line_end", "policy_id"}
                    or source["file"] not in BASELINE_FILES or source["policy_id"] != pid
                    or type(source["line_start"]) is not int or type(source["line_end"]) is not int
                    or not 1 <= source["line_start"] <= source["line_end"]):
                raise ValueError(f"invalid baseline unit metadata: {pid}")
    for row in index["xrefs"]:
        if row["policy_id"] not in policies or row["target"] not in policies:
            raise ValueError("missing baseline cross-reference policy")


def load_baselines(read_text: ReadText) -> BaselineIndex:
    """Read only configs/explainer-baselines.json via the caller's resource reader.

    Pass azure_tenant_audit.resources.open_text_resource in the product. No
    checkout, discovery, generation, caching or filesystem access occurs here.
    """
    index = json.loads(read_text(RESOURCE))
    _validate(index)
    return index


def requirement(index: BaselineIndex, policy_id: str) -> str:
    """Return the policy requirement; unknown/absent baseline ids have no prose."""
    return index["policies"].get(policy_id, {}).get("requirement", "")


def criticality(index: BaselineIndex, policy_id: str) -> str | None:
    return index["policies"].get(policy_id, {}).get("criticality")


def _resolved_units(index: BaselineIndex, policy_id: str) -> list[Unit]:
    own = index["policies"].get(policy_id, {}).get("instructions", [])
    result = list(own)
    for row in index["xrefs"]:
        if row["policy_id"] != policy_id:
            continue
        target = index["policies"][row["target"]]["instructions"]
        labels = row["labels"]
        if labels is None:
            result.extend(target)
            continue
        selected, found = False, set()
        for unit in target:
            if unit["level"] == 0:
                selected = unit["kind"] == "num" and unit["label"] in labels
                if selected:
                    found.add(unit["label"])
            if selected:
                result.append(unit)
        if found != set(labels):
            raise ValueError(f"cross-reference labels missing in {row['target']}")
    return result


def _capped(index: BaselineIndex, policy_id: str, cap: int) -> tuple[list[Unit], dict | None]:
    if type(cap) is not int or cap < 2:
        raise ValueError("baseline cap must be an integer of at least 2")
    units = _resolved_units(index, policy_id)
    # As in S, the cap covers the canonical JSON array of customer strings,
    # excluding provenance. Count characters, including quotes/escapes/commas.
    sizes = [len(canon(unit["text"])) for unit in units]
    full = 2 + sum(sizes) + max(0, len(units) - 1)
    if full <= cap:
        return units, None
    size, count = 2, 0
    for length in sizes:
        next_size = size + length + (1 if count else 0)
        if next_size > cap:
            break
        size, count = next_size, count + 1
    report = {"lines_total": len(units), "lines_kept": count,
              "own_lines": len(index["policies"].get(policy_id, {}).get("instructions", [])),
              "chars_full": full, "chars_kept": size,
              "rule": "whole trailing units dropped; own units before cross-referenced units; no unit cut or summarised"}
    return units[:count], report


def instructions(index: BaselineIndex, policy_id: str, *, cap: int = CAP) -> list[Unit]:
    """Own units, then explicitly resolved target units, capped without mutation."""
    return deepcopy(_capped(index, policy_id, cap)[0])


def cap_report(index: BaselineIndex, policy_id: str, *, cap: int = CAP) -> dict | None:
    """Report whole-unit truncation, or None; the default cap hits no pinned policy."""
    return _capped(index, policy_id, cap)[1]

