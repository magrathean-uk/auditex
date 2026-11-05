"""Reusable view-boundary canary auditor for integration's injected builder.

The callback is build(record, redacted_sections, section_order) -> View.
Projection pseudonymisation precedes that callback and remains integration's
responsibility. P exercises the view's idempotent e-mail guard, not a second
pseudonymiser. Nothing here imports product code or reads tenant evidence.
"""
import copy
import json

KEY = "zqcanary"


def twins(record, sections, section_order, *, fixed_sections=None):
    """Five independent mutations of already redacted synthetic inputs."""
    cited = list(record.get("cited_sections") or sections)
    for name in ("F", "U", "B", "P", "C"):
        rec, sec, order = copy.deepcopy((record, sections, section_order))
        if name == "F":
            for field in ("tenant_id", "tenant_name", "user_principal_name", "run_id", "path", "as_of", "case_id", "rule_view", "detail", "other_policy_verdicts", "gold_verdict", "credentials"):
                rec[field] = KEY + field
        elif name == "U":
            sec["extra_uncited"] = {"value": KEY + "uncited"}
            rec["cited_sections"] = cited
            order.append("extra_uncited")
        else:
            section = {"B": cited[0] if fixed_sections is not None else "extra_big_section",
                       "P": "privileged_users", "C": "scuba_config"}[name]
            sec[section] = {
                "B": {"value": KEY + "x" * 7000 + KEY},
                "P": {"u1": {"DisplayName": "User 0123456789abcdef", "OnPremisesImmutableId": "Id 0123456789abcdef", "Mail": KEY + "@public.example"}},
                "C": {"M365Environment": "commercial", "collection_status": "collected", "OutPath": "/srv/run-1234/" + KEY, "Aad": {"Users": [KEY]}},
            }[name]
            rec["cited_sections"] = [s for s in cited if s != section] + [section]
            if section not in order:
                order.append(section)
        yield name, rec, sec, order


def audit_twins(build, record, sections, section_order, *, fixed_sections=None):
    base = build(copy.deepcopy(record), copy.deepcopy(sections), list(section_order))
    canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    leaks, identical, rejected = [], {}, []
    for name, rec, sec, order in twins(record, sections, section_order, fixed_sections=fixed_sections):
        forbidden = fixed_sections is not None and any(s not in fixed_sections for s in rec.get("cited_sections", []))
        if forbidden:
            try:
                build(rec, sec, order)
            except ValueError:
                rejected.append(name)
            else:
                leaks.append(name + "-not-rejected")
            continue
        view = build(rec, sec, order)
        if KEY in canonical(view).casefold():
            leaks.append(name)
        if name in ("F", "U"):
            identical[name] = canonical(view) == canonical(base)
            if not identical[name]:
                leaks.append(name + "-not-identical")
    result = {"ok": not leaks, "leaks": leaks, "identical": identical}
    if fixed_sections is not None:
        result["rejected"] = rejected
    return result
