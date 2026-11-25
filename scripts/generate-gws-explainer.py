#!/usr/bin/env python3
"""Generate the offline Google Workspace explainer catalogue."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from azure_tenant_audit.resources import open_text_resource  # noqa: E402
from azure_tenant_audit.value_rules.gws.catalogue import catalogue  # noqa: E402


def generate():
    rules = catalogue()
    baselines = json.loads(open_text_resource("configs/scuba-gws-policy-sections.json"))["policies"]
    if set(baselines) != set(rules["policies"]):
        raise ValueError("GWS policy catalogues disagree")
    kinds = {}
    for kind, value in sorted(rules["kinds"].items()):
        kinds[kind] = {}
        for name, cell in sorted(value["cells"].items()):
            verdict = cell["verdict"]
            check = {
                "met": "Check the setting again after changes.",
                "not_met": "Check the setting against the baseline in the Admin console.",
                "not_assessed": "Check the setting and collect complete evidence in the Admin console.",
                "not_applicable": "Check whether the service is enabled.",
            }[verdict]
            kinds[kind][name] = {"remediation_steps": check, "reason_texts": cell.get("reason_texts", [])}
    return {"schema_version": 1, "policies": {
        pid: {"baseline_text": baselines[pid]["baseline_text"], "kind": row["kind"]}
        for pid, row in sorted(rules["policies"].items())}, "kinds": kinds,
        "shared_reasons": "Check the policy and report the assessment problem."}


def main():
    if sys.argv[1:] not in ([], ["--check"]):
        print("usage: generate-gws-explainer.py [--check]", file=sys.stderr)
        return 2
    check = bool(sys.argv[1:])
    output = Path("configs/explainer-gws-template.json")
    try:
        result = (json.dumps(generate(), ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
        if check:
            if output.read_bytes() != result:
                print("GWS explainer template drift", file=sys.stderr)
                return 1
        else:
            output.write_bytes(result)
    except (OSError, ValueError, KeyError):
        print("GWS explainer template generation failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
