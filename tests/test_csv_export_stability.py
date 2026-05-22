"""D4: CSV export stability.

The CSV exporter (``auditex.reporting._render_csv``) feeds operators'
spreadsheets and downstream pipelines. The contract:

1. Stable column order with identifiers, triage fields, and remediation guidance.
2. Deterministic row order: severity desc → rule_id → record_key → id.
3. RFC 4180 quoting (Python's ``csv.writer`` default is RFC 4180
   compliant; this test guards against future regressions).
4. Byte-equal output for the same input → byte-equal across re-runs.
"""
from __future__ import annotations

from auditex.reporting import _render_csv


_FINDINGS_UNSORTED = [
    {
        "id": "rule.medium:obj-1",
        "title": "Medium",
        "severity": "medium",
        "status": "open",
        "rule_id": "rule.medium",
        "collector": "collector-medium",
        "impact": "Medium impact",
        "remediation": "Fix medium.",
        "expected_value": "Medium expected",
        "evidence_refs": [{"record_key": "section:medium-1"}],
    },
    {
        "id": "rule.high:obj-2",
        "title": "High 2",
        "severity": "high",
        "status": "open",
        "rule_id": "rule.high",
        "collector": "collector-high",
        "impact": "High impact 2",
        "remediation": "Fix high 2.",
        "affected_objects": ["obj-2"],
        "evidence_refs": [{"record_key": "section:high-2"}],
    },
    {
        "id": "rule.critical:obj-1",
        "title": "Crit",
        "severity": "critical",
        "status": "open",
        "rule_id": "rule.critical",
        "collector": "collector-critical",
        "impact": "Critical impact",
        "remediation": "Fix critical.",
        "evidence_refs": [{"record_key": "section:crit-1"}],
    },
    {
        "id": "rule.high:obj-1",
        "title": "High 1",
        "severity": "high",
        "status": "open",
        "rule_id": "rule.high",
        "collector": "collector-high",
        "impact": "High impact 1",
        "remediation": "Fix high 1.",
        "affected_objects": ["obj-1"],
        "evidence_refs": [{"record_key": "section:high-1"}],
    },
    {
        "id": "rule.low:obj-1",
        "title": "Low",
        "severity": "low",
        "status": "open",
        "rule_id": "rule.low",
        "collector": "collector-low",
        "impact": "Low impact",
        "remediation": "Fix low.",
        "evidence_refs": [{"record_key": "section:low-1"}],
    },
]


def test_csv_export_columns_match_canonical_order() -> None:
    csv_output = _render_csv({"findings": _FINDINGS_UNSORTED})
    header = csv_output.splitlines()[0]
    assert header == "id,title,severity,status,rule_id,collector,affected_objects,impact,remediation,expected_value"


def test_csv_export_includes_actionable_audit_fields() -> None:
    csv_output = _render_csv({"findings": _FINDINGS_UNSORTED})

    assert "rule.critical" in csv_output
    assert "collector-critical" in csv_output
    assert "Critical impact" in csv_output
    assert "Fix critical." in csv_output
    assert '[""obj-1""]' in csv_output


def test_csv_export_sorts_rows_severity_desc_then_rule_id_then_record_key() -> None:
    csv_output = _render_csv({"findings": _FINDINGS_UNSORTED})
    body_lines = csv_output.splitlines()[1:]  # skip header
    titles = [line.split(",")[1] for line in body_lines]
    # Critical first, then high (sorted by record_key within rule), then medium, then low.
    assert titles == ["Crit", "High 1", "High 2", "Medium", "Low"]


def test_csv_export_is_byte_equal_across_renders() -> None:
    """The same input must produce byte-equal CSV — D4 idempotency."""
    a = _render_csv({"findings": _FINDINGS_UNSORTED})
    b = _render_csv({"findings": _FINDINGS_UNSORTED})
    assert a == b


def test_csv_export_is_byte_equal_when_input_order_differs() -> None:
    """Reordering the input must NOT change the output (sort is stable)."""
    a = _render_csv({"findings": _FINDINGS_UNSORTED})
    shuffled = list(reversed(_FINDINGS_UNSORTED))
    b = _render_csv({"findings": shuffled})
    assert a == b


def test_csv_export_handles_unknown_severity_at_end() -> None:
    """Findings with an unknown / blank severity must sort AFTER the
    known severity tiers — never above them."""
    findings = [
        {"id": "x", "title": "X", "severity": "weird", "status": "open"},
        {"id": "c", "title": "C", "severity": "critical", "status": "open"},
        {"id": "h", "title": "H", "severity": "high", "status": "open"},
    ]
    csv_output = _render_csv({"findings": findings})
    titles = [line.split(",")[1] for line in csv_output.splitlines()[1:]]
    assert titles == ["C", "H", "X"]


def test_csv_export_quotes_fields_with_commas_and_newlines() -> None:
    """RFC 4180 quoting — embedded commas and newlines must be quoted."""
    findings = [
        {
            "id": "f1",
            "title": "Title, with comma",
            "severity": "high",
            "status": "open",
        },
        {
            "id": "f2",
            "title": "Title\nwith newline",
            "severity": "high",
            "status": "open",
        },
    ]
    csv_output = _render_csv({"findings": findings})
    # Both rows must be present and the embedded delimiters must be quoted.
    assert '"Title, with comma"' in csv_output
    assert '"Title\nwith newline"' in csv_output


def test_csv_export_stable_with_no_rule_id_or_record_key() -> None:
    """Findings without rule_id / record_key still sort stably (fall
    through to id)."""
    findings = [
        {"id": "b", "title": "B", "severity": "medium", "status": "open"},
        {"id": "a", "title": "A", "severity": "medium", "status": "open"},
    ]
    csv_output = _render_csv({"findings": findings})
    titles = [line.split(",")[1] for line in csv_output.splitlines()[1:]]
    assert titles == ["A", "B"]
