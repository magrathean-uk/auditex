"""User-authored text (Gmail vacation and signature, Graph auto-reply bodies) never reaches raw or normalized output."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from auditex.google_workspace.client import GoogleWorkspaceClient, minimise_gmail_settings
from auditex.google_workspace.collectors import GoogleGmailSettingsCollector
from auditex.google_workspace.normalize import build_google_normalized_snapshot
from azure_tenant_audit.collectors.mailbox_forwarding import MailboxForwardingCollector, minimise_mailbox_settings
from azure_tenant_audit.normalize import build_normalized_snapshot

VACATION_BODY = "I am away until the 3rd. Call Dana on 07700 900123 about the Acme merger."
VACATION_HTML = "<p>I am away until the 3rd. Call Dana on 07700 900123 about the Acme merger.</p>"
VACATION_SUBJECT = "Out of office - Acme merger"
SIGNATURE = "<div>Dana Whitfield, CFO<br>Acme Holdings, 1 Secret Lane</div>"
INTERNAL_REPLY = "<html>Internal: contact finance-team for the Acme merger papers.</html>"
EXTERNAL_REPLY = "<html>External: I am on leave; ring 07700 900123.</html>"
SECRETS = (VACATION_BODY, VACATION_HTML, VACATION_SUBJECT, SIGNATURE, INTERNAL_REPLY, EXTERNAL_REPLY, "07700 900123", "Acme merger", "Secret Lane")


class _Execute:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def execute(self) -> dict[str, Any]:
        return self._payload


class _Listing:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def list(self, **_: Any) -> _Execute:
        return _Execute(self._payload)


class _GmailSettings:
    def getAutoForwarding(self, **_: Any) -> _Execute:  # noqa: N802
        return _Execute({"enabled": False})

    def filters(self) -> _Listing:
        return _Listing({"filter": []})

    def forwardingAddresses(self) -> _Listing:  # noqa: N802
        return _Listing({"forwardingAddresses": []})

    def sendAs(self) -> _Listing:  # noqa: N802
        return _Listing(
            {
                "sendAs": [
                    {"sendAsEmail": "dana@acme.test", "isPrimary": True, "displayName": "Dana", "signature": SIGNATURE},
                    {"sendAsEmail": "alias@acme.test", "isPrimary": False, "signature": ""},
                ]
            }
        )

    def getImap(self, **_: Any) -> _Execute:  # noqa: N802
        return _Execute({"enabled": True})

    def getPop(self, **_: Any) -> _Execute:  # noqa: N802
        return _Execute({"accessWindow": "disabled"})

    def getVacation(self, **_: Any) -> _Execute:  # noqa: N802
        return _Execute(
            {
                "enableAutoReply": True,
                "restrictToDomain": False,
                "restrictToContacts": False,
                "responseSubject": VACATION_SUBJECT,
                "responseBodyPlainText": VACATION_BODY,
                "responseBodyHtml": VACATION_HTML,
                "startTime": "1760000000000",
                "endTime": "1760600000000",
            }
        )

    def delegates(self) -> _Listing:
        return _Listing({"delegates": []})


class _Gmail:
    def users(self) -> "_Gmail":
        return self

    def settings(self) -> _GmailSettings:
        return _GmailSettings()


def _client() -> GoogleWorkspaceClient:
    client = GoogleWorkspaceClient(credentials=object())
    assert client._services is not None
    client._services[("gmail", "v1")] = _Gmail()
    return client


def _assert_no_user_text(rendered: str) -> None:
    for secret in SECRETS:
        assert secret not in rendered, secret


def test_gmail_client_drops_vacation_and_signature_text_but_keeps_booleans_and_lengths() -> None:
    payload = _client().get_gmail_settings_for_user("dana@acme.test")

    _assert_no_user_text(json.dumps(payload))
    vacation = payload["vacation"]
    assert vacation["enableAutoReply"] is True
    assert vacation["restrictToDomain"] is False
    assert vacation["restrictToContacts"] is False
    assert vacation["startTime"] == "1760000000000"
    assert vacation["responseBodyPlainTextLength"] == len(VACATION_BODY)
    assert vacation["responseBodyHtmlLength"] == len(VACATION_HTML)
    assert vacation["responseSubjectLength"] == len(VACATION_SUBJECT)
    assert vacation["hasResponseBodyPlainText"] is True and vacation["hasResponseSubject"] is True
    primary, alias = payload["sendAs"]
    assert primary["sendAsEmail"] == "dana@acme.test" and primary["isPrimary"] is True
    assert primary["signatureLength"] == len(SIGNATURE) and primary["hasSignature"] is True
    assert alias["signatureLength"] == 0 and alias["hasSignature"] is False


def test_minimise_gmail_settings_is_idempotent_and_does_not_mutate_its_input() -> None:
    original = {"userEmail": "a@b.test", "vacation": {"enableAutoReply": True, "responseBodyHtml": "<b>x</b>"}, "sendAs": [{"signature": "sig"}]}

    once = minimise_gmail_settings(original)
    twice = minimise_gmail_settings(once)

    assert once == twice
    assert original["vacation"]["responseBodyHtml"] == "<b>x</b>"  # type: ignore[index]
    assert original["sendAs"][0]["signature"] == "sig"  # type: ignore[index]
    assert minimise_gmail_settings({"userEmail": "a@b.test"}) == {"userEmail": "a@b.test"}


class _LeakyClient:
    """A client that hands the collector unstripped settings; the collector must still drop the text."""

    def get_gmail_settings_for_user(self, user_email: str) -> dict[str, Any]:
        return {
            "userEmail": user_email,
            "vacation": {"enableAutoReply": True, "restrictToDomain": False, "responseBodyPlainText": VACATION_BODY, "responseBodyHtml": VACATION_HTML, "responseSubject": VACATION_SUBJECT},
            "sendAs": [{"sendAsEmail": user_email, "signature": SIGNATURE}],
        }


def test_gmail_collector_payload_and_normalized_snapshot_carry_no_user_text() -> None:
    result = GoogleGmailSettingsCollector().run(
        {"client": _LeakyClient(), "users": [{"primaryEmail": "dana@acme.test"}], "top": 10}
    )

    _assert_no_user_text(json.dumps(result.payload))
    snapshot = build_google_normalized_snapshot(
        tenant_name="acme", run_id="r1", collector_payloads={"google_gmail_settings": result.payload}, domain="acme.test"
    )
    _assert_no_user_text(json.dumps(snapshot, default=str))
    setting = snapshot["google_mailbox_settings"]["records"][0]
    assert setting["vacation"]["enableAutoReply"] is True
    assert setting["vacation"]["restrictToDomain"] is False


def test_vacation_finding_still_fires_from_the_stripped_settings() -> None:
    from auditex.google_workspace.findings import build_google_findings

    result = GoogleGmailSettingsCollector().run({"client": _LeakyClient(), "users": [{"primaryEmail": "dana@acme.test"}], "top": 10})
    snapshot = build_google_normalized_snapshot(
        tenant_name="acme", run_id="r1", collector_payloads={"google_gmail_settings": result.payload}, domain="acme.test"
    )

    findings = build_google_findings(snapshot)

    assert "google.gmail_vacation_external_reply" in {row.get("rule_id") for row in findings}
    _assert_no_user_text(json.dumps(findings, default=str))


class _GraphClient:
    def get_all(self, path: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:  # noqa: ARG002
        if path == "/users":
            return [{"id": "u1", "userPrincipalName": "dana@acme.test", "mail": "dana@acme.test"}]
        return [{"id": "acme.test", "isVerified": True}]

    def get_json(self, path: str, params: dict[str, Any] | None = None, full_url: bool = False) -> dict[str, Any]:  # noqa: ARG002
        if path.endswith("/messageRules"):
            return {"value": []}
        return {
            "timeZone": "UTC",
            "automaticRepliesSetting": {
                "status": "alwaysEnabled",
                "externalAudience": "all",
                "scheduledStartDateTime": {"dateTime": "2026-10-20T00:00:00", "timeZone": "UTC"},
                "internalReplyMessage": INTERNAL_REPLY,
                "externalReplyMessage": EXTERNAL_REPLY,
            },
        }


def test_graph_auto_reply_bodies_are_dropped_before_raw_and_normalized_output() -> None:
    result = MailboxForwardingCollector().run({"client": _GraphClient(), "top": 10})

    _assert_no_user_text(json.dumps(result.payload))
    settings = result.payload["mailboxSettings"]["value"][0]["settings"]
    auto = settings["automaticRepliesSetting"]
    assert auto["status"] == "alwaysEnabled" and auto["externalAudience"] == "all"
    assert auto["scheduledStartDateTime"]["dateTime"] == "2026-10-20T00:00:00"
    assert auto["internalReplyMessageLength"] == len(INTERNAL_REPLY) and auto["hasInternalReplyMessage"] is True
    assert auto["externalReplyMessageLength"] == len(EXTERNAL_REPLY) and auto["hasExternalReplyMessage"] is True
    assert settings["timeZone"] == "UTC"

    snapshot = build_normalized_snapshot(
        tenant_name="acme", run_id="r1", collector_payloads={"mailbox_forwarding": result.payload}, diagnostics=[], result_rows=[]
    )
    _assert_no_user_text(json.dumps(snapshot, default=str))


def test_minimise_mailbox_settings_keeps_settings_without_an_auto_reply_block() -> None:
    assert minimise_mailbox_settings({"timeZone": "UTC"}) == {"timeZone": "UTC"}
    assert minimise_mailbox_settings({"automaticRepliesSetting": {"status": "disabled"}}) == {
        "automaticRepliesSetting": {"status": "disabled"}
    }


def test_offline_google_bundle_written_from_leaky_rows_has_no_user_text(tmp_path: Path) -> None:
    from azure_tenant_audit.output import AuditWriter

    result = GoogleGmailSettingsCollector().run({"client": _LeakyClient(), "users": [{"primaryEmail": "dana@acme.test"}], "top": 10})
    writer = AuditWriter(tmp_path, tenant_name="acme", run_name="r1")
    writer.write_raw("google_gmail_settings", result.payload)

    for path in writer.run_dir.rglob("*"):
        if path.is_file():
            _assert_no_user_text(path.read_text(encoding="utf-8", errors="ignore"))


# --- the offline replay path and the writer (found in review) -----------------------------------------


def _all_text(root: Path) -> str:
    chunks = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix in {".json", ".jsonl", ".md", ".log", ""}:
            chunks.append(path.read_text(encoding="utf-8", errors="ignore"))
    return "\n".join(chunks)


def test_minimise_user_text_strips_every_shape_wherever_it_appears() -> None:
    from azure_tenant_audit.data_minimisation import minimise_user_text

    nested = {
        "a": [{"vacation": {"responseBodyHtml": VACATION_HTML}}],  # no enableAutoReply: keyed on the parent
        "b": {"enableAutoReply": False, "responseSubject": VACATION_SUBJECT, "responseBodyPlainText": VACATION_BODY},
        "c": [{"sendAsEmail": "x@y.test", "signature": SIGNATURE}],
        "d": {"settings": {"automaticRepliesSetting": {"status": "scheduled", "internalReplyMessage": INTERNAL_REPLY}}},
        "e": {"externalReplyMessage": EXTERNAL_REPLY},
        "keep": {"signature": "a signature key outside a send-as entry is not touched", "n": 1},
    }
    before = json.dumps(nested, sort_keys=True)

    result = minimise_user_text(nested)

    assert json.dumps(nested, sort_keys=True) == before  # the input is not mutated
    rendered = json.dumps(result)
    _assert_no_user_text(rendered)
    assert result["a"][0]["vacation"]["hasResponseBodyHtml"] is True
    assert result["b"]["enableAutoReply"] is False and result["b"]["responseSubjectLength"] == len(VACATION_SUBJECT)
    assert result["c"][0]["signatureLength"] == len(SIGNATURE) and result["c"][0]["sendAsEmail"] == "x@y.test"
    assert result["d"]["settings"]["automaticRepliesSetting"]["status"] == "scheduled"
    assert result["e"]["hasExternalReplyMessage"] is True
    assert result["keep"]["signature"].startswith("a signature key")
    assert minimise_user_text(result) == result  # idempotent
    assert minimise_user_text("text") == "text" and minimise_user_text(None) is None


def test_google_offline_replay_drops_vacation_and_signature_text_from_raw_and_normalized(tmp_path: Path) -> None:
    from auditex.google_workspace.run import run_google_offline

    sample = {
        "google_gmail_settings": {
            "mailboxSettings": {
                "value": [
                    {
                        "userEmail": "dana@acme.test",
                        "vacation": {
                            "enableAutoReply": True,
                            "restrictToDomain": False,
                            "responseSubject": VACATION_SUBJECT,
                            "responseBodyPlainText": VACATION_BODY,
                            "responseBodyHtml": VACATION_HTML,
                        },
                        "sendAs": [{"sendAsEmail": "dana@acme.test", "isPrimary": True, "signature": SIGNATURE}],
                    }
                ]
            }
        }
    }
    sample_path = tmp_path / "replay.json"
    sample_path.write_text(json.dumps(sample), encoding="utf-8")

    rc = run_google_offline(
        sample_path=sample_path, out=tmp_path / "out", tenant_name="Acme", run_name="replay", domain="acme.test", customer_id="C1"
    )

    assert rc in {0, 1}
    run_dir = tmp_path / "out" / "Acme-replay"
    _assert_no_user_text(_all_text(run_dir))
    raw = json.loads((run_dir / "raw" / "google_gmail_settings.json").read_text(encoding="utf-8"))
    row = raw["mailboxSettings"]["value"][0]
    assert row["vacation"]["enableAutoReply"] is True and row["vacation"]["responseBodyHtmlLength"] == len(VACATION_HTML)
    assert row["sendAs"][0]["hasSignature"] is True
    normalized = json.loads((run_dir / "normalized" / "google_mailbox_settings.json").read_text(encoding="utf-8"))
    vacation = normalized["records"][0]["vacation"]
    assert vacation["enableAutoReply"] is True and vacation["restrictToDomain"] is False
    assert vacation["hasResponseBodyPlainText"] is True


def test_m365_offline_replay_drops_auto_reply_bodies_from_raw_and_normalized(tmp_path: Path) -> None:
    from azure_tenant_audit.cli import run_offline

    sample = {
        "mailbox_forwarding": {
            "messageRules": {"value": []},
            "mailboxSettings": {
                "value": [
                    {
                        "user_id": "u1",
                        "user_principal_name": "dana@acme.test",
                        "settings": {
                            "timeZone": "UTC",
                            "automaticRepliesSetting": {
                                "status": "alwaysEnabled",
                                "externalAudience": "all",
                                "internalReplyMessage": INTERNAL_REPLY,
                                "externalReplyMessage": EXTERNAL_REPLY,
                            },
                        },
                    }
                ]
            },
        }
    }
    sample_path = tmp_path / "replay.json"
    sample_path.write_text(json.dumps(sample), encoding="utf-8")

    rc = run_offline(sample_path, tmp_path / "out", "acme", "replay")

    assert rc in {0, 1}
    run_dir = tmp_path / "out" / "acme-replay"
    _assert_no_user_text(_all_text(run_dir))
    copied = json.loads((run_dir / "raw" / "sample_input.json").read_text(encoding="utf-8"))
    auto = copied["mailbox_forwarding"]["mailboxSettings"]["value"][0]["settings"]["automaticRepliesSetting"]
    assert auto["status"] == "alwaysEnabled" and auto["externalAudience"] == "all"
    assert auto["internalReplyMessageLength"] == len(INTERNAL_REPLY) and auto["hasExternalReplyMessage"] is True
    normalized = json.loads((run_dir / "normalized" / "mailbox_setting_objects.json").read_text(encoding="utf-8"))
    settings = normalized["records"][0]["settings"]["automaticRepliesSetting"]
    assert settings["status"] == "alwaysEnabled" and settings["hasInternalReplyMessage"] is True


def test_normalizers_strip_text_even_when_called_directly_with_replay_rows() -> None:
    leaky = {
        "mailbox_forwarding": {
            "messageRules": {"value": []},
            "mailboxSettings": {
                "value": [{"user_id": "u1", "settings": {"automaticRepliesSetting": {"status": "x", "internalReplyMessage": INTERNAL_REPLY}}}]
            },
        }
    }
    snapshot = build_normalized_snapshot(tenant_name="a", run_id="r", collector_payloads=leaky, diagnostics=[], result_rows=[])
    _assert_no_user_text(json.dumps(snapshot, default=str))

    google = {"google_gmail_settings": {"mailboxSettings": {"value": [{"userEmail": "d@a.test", "vacation": {"responseBodyHtml": VACATION_HTML}, "sendAs": [{"signature": SIGNATURE}]}]}}}
    normalized = build_google_normalized_snapshot(tenant_name="a", run_id="r", collector_payloads=google, domain="a.test")
    _assert_no_user_text(json.dumps(normalized, default=str))


def test_writer_strips_the_text_from_every_data_file_it_writes(tmp_path: Path) -> None:
    from azure_tenant_audit.output import AuditWriter

    writer = AuditWriter(tmp_path, tenant_name="acme", run_name="w")
    row = {"vacation": {"enableAutoReply": True, "responseBodyHtml": VACATION_HTML}, "sendAs": [{"sendAsEmail": "a@b.test", "signature": SIGNATURE}]}
    writer.write_raw("x", {"mailboxSettings": {"value": [row]}})
    writer.write_normalized("y", {"records": [row]})
    writer.write_ai_safe("z", {"rows": [row]})
    writer.write_chunk_records("c", "n", 1, [row])
    writer.write_export_records("c", "op", 1, [row])

    _assert_no_user_text(_all_text(writer.run_dir))
    assert json.loads((writer.raw_dir / "x.json").read_text(encoding="utf-8"))["mailboxSettings"]["value"][0]["vacation"]["enableAutoReply"] is True
