"""Collector for Microsoft Entra cross-tenant access settings.

Captures the tenant-level cross-tenant access policy, default inbound/outbound
trust posture for B2B Collaboration and B2B Direct Connect, and per-partner
configurations including inbound trust acceptance (MFA, compliant device,
hybrid join).
"""
from __future__ import annotations

import time
from typing import Any, Callable, Optional

from ..graph import GraphClient, GraphError
from .base import Collector, CollectorResult, _classify_graph_error


class CrossTenantAccessCollector(Collector):
    name = "cross_tenant_access"
    description = (
        "Microsoft Entra cross-tenant access policy: default and partner-scoped B2B "
        "Collaboration / B2B Direct Connect access plus inbound trust acceptance."
    )
    required_permissions = [
        "Policy.Read.All",
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client: GraphClient | None = context.get("client")
        log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = context.get("audit_logger")
        coverage: list[dict[str, Any]] = []
        payload: dict[str, Any] = {
            "crossTenantAccessPolicy": {"value": []},
            "defaultPolicy": {"value": []},
            "partnerConfigurations": {"value": []},
        }

        root, root_status = self._fetch_json(client, "/policies/crossTenantAccessPolicy")
        coverage.append(self._coverage_row("crossTenantAccessPolicy", "/policies/crossTenantAccessPolicy", root_status, 1 if root else 0))
        if log_event:
            self._log(log_event, "crossTenantAccessPolicy", root_status, 1 if root else 0)
        if root:
            payload["crossTenantAccessPolicy"] = {"value": [root]}

        default_raw, default_status = self._fetch_json(client, "/policies/crossTenantAccessPolicy/default")
        coverage.append(self._coverage_row("default", "/policies/crossTenantAccessPolicy/default", default_status, 1 if default_raw else 0))
        if log_event:
            self._log(log_event, "default", default_status, 1 if default_raw else 0)
        if default_raw:
            payload["defaultPolicy"] = {"value": [_normalize_default_policy(default_raw)]}

        partners_raw, partners_status = self._fetch_collection(client, "/policies/crossTenantAccessPolicy/partners")
        coverage.append(self._coverage_row("partners", "/policies/crossTenantAccessPolicy/partners", partners_status, len(partners_raw)))
        if log_event:
            self._log(log_event, "partners", partners_status, len(partners_raw))
        partners_normalized = [_normalize_partner_configuration(item) for item in partners_raw]
        payload["partnerConfigurations"] = {"value": partners_normalized}

        partial = any(row.get("status") != "ok" for row in coverage)
        return CollectorResult(
            name=self.name,
            status="partial" if partial else "ok",
            payload=payload,
            item_count=sum(int(row.get("item_count") or 0) for row in coverage),
            message="Cross-tenant access collection partially completed" if partial else "",
            coverage=coverage,
        )

    @staticmethod
    def _fetch_json(
        client: GraphClient | None, path: str
    ) -> tuple[dict[str, Any] | None, dict[str, Any]]:
        start = time.perf_counter()
        status: dict[str, Any] = {"status": "ok", "duration_ms": 0.0, "error_class": None, "error": None}
        try:
            if client is None or not hasattr(client, "get_json"):
                raise GraphError("graph client unavailable", request=path)
            response = client.get_json(path)
        except Exception as exc:  # noqa: BLE001
            status["status"] = "failed"
            status["duration_ms"] = round((time.perf_counter() - start) * 1000, 2)
            status["error_class"], status["error"] = _classify_graph_error(exc)
            return None, status
        status["duration_ms"] = round((time.perf_counter() - start) * 1000, 2)
        if isinstance(response, dict):
            return response, status
        return None, status

    @staticmethod
    def _fetch_collection(
        client: GraphClient | None, path: str
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        start = time.perf_counter()
        status: dict[str, Any] = {"status": "ok", "duration_ms": 0.0, "error_class": None, "error": None}
        items: list[dict[str, Any]] = []
        try:
            if client is None or not hasattr(client, "get_all"):
                raise GraphError("graph client unavailable", request=path)
            raw = client.get_all(path)
            if isinstance(raw, list):
                items = [item for item in raw if isinstance(item, dict)]
            elif isinstance(raw, dict):
                values = raw.get("value")
                if isinstance(values, list):
                    items = [item for item in values if isinstance(item, dict)]
        except Exception as exc:  # noqa: BLE001
            status["status"] = "failed"
            status["error_class"], status["error"] = _classify_graph_error(exc)
        status["duration_ms"] = round((time.perf_counter() - start) * 1000, 2)
        return items, status

    def _coverage_row(self, name: str, endpoint: str, status: dict[str, Any], item_count: int) -> dict[str, Any]:
        return {
            "collector": self.name,
            "type": "graph",
            "name": name,
            "endpoint": endpoint,
            "status": status["status"],
            "item_count": item_count,
            "duration_ms": status["duration_ms"],
            "error_class": status["error_class"],
            "error": status["error"],
        }

    def _log(self, log_event: Callable[[str, str, Optional[dict[str, Any]]], None], name: str, status: dict[str, Any], item_count: int) -> None:
        log_event(
            "collector.endpoint.finished",
            "Collector endpoint request completed",
            {
                "collector": self.name,
                "endpoint_name": name,
                "status": status["status"],
                "item_count": item_count,
                "duration_ms": status["duration_ms"],
                "error_class": status["error_class"],
            },
        )


def _access_type(section: dict[str, Any] | None, key: str) -> Any:
    if not isinstance(section, dict):
        return None
    inner = section.get(key)
    if not isinstance(inner, dict):
        return None
    return inner.get("accessType")


def _normalize_default_policy(payload: dict[str, Any]) -> dict[str, Any]:
    inbound_trust = payload.get("inboundTrust") or {}
    auto_consent = payload.get("automaticUserConsentSettings") or {}
    return {
        "id": "default",
        "is_service_default": bool(payload.get("isServiceDefault")),
        "b2b_collaboration_outbound_access": _access_type(payload.get("b2bCollaborationOutbound"), "applications"),
        "b2b_collaboration_inbound_access": _access_type(payload.get("b2bCollaborationInbound"), "applications"),
        "b2b_direct_connect_outbound_access": _access_type(payload.get("b2bDirectConnectOutbound"), "applications"),
        "b2b_direct_connect_inbound_access": _access_type(payload.get("b2bDirectConnectInbound"), "applications"),
        "inbound_trust_mfa_accepted": bool(inbound_trust.get("isMfaAccepted")),
        "inbound_trust_compliant_device_accepted": bool(inbound_trust.get("isCompliantDeviceAccepted")),
        "inbound_trust_hybrid_aad_joined_accepted": bool(inbound_trust.get("isHybridAzureADJoinedDeviceAccepted")),
        "automatic_user_consent_inbound_allowed": bool(auto_consent.get("inboundAllowed")),
        "automatic_user_consent_outbound_allowed": bool(auto_consent.get("outboundAllowed")),
    }


def _normalize_partner_configuration(payload: dict[str, Any]) -> dict[str, Any]:
    inbound_trust = payload.get("inboundTrust") or {}
    return {
        "id": str(payload.get("tenantId") or ""),
        "tenant_id": payload.get("tenantId"),
        "is_service_provider": bool(payload.get("isServiceProvider")),
        "b2b_collaboration_outbound_access": _access_type(payload.get("b2bCollaborationOutbound"), "applications"),
        "b2b_collaboration_inbound_access": _access_type(payload.get("b2bCollaborationInbound"), "applications"),
        "b2b_direct_connect_outbound_access": _access_type(payload.get("b2bDirectConnectOutbound"), "applications"),
        "b2b_direct_connect_inbound_access": _access_type(payload.get("b2bDirectConnectInbound"), "applications"),
        "inbound_trust_mfa_accepted": bool(inbound_trust.get("isMfaAccepted")),
        "inbound_trust_compliant_device_accepted": bool(inbound_trust.get("isCompliantDeviceAccepted")),
        "inbound_trust_hybrid_aad_joined_accepted": bool(inbound_trust.get("isHybridAzureADJoinedDeviceAccepted")),
    }
