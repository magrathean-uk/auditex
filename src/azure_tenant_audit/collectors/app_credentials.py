"""Collector for application & service principal credential hygiene.

Captures secrets, certificates, redirect URIs, federated identity credentials,
owner counts, and sign-in audience for each Microsoft Entra application and
service principal. The findings layer flags expiring credentials, insecure
redirects, multi-tenant audience drift, and orphaned ownership.
"""
from __future__ import annotations

import time
from typing import Any, Callable, Optional
from urllib.parse import urlparse

from ..graph import GraphClient, GraphError, graph_api_version, graph_url
from .base import Collector, CollectorResult, _classify_graph_error

# Beta-only report (AuditLog.Read.All). Gated: when it is unavailable the
# dormant-credential rule stays inert (signin_data_available=False).
SERVICE_PRINCIPAL_SIGNIN_ACTIVITY_PATH = "/reports/servicePrincipalSignInActivities"
_SIGNIN_ACTIVITY_KEYS = (
    "lastSignInActivity",
    "delegatedClientSignInActivity",
    "delegatedResourceSignInActivity",
    "applicationAuthenticationClientSignInActivity",
    "applicationAuthenticationResourceSignInActivity",
)


_APPLICATION_SELECT = (
    "id,displayName,appId,createdDateTime,signInAudience,publisherDomain,"
    "passwordCredentials,keyCredentials,web,publicClient,spa,requiredResourceAccess"
)
_SERVICE_PRINCIPAL_SELECT = (
    "id,displayName,appId,servicePrincipalType,publisherName,signInAudience,"
    "passwordCredentials,keyCredentials,replyUrls,accountEnabled,homepage,appOwnerOrganizationId,tags"
)


class AppCredentialsCollector(Collector):
    name = "app_credentials"
    description = (
        "Application and service principal credential hygiene: secret/cert expiry, "
        "redirect URIs, federated identity credentials, owners, and audience drift."
    )
    required_permissions = [
        "Application.Read.All",
        "Directory.Read.All",
        "AuditLog.Read.All",
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client: GraphClient | None = context.get("client")
        log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = context.get("audit_logger")
        coverage: list[dict[str, Any]] = []
        payload: dict[str, Any] = {
            "applicationCredentials": {"value": []},
            "servicePrincipalCredentials": {"value": []},
        }

        applications = self._fetch_collection(
            client,
            "/applications",
            params={"$select": _APPLICATION_SELECT},
            coverage=coverage,
            log_event=log_event,
        )
        service_principals = self._fetch_collection(
            client,
            "/servicePrincipals",
            params={"$select": _SERVICE_PRINCIPAL_SELECT},
            coverage=coverage,
            log_event=log_event,
        )

        signin_coverage_start = len(coverage)
        signin_rows = self._fetch_collection(
            client,
            graph_url(SERVICE_PRINCIPAL_SIGNIN_ACTIVITY_PATH, "beta"),
            params={},
            coverage=coverage,
            log_event=log_event,
            name="servicePrincipalSignInActivities",
        )
        signin_row = coverage[signin_coverage_start] if len(coverage) > signin_coverage_start else {}
        signin_data_available = signin_row.get("status") == "ok"
        if not signin_data_available and signin_row:
            signin_row["capability_gated"] = True
            signin_row["coverage_note"] = (
                "Service principal sign-in activity (Graph beta, AuditLog.Read.All) is unavailable; "
                "dormant-application findings are not evaluated."
            )
        last_signin_by_app = _last_signin_by_app_id(signin_rows) if signin_data_available else {}

        application_records: list[dict[str, Any]] = []
        for app in applications:
            normalized = self._normalize_application(app)
            owner_count, owners = self._fetch_owners(client, "/applications", app.get("id"))
            normalized["owner_count"] = owner_count
            if owners:
                normalized["owners"] = owners
            normalized["federated_credentials"] = self._fetch_federated_credentials(client, app.get("id"))
            normalized["signin_data_available"] = signin_data_available
            if signin_data_available:
                normalized["last_signin_at"] = last_signin_by_app.get(str(app.get("appId") or "").lower())
            application_records.append(normalized)

        service_principal_records: list[dict[str, Any]] = []
        for sp in service_principals:
            normalized = self._normalize_service_principal(sp)
            owner_count, owners = self._fetch_owners(client, "/servicePrincipals", sp.get("id"))
            normalized["owner_count"] = owner_count
            if owners:
                normalized["owners"] = owners
            service_principal_records.append(normalized)

        payload["applicationCredentials"] = {"value": application_records}
        payload["servicePrincipalCredentials"] = {"value": service_principal_records}

        partial = any(row.get("status") != "ok" for row in coverage)
        return CollectorResult(
            name=self.name,
            status="partial" if partial else "ok",
            payload=payload,
            item_count=len(application_records) + len(service_principal_records),
            message="App credential collection partially completed" if partial else "",
            coverage=coverage,
        )

    def _fetch_collection(
        self,
        client: GraphClient | None,
        path: str,
        *,
        params: dict[str, Any],
        coverage: list[dict[str, Any]],
        log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]],
        name: str | None = None,
    ) -> list[dict[str, Any]]:
        endpoint_name = name or path.lstrip("/")
        start = time.perf_counter()
        items: list[dict[str, Any]] = []
        status = "ok"
        error_class: str | None = None
        error: str | None = None
        try:
            if client is None or not hasattr(client, "get_all"):
                raise GraphError("graph client unavailable", request=path)
            raw = client.get_all(path, params=params or None)
            if isinstance(raw, list):
                items = [item for item in raw if isinstance(item, dict)]
            elif isinstance(raw, dict):
                values = raw.get("value")
                if isinstance(values, list):
                    items = [item for item in values if isinstance(item, dict)]
        except Exception as exc:  # noqa: BLE001
            status = "failed"
            error_class, error = _classify_graph_error(exc)
        duration_ms = round((time.perf_counter() - start) * 1000, 2)
        coverage.append(
            {
                "collector": self.name,
                "type": "graph",
                "name": endpoint_name,
                "endpoint": path,
                "api_version": graph_api_version(path),
                "status": status,
                "item_count": len(items),
                "duration_ms": duration_ms,
                "error_class": error_class,
                "error": error,
            }
        )
        if log_event:
            log_event(
                "collector.endpoint.finished",
                "Collector endpoint request completed",
                {
                    "collector": self.name,
                    "endpoint_name": endpoint_name,
                    "status": status,
                    "item_count": len(items),
                    "duration_ms": duration_ms,
                    "error_class": error_class,
                },
            )
        return items

    @staticmethod
    def _fetch_owners(
        client: GraphClient | None, prefix: str, object_id: Any
    ) -> tuple[int | None, list[dict[str, Any]]]:
        """Return the owner count (None when unreadable) and owner ids with types."""
        if client is None or not hasattr(client, "get_json") or not object_id:
            return None, []
        try:
            response = client.get_json(f"{prefix}/{object_id}/owners", params={"$select": "id"})
        except Exception:  # noqa: BLE001
            return None, []
        if isinstance(response, dict):
            value = response.get("value")
            if isinstance(value, list):
                owners = [
                    {"id": str(row.get("id")), "@odata.type": row.get("@odata.type")}
                    for row in value
                    if isinstance(row, dict) and row.get("id")
                ]
                return len(value), owners
        return None, []

    @staticmethod
    def _fetch_federated_credentials(client: GraphClient | None, object_id: Any) -> list[dict[str, Any]]:
        if client is None or not hasattr(client, "get_json") or not object_id:
            return []
        try:
            response = client.get_json(f"/applications/{object_id}/federatedIdentityCredentials")
        except Exception:  # noqa: BLE001
            return []
        if not isinstance(response, dict):
            return []
        rows: list[dict[str, Any]] = []
        for entry in response.get("value", []) or []:
            if not isinstance(entry, dict):
                continue
            rows.append(
                {
                    "id": entry.get("id"),
                    "name": entry.get("name"),
                    "issuer": entry.get("issuer"),
                    "subject": entry.get("subject"),
                    "audiences": entry.get("audiences") or [],
                }
            )
        return rows

    def _normalize_application(self, app: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": app.get("id"),
            "display_name": app.get("displayName"),
            "app_id": app.get("appId"),
            "created_date_time": app.get("createdDateTime"),
            "sign_in_audience": app.get("signInAudience"),
            "publisher_domain": app.get("publisherDomain"),
            "password_credentials": _normalize_credentials(app.get("passwordCredentials")),
            "key_credentials": _normalize_credentials(app.get("keyCredentials")),
            "redirect_uris": _classify_redirect_uris(app),
            "required_resource_access": app.get("requiredResourceAccess") or [],
        }

    def _normalize_service_principal(self, sp: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": sp.get("id"),
            "display_name": sp.get("displayName"),
            "app_id": sp.get("appId"),
            "service_principal_type": sp.get("servicePrincipalType"),
            "publisher_name": sp.get("publisherName"),
            "sign_in_audience": sp.get("signInAudience"),
            "account_enabled": sp.get("accountEnabled"),
            "app_owner_organization_id": sp.get("appOwnerOrganizationId"),
            "tags": sp.get("tags") or [],
            "password_credentials": _normalize_credentials(sp.get("passwordCredentials")),
            "key_credentials": _normalize_credentials(sp.get("keyCredentials")),
            "reply_urls": [
                _classify_redirect_uri(uri) for uri in (sp.get("replyUrls") or []) if isinstance(uri, str)
            ],
        }


def _last_signin_by_app_id(rows: list[dict[str, Any]]) -> dict[str, str]:
    """Map appId (lower-case) to the most recent sign-in timestamp across activity kinds."""
    latest: dict[str, str] = {}
    for row in rows:
        app_id = str(row.get("appId") or "").lower()
        if not app_id:
            continue
        stamps = []
        for key in _SIGNIN_ACTIVITY_KEYS:
            activity = row.get(key)
            if isinstance(activity, dict):
                stamp = activity.get("lastSignInDateTime")
                if isinstance(stamp, str) and stamp:
                    stamps.append(stamp)
        if not stamps:
            continue
        candidate = max(stamps)
        if app_id not in latest or candidate > latest[app_id]:
            latest[app_id] = candidate
    return latest


def _normalize_credentials(credentials: Any) -> list[dict[str, Any]]:
    if not isinstance(credentials, list):
        return []
    rows: list[dict[str, Any]] = []
    for cred in credentials:
        if not isinstance(cred, dict):
            continue
        rows.append(
            {
                "key_id": cred.get("keyId"),
                "display_name": cred.get("displayName"),
                "start_date_time": cred.get("startDateTime"),
                "end_date_time": cred.get("endDateTime"),
                "type": cred.get("type"),
            }
        )
    return rows


def _classify_redirect_uris(app: dict[str, Any]) -> list[dict[str, Any]]:
    uris: list[str] = []
    for section_key in ("web", "spa", "publicClient"):
        section = app.get(section_key)
        if isinstance(section, dict):
            section_uris = section.get("redirectUris")
            if isinstance(section_uris, list):
                uris.extend(uri for uri in section_uris if isinstance(uri, str))
    classified = [_classify_redirect_uri(uri) for uri in uris]
    return classified


def _classify_redirect_uri(uri: str) -> dict[str, Any]:
    parsed = urlparse(uri)
    host = (parsed.hostname or "").lower()
    return {
        "uri": uri,
        "scheme": parsed.scheme.lower(),
        "host": host,
        "is_localhost": host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".localhost"),
        "is_wildcard": "*" in (parsed.netloc or "") or "*" in (parsed.path or ""),
    }
