from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


class GoogleWorkspaceError(RuntimeError):
    def __init__(self, message: str, *, surface: str | None = None) -> None:
        super().__init__(message)
        self.surface = surface


def classify_google_error(exc: Exception) -> tuple[str, str]:
    status = getattr(getattr(exc, "resp", None), "status", None) or getattr(exc, "status_code", None)
    message = str(exc)
    if "unauthorized_client" in message or "invalid_scope" in message or "not authorized for any of the scopes" in message:
        return "insufficient_permissions", message
    if status in {401, 403}:
        return "insufficient_permissions" if status == 403 else "unauthenticated", message
    if status == 404:
        return "resource_not_found", message
    if status == 429:
        return "rate_limited", message
    if isinstance(status, int) and status >= 500:
        return "google_transient", message
    return "client_error", message


@dataclass
class GoogleWorkspaceClient:
    credentials: Any
    customer_id: str | None = None
    domain: str | None = None
    page_size: int = 100
    _services: dict[tuple[str, str], Any] | None = None

    def __post_init__(self) -> None:
        if self._services is None:
            self._services = {}

    @property
    def customer(self) -> str:
        return self.customer_id or "my_customer"

    def _service(self, api: str, version: str) -> Any:
        key = (api, version)
        assert self._services is not None
        if key not in self._services:
            from googleapiclient.discovery import build

            self._services[key] = build(api, version, credentials=self.credentials, cache_discovery=False)
        return self._services[key]

    def _collect_pages(
        self,
        request_factory: Callable[[str | None], Any],
        item_key: str,
        *,
        limit: int | None,
    ) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        token: str | None = None
        while True:
            payload = request_factory(token).execute()
            values = payload.get(item_key) or payload.get("items") or payload.get("value") or []
            if isinstance(values, list):
                rows.extend(item for item in values if isinstance(item, dict))
            if limit is not None and len(rows) >= limit:
                return rows[:limit]
            token = payload.get("nextPageToken")
            if not token:
                return rows

    def list_directory(self, resource: str, *, top: int | None = None, domain: str | None = None) -> list[dict[str, Any]]:
        service = self._service("admin", "directory_v1")
        page_size = min(self.page_size, top or self.page_size)
        if resource == "users":
            def request(page_token: str | None) -> Any:
                kwargs = {"customer": self.customer, "maxResults": page_size, "pageToken": page_token, "orderBy": "email"}
                effective_domain = domain or self.domain
                if effective_domain:
                    kwargs["domain"] = effective_domain
                    kwargs.pop("customer", None)
                return service.users().list(**kwargs)

            return self._collect_pages(request, "users", limit=top)
        if resource == "groups":
            def request(page_token: str | None) -> Any:
                kwargs = {"customer": self.customer, "maxResults": page_size, "pageToken": page_token}
                effective_domain = domain or self.domain
                if effective_domain:
                    kwargs["domain"] = effective_domain
                    kwargs.pop("customer", None)
                return service.groups().list(**kwargs)

            return self._collect_pages(request, "groups", limit=top)
        if resource == "orgUnits":
            payload = service.orgunits().list(customerId=self.customer, type="all").execute()
            values = payload.get("organizationUnits") or []
            return [item for item in values if isinstance(item, dict)][: top or None]
        if resource == "domains":
            payload = service.domains().list(customer=self.customer).execute()
            values = payload.get("domains") or []
            return [item for item in values if isinstance(item, dict)][: top or None]
        if resource == "roles":
            return self._collect_pages(
                lambda page_token: service.roles().list(customer=self.customer, maxResults=page_size, pageToken=page_token),
                "items",
                limit=top,
            )
        if resource == "roleAssignments":
            return self._collect_pages(
                lambda page_token: service.roleAssignments().list(
                    customer=self.customer,
                    maxResults=page_size,
                    pageToken=page_token,
                ),
                "items",
                limit=top,
            )
        raise GoogleWorkspaceError(f"unsupported directory resource: {resource}", surface=resource)

    def list_group_members(self, group_email: str, *, top: int | None = None) -> list[dict[str, Any]]:
        service = self._service("admin", "directory_v1")
        page_size = min(self.page_size, top or self.page_size)
        return self._collect_pages(
            lambda page_token: service.members().list(groupKey=group_email, maxResults=page_size, pageToken=page_token),
            "members",
            limit=top,
        )

    def list_user_aliases(self, user_key: str, *, top: int | None = None) -> list[dict[str, Any]]:
        service = self._service("admin", "directory_v1")
        payload = service.users().aliases().list(userKey=user_key).execute()
        values = payload.get("aliases") or []
        return [item for item in values if isinstance(item, dict)][: top or None]

    def list_user_tokens(self, user_key: str, *, top: int | None = None) -> list[dict[str, Any]]:
        service = self._service("admin", "directory_v1")
        payload = service.tokens().list(userKey=user_key).execute()
        values = payload.get("items") or []
        return [item for item in values if isinstance(item, dict)][: top or None]

    def list_report_activities(
        self,
        application_name: str,
        *,
        top: int | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
    ) -> list[dict[str, Any]]:
        service = self._service("admin", "reports_v1")
        page_size = min(self.page_size, top or self.page_size)

        def request(page_token: str | None) -> Any:
            kwargs = {
                "userKey": "all",
                "applicationName": application_name,
                "maxResults": page_size,
                "pageToken": page_token,
            }
            if start_time:
                kwargs["startTime"] = start_time
            if end_time:
                kwargs["endTime"] = end_time
            return service.activities().list(**kwargs)

        return self._collect_pages(request, "items", limit=top)

    def list_alerts(self, *, top: int | None = None) -> list[dict[str, Any]]:
        service = self._service("alertcenter", "v1beta1")
        page_size = min(self.page_size, top or self.page_size)
        return self._collect_pages(
            lambda page_token: service.alerts().list(pageSize=page_size, pageToken=page_token),
            "alerts",
            limit=top,
        )

    def get_gmail_settings_for_user(self, user_email: str) -> dict[str, Any]:
        service = self._service("gmail", "v1")
        settings = service.users().settings()
        payload: dict[str, Any] = {"userEmail": user_email}
        payload["autoForwarding"] = settings.getAutoForwarding(userId=user_email).execute()
        payload["filters"] = settings.filters().list(userId=user_email).execute().get("filter", [])
        payload["forwardingAddresses"] = (
            settings.forwardingAddresses().list(userId=user_email).execute().get("forwardingAddresses", [])
        )
        payload["sendAs"] = settings.sendAs().list(userId=user_email).execute().get("sendAs", [])
        payload["imap"] = settings.getImap(userId=user_email).execute()
        payload["pop"] = settings.getPop(userId=user_email).execute()
        payload["vacation"] = settings.getVacation(userId=user_email).execute()
        try:
            payload["delegates"] = settings.delegates().list(userId=user_email).execute().get("delegates", [])
        except Exception as exc:  # noqa: BLE001
            error_class, error = classify_google_error(exc)
            payload["delegates_error"] = {"error_class": error_class, "error": error}
        return payload

    def list_drive_files(self, *, top: int | None = None) -> list[dict[str, Any]]:
        service = self._service("drive", "v3")
        page_size = min(self.page_size, top or self.page_size)
        fields = (
            "nextPageToken,files("
            "id,name,mimeType,owners(emailAddress,displayName),webViewLink,shared,"
            "permissions(id,type,role,emailAddress,domain,allowFileDiscovery,deleted),modifiedTime)"
        )
        return self._collect_pages(
            lambda page_token: service.files().list(
                pageSize=page_size,
                pageToken=page_token,
                q="trashed=false",
                includeItemsFromAllDrives=True,
                supportsAllDrives=True,
                fields=fields,
            ),
            "files",
            limit=top,
        )

    def list_shared_drives(self, *, top: int | None = None) -> list[dict[str, Any]]:
        service = self._service("drive", "v3")
        page_size = min(self.page_size, top or self.page_size)
        return self._collect_pages(
            lambda page_token: service.drives().list(
                pageSize=page_size,
                pageToken=page_token,
                fields="nextPageToken,drives(id,name,hidden,createdTime,restrictions)",
            ),
            "drives",
            limit=top,
        )

    def get_group_settings(self, group_email: str) -> dict[str, Any]:
        service = self._service("groupssettings", "v1")
        return service.groups().get(groupUniqueId=group_email).execute()

    def list_calendar_resources(self, *, top: int | None = None) -> list[dict[str, Any]]:
        service = self._service("admin", "directory_v1")
        page_size = min(self.page_size, top or self.page_size)
        return self._collect_pages(
            lambda page_token: service.resources().calendars().list(
                customer=self.customer,
                maxResults=page_size,
                pageToken=page_token,
            ),
            "items",
            limit=top,
        )

    def list_calendar_list(self, *, top: int | None = None) -> list[dict[str, Any]]:
        service = self._service("calendar", "v3")
        page_size = min(self.page_size, top or self.page_size)
        return self._collect_pages(
            lambda page_token: service.calendarList().list(maxResults=page_size, pageToken=page_token),
            "items",
            limit=top,
        )

    def list_calendar_acl(self, calendar_id: str, *, top: int | None = None) -> list[dict[str, Any]]:
        service = self._service("calendar", "v3")
        page_size = min(self.page_size, top or self.page_size)
        return self._collect_pages(
            lambda page_token: service.acl().list(calendarId=calendar_id, maxResults=page_size, pageToken=page_token),
            "items",
            limit=top,
        )

    def list_devices(self, resource: str, *, top: int | None = None) -> list[dict[str, Any]]:
        service = self._service("admin", "directory_v1")
        page_size = min(self.page_size, top or self.page_size)
        if resource == "mobile":
            return self._collect_pages(
                lambda page_token: service.mobiledevices().list(
                    customerId=self.customer,
                    maxResults=page_size,
                    pageToken=page_token,
                ),
                "mobiledevices",
                limit=top,
            )
        if resource == "chromeos":
            return self._collect_pages(
                lambda page_token: service.chromeosdevices().list(
                    customerId=self.customer,
                    maxResults=page_size,
                    pageToken=page_token,
                ),
                "chromeosdevices",
                limit=top,
            )
        raise GoogleWorkspaceError(f"unsupported device resource: {resource}", surface=resource)
