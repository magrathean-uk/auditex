from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Callable

from azure_tenant_audit.data_minimisation import minimise_gmail_settings

from .auth import GMAIL_SETTINGS_SCOPES, POLICIES_SCOPE, user_delegated_credentials

# Per-user services kept at once. The Gmail collector reads one user at a time, so a few are enough;
# the bound keeps a 10,000-user run from holding 10,000 discovery clients.
SUBJECT_SERVICE_CACHE_SIZE = 8

# Cloud Identity Policy API filter for the 2-step verification settings. It is a CEL string, and CEL needs
# the regex escape written as two backslashes (the API's own examples read ``gmail\\..*``), so this raw
# string holds two backslashes. Every ``security.two_step_verification_*`` policy matches.
_TWO_STEP_POLICY_FILTER = r"setting.type.matches('^settings/security\\.two_step_verification_.*$')"

# Fields read from the device lists. Naming them keeps the telemetry the FULL projection also returns
# (installed apps, recent users, active time ranges, disk and CPU reports) out of the bundle.
_MOBILE_DEVICE_FIELDS = (
    "nextPageToken,mobiledevices("
    "resourceId,deviceId,email,model,os,type,status,lastSync,"
    "deviceCompromisedStatus,encryptionStatus,devicePasswordStatus,securityPatchLevel,releaseVersion)"
)
_CHROMEOS_DEVICE_FIELDS = (
    "nextPageToken,chromeosdevices("
    "deviceId,serialNumber,status,lastSync,annotatedUser,model,osVersion,platformVersion,bootMode,"
    "orgUnitPath,autoUpdateThrough,autoUpdateExpiration,supportEndDate,lastEnrollmentTime)"
)


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


class CollectedRows(list):
    """Rows of one Google list, plus whether the list continued past the operator's limit.

    A plain ``list`` is what a caller that does not know about limits returns; the collectors
    read ``truncated`` with ``getattr`` so both work.
    """

    truncated: bool = False
    result_limit: int | None = None

    def __init__(self, rows: Any = (), *, truncated: bool = False, result_limit: int | None = None) -> None:
        super().__init__(rows)
        self.truncated = truncated
        self.result_limit = result_limit


def _cut(values: list[dict[str, Any]], limit: int | None) -> CollectedRows:
    """Dict rows of a single-call list cut to ``limit``; ``truncated`` says rows were dropped."""
    rows = [item for item in values if isinstance(item, dict)]
    if not limit or len(rows) <= limit:
        return CollectedRows(rows, result_limit=limit or None)
    return CollectedRows(rows[:limit], truncated=True, result_limit=limit)


@dataclass
class GoogleWorkspaceClient:
    """Read-only Google Workspace client.

    ``delegated`` says the credentials are a domain-wide delegation service account, so a user's own
    mailbox settings can be read by acting as that user. Directory lists always use the customer
    (``my_customer`` unless a customer id is given): ``--domain`` is a label, never a filter.
    """

    credentials: Any
    customer_id: str | None = None
    page_size: int = 100
    delegated: bool = False
    _services: dict[tuple[str, str], Any] | None = None
    _subject_services: OrderedDict[tuple[str, str, str], Any] | None = None

    def __post_init__(self) -> None:
        if self._services is None:
            self._services = {}
        if self._subject_services is None:
            self._subject_services = OrderedDict()

    @property
    def customer(self) -> str:
        return self.customer_id or "my_customer"

    @property
    def per_user_delegation(self) -> bool:
        """Whether per-user settings can be read as each user (domain-wide delegation)."""
        return bool(self.delegated) and hasattr(self.credentials, "with_subject")

    def _service(self, api: str, version: str, *, scopes: tuple[str, ...] | None = None) -> Any:
        key = (api, version)
        assert self._services is not None
        if key not in self._services:
            from googleapiclient.discovery import build

            credentials = self._scoped_credentials(scopes) if scopes else self.credentials
            self._services[key] = build(api, version, credentials=credentials, cache_discovery=False)
        return self._services[key]

    def _scoped_credentials(self, scopes: tuple[str, ...]) -> Any:
        """Credentials narrowed to ``scopes``, so a scope the tenant has not authorised fails only its own calls."""
        with_scopes = getattr(self.credentials, "with_scopes", None)
        if with_scopes is None:
            return self.credentials
        try:
            return with_scopes(list(scopes))
        except Exception:  # noqa: BLE001 - fall back to the shared token rather than skip the read
            return self.credentials

    def _subject_service(self, subject: str, api: str, version: str, scopes: tuple[str, ...]) -> Any:
        """A service that acts as ``subject`` with only ``scopes``; the last few are cached, never one per user."""
        cache = self._subject_services
        assert cache is not None
        key = (subject, api, version)
        if key in cache:
            cache.move_to_end(key)
            return cache[key]
        from googleapiclient.discovery import build

        credentials = user_delegated_credentials(self.credentials, subject, scopes=scopes)
        cache[key] = build(api, version, credentials=credentials, cache_discovery=False)
        while len(cache) > SUBJECT_SERVICE_CACHE_SIZE:
            cache.popitem(last=False)
        return cache[key]

    def _collect_pages(
        self,
        request_factory: Callable[[str | None], Any],
        item_key: str,
        *,
        limit: int | None,
    ) -> CollectedRows:
        limit = limit or None
        rows: list[dict[str, Any]] = []
        token: str | None = None
        while True:
            payload = request_factory(token).execute()
            values = payload.get(item_key) or payload.get("items") or payload.get("value") or []
            if isinstance(values, list):
                rows.extend(item for item in values if isinstance(item, dict))
            token = payload.get("nextPageToken")
            if limit is not None and len(rows) >= limit:
                # More rows, or a further page, means the list was cut at the operator's limit.
                return CollectedRows(rows[:limit], truncated=len(rows) > limit or bool(token), result_limit=limit)
            if not token:
                return CollectedRows(rows, result_limit=limit)

    def list_directory(self, resource: str, *, top: int | None = None) -> list[dict[str, Any]]:
        service = self._service("admin", "directory_v1")
        page_size = min(self.page_size, top or self.page_size)
        if resource == "users":
            # customer=my_customer lists every domain of the tenant, secondary and alias domains included.
            return self._collect_pages(
                lambda page_token: service.users().list(
                    customer=self.customer, maxResults=page_size, pageToken=page_token, orderBy="email"
                ),
                "users",
                limit=top,
            )
        if resource == "groups":
            return self._collect_pages(
                lambda page_token: service.groups().list(customer=self.customer, maxResults=page_size, pageToken=page_token),
                "groups",
                limit=top,
            )
        if resource == "orgUnits":
            payload = service.orgunits().list(customerId=self.customer, type="all").execute()
            return _cut(payload.get("organizationUnits") or [], top)
        if resource == "domains":
            payload = service.domains().list(customer=self.customer).execute()
            return _cut(payload.get("domains") or [], top)
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
        return _cut(payload.get("aliases") or [], top)

    def list_user_tokens(self, user_key: str, *, top: int | None = None) -> list[dict[str, Any]]:
        service = self._service("admin", "directory_v1")
        payload = service.tokens().list(userKey=user_key).execute()
        return _cut(payload.get("items") or [], top)

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
        """Settings of one mailbox, read as that user when the credentials are delegated.

        With a single admin subject the settings calls for another user's mailbox are refused, so a
        delegated client acts as each user. Without delegation only ``me`` (the signed-in user) is readable.
        """
        if self.per_user_delegation and user_email != "me":
            service = self._subject_service(user_email, "gmail", "v1", GMAIL_SETTINGS_SCOPES)
        else:
            service = self._service("gmail", "v1")
        settings = service.users().settings()
        payload: dict[str, Any] = {"userEmail": user_email}

        def _capture(name: str, getter: Callable[[], Any], *, list_key: str | None = None, default: Any = None) -> None:
            try:
                value = getter()
                if list_key is not None and isinstance(value, dict):
                    payload[name] = value.get(list_key, default if default is not None else [])
                else:
                    payload[name] = value
            except Exception as exc:  # noqa: BLE001
                error_class, error = classify_google_error(exc)
                payload[f"{name}_error"] = {"error_class": error_class, "error": error}

        _capture("autoForwarding", lambda: settings.getAutoForwarding(userId=user_email).execute(), default={})
        _capture("filters", lambda: settings.filters().list(userId=user_email).execute(), list_key="filter", default=[])
        _capture(
            "forwardingAddresses",
            lambda: settings.forwardingAddresses().list(userId=user_email).execute(),
            list_key="forwardingAddresses",
            default=[],
        )
        _capture("sendAs", lambda: settings.sendAs().list(userId=user_email).execute(), list_key="sendAs", default=[])
        _capture("imap", lambda: settings.getImap(userId=user_email).execute(), default={})
        _capture("pop", lambda: settings.getPop(userId=user_email).execute(), default={})
        _capture("vacation", lambda: settings.getVacation(userId=user_email).execute(), default={})
        _capture("delegates", lambda: settings.delegates().list(userId=user_email).execute(), list_key="delegates", default=[])
        return minimise_gmail_settings(payload)

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

    def list_policies(self, *, top: int | None = None) -> list[dict[str, Any]]:
        """Cloud Identity policies for the 2-step verification settings (read-only policies scope)."""
        service = self._service("cloudidentity", "v1", scopes=(POLICIES_SCOPE,))
        policies = getattr(service, "policies", None)
        if policies is None:
            raise GoogleWorkspaceError(
                "the installed google-api-python-client has no cloudidentity v1 policies resource; upgrade it",
                surface="policies",
            )
        page_size = min(self.page_size, top or self.page_size, 100)
        policy_filter = f'customer == "customers/{self.customer}" && {_TWO_STEP_POLICY_FILTER}'
        return self._collect_pages(
            lambda page_token: policies().list(pageSize=page_size, pageToken=page_token, filter=policy_filter),
            "policies",
            limit=top,
        )

    def list_devices(self, resource: str, *, top: int | None = None) -> list[dict[str, Any]]:
        service = self._service("admin", "directory_v1")
        page_size = min(self.page_size, top or self.page_size)
        # FULL projection carries the posture fields (encryption, password, patch level, auto-update
        # expiration); ``fields`` keeps the response to the ones the audit reads.
        if resource == "mobile":
            return self._collect_pages(
                lambda page_token: service.mobiledevices().list(
                    customerId=self.customer,
                    maxResults=page_size,
                    pageToken=page_token,
                    projection="FULL",
                    fields=_MOBILE_DEVICE_FIELDS,
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
                    projection="FULL",
                    fields=_CHROMEOS_DEVICE_FIELDS,
                ),
                "chromeosdevices",
                limit=top,
            )
        raise GoogleWorkspaceError(f"unsupported device resource: {resource}", surface=resource)
