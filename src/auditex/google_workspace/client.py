from __future__ import annotations

import json
import re
import time
from collections import Counter, OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from azure_tenant_audit.data_minimisation import minimise_gmail_settings

from .auth import GMAIL_SETTINGS_SCOPES, POLICIES_SCOPE, user_delegated_credentials

# Per-user services kept at once. The Gmail collector reads one user at a time, so a few are enough;
# the bound keeps a 10,000-user run from holding 10,000 discovery clients.
SUBJECT_SERVICE_CACHE_SIZE = 8

# Cloud Identity Policy API filter: an allow-list of the setting-type service prefixes the SCuBA Google Workspace
# baselines read, plus the one system rule type they read. It is a CEL string, and CEL needs the
# regex escape written as two backslashes (the API's own examples read ``gmail\\..*``), so this raw string holds
# two backslashes before every dot. ``settings/rule.dlp`` is never requested: DLP rule bodies can hold sensitive
# patterns, so ``rule`` is not a prefix and only ``rule.system_defined_alerts`` is named in full. Every
# ``security.two_step_verification_*`` policy matches, so the 2-step verification read is a subset of this one.
_POLICY_SETTINGS_FILTER = (
    r"setting.type.matches('^settings/((gmail|security|drive_and_docs|calendar|chat|meet|classroom|"
    r"groups_for_business|sites|takeout|blogger_user_takeout|books_user_takeout|location_history_user_takeout|"
    r"maps_user_takeout|pay_user_takeout|photos_user_takeout|play_user_takeout|play_console_user_takeout|"
    r"youtube_user_takeout|data_regions|workspace_marketplace|api_controls|provisioning|multi_party_approval|"
    r"enterprise_service_restrictions|early_access_apps|gemini_app|access_approval|access_management)\\..*|"
    r"rule\\.system_defined_alerts)$')"
)

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


# Users: only the fields the audit reads. Recovery e-mail and phone, phones, addresses and notes are never received.
_USER_FIELDS = (
    "nextPageToken,users("
    "id,primaryEmail,name/fullName,isAdmin,isDelegatedAdmin,suspended,archived,"
    "isEnrolledIn2Sv,isEnforcedIn2Sv,lastLoginTime,creationTime,orgUnitPath)"
)


_DRIVE_PERMISSION_FIELDS = "id,type,role,emailAddress,domain,allowFileDiscovery,deleted"


# Gmail settings `fields` masks: only what normalize.py and findings.py read; no vacation text, signature or filter text.
GMAIL_VACATION_FIELDS = "enableAutoReply,restrictToContacts,restrictToDomain,startTime,endTime"
GMAIL_SEND_AS_FIELDS = (
    "sendAs(sendAsEmail,displayName,replyToAddress,isPrimary,isDefault,treatAsAlias,smtpMsa,verificationStatus)"
)
GMAIL_FILTERS_FIELDS = (
    "filter(id,action(forward,addLabelIds,removeLabelIds),criteria(from,to,hasAttachment,excludeChats,size,sizeComparison))"
)


# Field masks: the payload `data` (message snippets, subjects) and the free-text group settings are never received.
ALERT_FIELDS = "nextPageToken,alerts(alertId,type,source,createTime,startTime,endTime,deleted,customerId,metadata)"
GROUP_SETTING_FIELDS = (
    "email,allowExternalMembers,whoCanJoin,whoCanPostMessage,messageModerationLevel,"
    "whoCanViewMembership,whoCanViewGroup"
)


# The settings each mailbox read makes; a failed one is kept in the payload as ``<name>_error``.
GMAIL_SETTING_NAMES: tuple[str, ...] = (
    "autoForwarding", "filters", "forwardingAddresses", "sendAs", "imap", "pop", "vacation", "delegates",
)


def gmail_settings_status(payload: dict[str, Any]) -> tuple[str, str | None, str | None]:
    """Status, dominant error class and error of one mailbox's settings read.

    Every settings read failing is ``failed``; some failing is ``partial``; none failing is ``ok``.
    """
    skipped = set(payload.get("skippedSettings") or ())
    attempted = [name for name in GMAIL_SETTING_NAMES if name not in skipped]
    failures = {
        name: error
        for name in attempted
        if isinstance(error := payload.get(f"{name}_error"), dict) and error
    }
    if not failures:
        if skipped:
            # A setting these credentials cannot read (delegates under OAuth) is a gap, never a complete read.
            names = ", ".join(sorted(skipped))
            return "partial", "subject_scope", f"Gmail settings not read with these credentials: {names}."
        return "ok", None, None
    classes = Counter(str(error.get("error_class") or "client_error") for error in failures.values())
    error_class = classes.most_common(1)[0][0]
    example = next(
        (str(error.get("error") or "") for error in failures.values() if str(error.get("error_class") or "client_error") == error_class),
        "",
    )
    status = "failed" if len(failures) == len(attempted) else "partial"
    error = f"{len(failures)} of {len(attempted)} Gmail settings reads failed ({', '.join(sorted(failures))})"
    return status, error_class, f"{error}: {example}" if example else error


def classify_page_error(exc: Exception) -> tuple[str, str]:
    """Class and a fixed description of a later page that failed after its retries.

    The library's text names the request URL, whose query carries the customer and the opaque page cursor, so it is
    never copied: only the HTTP status (when there is one) is kept.
    """
    error_class, _message = classify_google_error(exc)
    status = getattr(getattr(exc, "resp", None), "status", None) or getattr(exc, "status_code", None)
    detail = f"HTTP {status}" if isinstance(status, int) else error_class
    return error_class, f"A later page failed after its retries ({detail}); the rows read before it are kept."


class GoogleWorkspaceError(RuntimeError):
    def __init__(self, message: str, *, surface: str | None = None) -> None:
        super().__init__(message)
        self.surface = surface


# Structured reasons on an HTTP 403 that mean a per-user or per-project rate limit, not a refusal: they are retried.
# Daily quota (``quotaExceeded``, ``dailyLimitExceeded``) is left out, since waiting seconds cannot clear it.
_RATE_LIMIT_403_REASONS = frozenset({"rateLimitExceeded", "userRateLimitExceeded", "RATE_LIMIT_EXCEEDED"})


def _error_reasons(exc: Exception) -> set[str]:
    """The structured ``reason`` values of a Google API error (``errors[]`` and ``details[]`` of its JSON body)."""
    entries: list[Any] = []
    details = getattr(exc, "error_details", None)
    if isinstance(details, list):
        entries.extend(details)
    content = getattr(exc, "content", None)
    if isinstance(content, (bytes, str)):
        try:
            body = json.loads(content)
        except (ValueError, TypeError):
            body = None
        error = body.get("error") if isinstance(body, dict) else None
        if isinstance(error, dict):
            for key in ("errors", "details"):
                if isinstance(error.get(key), list):
                    entries.extend(error[key])
    return {str(entry["reason"]) for entry in entries if isinstance(entry, dict) and entry.get("reason")}


def classify_google_error(exc: Exception) -> tuple[str, str]:
    status = getattr(getattr(exc, "resp", None), "status", None) or getattr(exc, "status_code", None)
    message = str(exc)
    if isinstance(exc, OSError) and (exc.filename or exc.filename2):
        # A local file failure can come from the discovery library as well as from sign-in.
        filename = re.split(r"[\\/]", str(exc.filename or exc.filename2))[-1]
        message = f"{exc.strerror or type(exc).__name__}: {filename}"
    if is_token_refusal(message):
        return "insufficient_permissions", message
    if status == 403 and _error_reasons(exc) & _RATE_LIMIT_403_REASONS:
        return "rate_limited", message
    if status in {401, 403}:
        return "insufficient_permissions" if status == 403 else "unauthenticated", message
    if status == 404:
        return "resource_not_found", message
    if status == 429:
        return "rate_limited", message
    if isinstance(status, int) and status >= 500:
        return "google_transient", message
    return "client_error", message


# Token-exchange refusals: domain-wide delegation was not granted one of the scopes the token asked for.
_TOKEN_REFUSAL_MARKERS = ("unauthorized_client", "invalid_scope", "not authorized for any of the scopes")
# The token endpoint's ``access_denied`` error, as google-auth words a refused exchange ("access_denied: <description>",
# alone or as the first item of the RefreshError's arguments). An API answer never starts this way.
_TOKEN_ACCESS_DENIED = re.compile(r"^\(?['\"]?access_denied:")


def is_token_refusal(error: str | None) -> bool:
    """Whether an error text is a refused token exchange (a scope missing from the delegation), not an API answer."""
    text = str(error or "")
    return any(marker in text for marker in _TOKEN_REFUSAL_MARKERS) or bool(_TOKEN_ACCESS_DENIED.match(text))


def _token_request() -> Any:
    from google.auth.transport.requests import Request

    return Request()


# Waits before each retry of a rate-limited (429) or transient (5xx, dropped connection) read; then the error stands.
RETRY_DELAYS: tuple[float, ...] = (1.0, 2.0, 4.0)
_RETRYABLE_ERROR_CLASSES = frozenset({"rate_limited", "google_transient"})
_sleep = time.sleep


def _retryable(exc: Exception) -> bool:
    if isinstance(exc, (TimeoutError, ConnectionError)):
        return True
    return classify_google_error(exc)[0] in _RETRYABLE_ERROR_CLASSES


def _execute(call: Callable[[], Any]) -> Any:
    """Run one API call, retrying 429 and 5xx answers with backoff; other errors are raised at once."""
    for delay in (*RETRY_DELAYS, None):
        try:
            return call()
        except Exception as exc:
            if delay is None or not _retryable(exc):
                raise
            _sleep(delay)
    raise AssertionError("unreachable")  # pragma: no cover


class CollectedRows(list):
    """Rows of one Google list, plus whether the list continued past the operator's limit.

    A plain ``list`` is what a caller that does not know about limits returns; the collectors
    read ``truncated`` with ``getattr`` so both work. ``page_error`` is the error of a later page that
    could not be read even after retries: the rows before it are kept and the list is cut short.
    """

    truncated: bool = False
    result_limit: int | None = None
    page_error: Exception | None = None
    # Drive only: files whose permissions files.list left out and that were read one by one (see list_drive_files).
    permission_reads: int = 0
    permission_errors: list[dict[str, Any]] | None = None

    def __init__(
        self,
        rows: Any = (),
        *,
        truncated: bool = False,
        result_limit: int | None = None,
        page_error: Exception | None = None,
    ) -> None:
        super().__init__(rows)
        self.truncated = truncated
        self.result_limit = result_limit
        self.page_error = page_error


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

    def for_scopes(self, scopes: tuple[str, ...] | list[str] | None) -> GoogleWorkspaceClient:
        """A client whose calls use a token narrowed to ``scopes`` (one collector's).

        Under domain-wide delegation one scope the tenant has not authorised fails every call on the token that
        asks for it, so each collector asks only for its own: a missing scope then fails only that collector.
        Credentials that cannot be narrowed (an OAuth sign-in, which granted every scope at once) are shared as is.
        """
        wanted = tuple(scopes or ())
        if not wanted or getattr(self.credentials, "with_scopes", None) is None:
            return self
        credentials = self._scoped_credentials(wanted)
        if credentials is self.credentials:
            return self
        return replace(self, credentials=credentials, _services=None, _subject_services=None)

    def _scoped_credentials(self, scopes: tuple[str, ...]) -> Any:
        """Credentials narrowed to ``scopes``, so a scope the tenant has not authorised fails only its own calls."""
        with_scopes = getattr(self.credentials, "with_scopes", None)
        if with_scopes is None:
            return self.credentials
        try:
            return with_scopes(list(scopes))
        except Exception:  # noqa: BLE001 - fall back to the shared token rather than skip the read
            return self.credentials

    def unauthorised_scopes(self, scopes: tuple[str, ...] | list[str]) -> list[str] | None:
        """The scopes in ``scopes`` the domain-wide delegation does not grant, found by one token exchange per scope.

        A refused token says only that some scope was not authorised; asking for each scope alone names the ones
        actually missing. ``None`` when that cannot be told (credentials that cannot be narrowed, or an exchange
        that failed for another reason).
        """
        if getattr(self.credentials, "with_scopes", None) is None:
            return None
        missing: list[str] = []
        for scope in scopes:
            narrowed = self._scoped_credentials((scope,))
            if narrowed is self.credentials:
                return None
            try:
                narrowed.refresh(_token_request())
            except Exception as exc:  # noqa: BLE001
                if not is_token_refusal(str(exc)):
                    return None
                missing.append(scope)
        return missing

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
        first_page = True
        while True:
            try:
                payload = _execute(lambda token=token: request_factory(token).execute())
            except Exception as exc:
                if first_page:
                    raise
                # A later page failed after its retries: keep what was read, recorded as a list cut short.
                kept = rows[:limit] if limit is not None else rows
                return CollectedRows(kept, truncated=True, result_limit=limit, page_error=exc)
            first_page = False
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
                    customer=self.customer, maxResults=page_size, pageToken=page_token, orderBy="email",
                    fields=_USER_FIELDS,
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
            payload = _execute(lambda: service.orgunits().list(customerId=self.customer, type="all").execute())
            return _cut(payload.get("organizationUnits") or [], top)
        if resource == "domains":
            payload = _execute(lambda: service.domains().list(customer=self.customer).execute())
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
        payload = _execute(lambda: service.users().aliases().list(userKey=user_key).execute())
        return _cut(payload.get("aliases") or [], top)

    def list_user_tokens(self, user_key: str, *, top: int | None = None) -> list[dict[str, Any]]:
        service = self._service("admin", "directory_v1")
        payload = _execute(lambda: service.tokens().list(userKey=user_key).execute())
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
        rows = self._collect_pages(
            lambda page_token: service.alerts().list(pageSize=page_size, pageToken=page_token, fields=ALERT_FIELDS),
            "alerts",
            limit=top,
        )
        # A deleted alert is not an open incident; it never reaches the findings as one.
        kept = [alert for alert in rows if alert.get("deleted") is not True]
        if len(kept) == len(rows):
            return rows
        return CollectedRows(
            kept,
            truncated=getattr(rows, "truncated", False),
            result_limit=getattr(rows, "result_limit", None),
            page_error=getattr(rows, "page_error", None),
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
        # Request-level masks (DEC-012): owner-written text is never requested, so it never reaches the collector.

        def _capture(name: str, getter: Callable[[], Any], *, list_key: str | None = None, default: Any = None) -> None:
            try:
                value = _execute(getter)
                if list_key is not None and isinstance(value, dict):
                    payload[name] = value.get(list_key, default if default is not None else [])
                else:
                    payload[name] = value
            except Exception as exc:  # noqa: BLE001
                error_class, error = classify_google_error(exc)
                payload[f"{name}_error"] = {"error_class": error_class, "error": error}

        _capture("autoForwarding", lambda: settings.getAutoForwarding(userId=user_email).execute(), default={})
        _capture("filters", lambda: settings.filters().list(userId=user_email, fields=GMAIL_FILTERS_FIELDS).execute(), list_key="filter", default=[])
        _capture(
            "forwardingAddresses",
            lambda: settings.forwardingAddresses().list(userId=user_email).execute(),
            list_key="forwardingAddresses",
            default=[],
        )
        _capture("sendAs", lambda: settings.sendAs().list(userId=user_email, fields=GMAIL_SEND_AS_FIELDS).execute(), list_key="sendAs", default=[])
        _capture("imap", lambda: settings.getImap(userId=user_email).execute(), default={})
        _capture("pop", lambda: settings.getPop(userId=user_email).execute(), default={})
        _capture("vacation", lambda: settings.getVacation(userId=user_email, fields=GMAIL_VACATION_FIELDS).execute(), default={})
        if self.per_user_delegation:
            _capture("delegates", lambda: settings.delegates().list(userId=user_email).execute(), list_key="delegates", default=[])
        else:
            # delegates.list answers only a service account with domain-wide delegation; an OAuth sign-in is always
            # refused, which is not a missing scope. It is recorded as not read, never as a failed read.
            payload["skippedSettings"] = ["delegates"]
            payload["delegates_error"] = {
                "error_class": "subject_scope",
                "error": "Gmail delegates can be listed only under domain-wide delegation; they were not read.",
            }
        return minimise_gmail_settings(payload)

    def list_drive_files(self, *, top: int | None = None) -> list[dict[str, Any]]:
        """Drive files with their sharing.

        files.list does not return ``permissions`` for items in shared drives, nor for files the subject cannot
        share. Each file it left them out of has them read with permissions.list, so its sharing is never read as
        none; a file whose permissions cannot be read either is listed in ``permission_errors``.
        """
        service = self._service("drive", "v3")
        page_size = min(self.page_size, top or self.page_size)
        fields = (
            "nextPageToken,files("
            "id,name,mimeType,owners(emailAddress,displayName),webViewLink,shared,driveId,permissionIds,"
            f"permissions({_DRIVE_PERMISSION_FIELDS}),modifiedTime)"
        )
        files = self._collect_pages(
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
        if not isinstance(files, CollectedRows):
            files = CollectedRows(files)
        errors: list[dict[str, Any]] = []
        for drive_file in files:
            file_id = str(drive_file.get("id") or "")
            if "permissions" in drive_file or not file_id:
                continue
            try:
                permissions = self._collect_pages(
                    lambda page_token, file_id=file_id: service.permissions().list(
                        fileId=file_id,
                        pageSize=100,
                        pageToken=page_token,
                        supportsAllDrives=True,
                        fields=f"nextPageToken,permissions({_DRIVE_PERMISSION_FIELDS})",
                    ),
                    "permissions",
                    limit=None,
                )
                drive_file["permissions"] = permissions
                if permissions.page_error is not None:
                    # Only some pages were read: what is there is kept, but the file's sharing is not complete.
                    raise permissions.page_error
                files.permission_reads += 1
            except Exception as exc:  # noqa: BLE001 - recorded as a coverage gap, never as no sharing
                error_class, error = classify_google_error(exc)
                errors.append({"fileId": file_id, "error_class": error_class, "error": error})
        files.permission_errors = errors
        return files

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
        return _execute(lambda: service.groups().get(groupUniqueId=group_email, fields=GROUP_SETTING_FIELDS).execute())

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
        """Cloud Identity policies for the SCuBA setting types (read-only policies scope).

        One paged read of every allow-listed setting type (``_POLICY_SETTINGS_FILTER``). The operator's ``--top``
        still bounds it; a read cut there or by a later page error comes back marked, and the collector records it
        as incomplete.
        """
        service = self._service("cloudidentity", "v1", scopes=(POLICIES_SCOPE,))
        policies = getattr(service, "policies", None)
        if policies is None:
            raise GoogleWorkspaceError(
                "the installed google-api-python-client has no cloudidentity v1 policies resource; upgrade it",
                surface="policies",
            )
        page_size = min(self.page_size, top or self.page_size, 100)
        policy_filter = f'customer == "customers/{self.customer}" && {_POLICY_SETTINGS_FILTER}'
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
