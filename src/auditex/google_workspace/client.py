from __future__ import annotations

import json
import re
import time
from collections import Counter, OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from azure_tenant_audit.collection_gaps import (
    REASON_PAGINATION_NOT_FOLLOWED,
)
from azure_tenant_audit.data_minimisation import (
    POLICY_TYPE_PATTERN,
    POLICY_UNIT_ID,
    minimise_gmail_settings,
)

from .auth import (
    GMAIL_SETTINGS_SCOPES,
    INBOUND_SSO_SCOPE,
    POLICIES_SCOPE,
    user_delegated_credentials,
)
from .customer_id import learn_response_customer_ids, withhold_request_customer_ids

# Per-user services kept at once. The Gmail collector reads one user at a time, so a few are enough;
# the bound keeps a 10,000-user run from holding 10,000 discovery clients.
SUBJECT_SERVICE_CACHE_SIZE = 8

# Cloud Identity Policy API filter: an allow-list of the setting-type service prefixes the SCuBA Google Workspace
# baselines read, plus the exact Takeout and system alert types they read. It is a CEL string, and CEL needs the
# regex escape written as two backslashes (the API's own examples read ``gmail\\..*``), so the filter sends
# two backslashes before every dot. ``settings/rule.dlp`` is never requested: DLP rule bodies can hold sensitive
# patterns, so ``rule`` is not a prefix and only ``rule.system_defined_alerts`` is named in full. Every
# ``security.two_step_verification_*`` policy matches, so the 2-step verification read is a subset of this one.
_POLICY_SETTINGS_FILTER = "setting.type.matches('" + POLICY_TYPE_PATTERN.replace("\\", "\\\\") + "')"

# The widened policies read takes no operator ``--top``: a SCuBA setting cut off by a row limit would be unknown, and
# the 2-step verification subset used to finish whatever ``--top`` said. This internal cap only stops a runaway read;
# a read cut at it comes back marked as cut at the collector's safety cap, and the collector records it as incomplete.
POLICY_SETTINGS_ROW_CAP = 20_000
SCUBA_EVENT_LIMIT = 20_000
# Union of ScubaGoggles v1.1.0 provider.py EVENTS, excluding the unfiltered "all" request.
SCUBA_ADMIN_EVENTS = (
    "ALLOW_SERVICE_FOR_OAUTH2_ACCESS",
    "BLOCK_ALL_THIRD_PARTY_API_ACCESS",
    "CHANGE_APPLICATION_SETTING",
    "CHANGE_DOCS_SETTING",
    "CHANGE_EMAIL_SETTING",
    "CHANGE_GMAIL_SETTING",
    "CREATE_APPLICATION_SETTING",
    "DELETE_APPLICATION_SETTING",
    "DISALLOW_SERVICE_FOR_OAUTH2_ACCESS",
    "SIGN_IN_ONLY_THIRD_PARTY_API_ACCESS",
    "SYSTEM_DEFINED_RULE_UPDATED",
    "TOGGLE_CAA_ENABLEMENT",
    "TOGGLE_SERVICE_ENABLED",
    "TRUST_DOMAIN_OWNED_OAUTH2_APPS",
    "UNBLOCK_ALL_THIRD_PARTY_API_ACCESS",
    "UNTRUST_DOMAIN_OWNED_OAUTH2_APPS",
)
# Further bounds on the policies read: a read that needs more requests than this or repeats a page cursor is stopped
# there and marked incomplete.
POLICY_PAGE_BUDGET = 1_000
# The longest page cursor accepted; a longer one is a page that cannot be read.
POLICY_CURSOR_MAX = 4_096
# Error class of a policies read whose answer could not be read: a malformed page or no policies at all.
POLICY_MALFORMED_ERROR_CLASS = "malformed_response"


def _policy_error_reasons() -> frozenset[str]:
    """Structured API reasons that may be named in a policies read error. Any other reason text is not copied: a
    reason field is free text as far as this client can tell."""
    # Google's reason words stay values in a call, not a module-level constant, so none becomes a product field
    # name the shareable redaction keeps (``output_redaction._D5_FIELD_NAMES``, DEC-171).
    return frozenset((
        "badRequest",
        "invalid",
        "invalidParameter",
        "required",
        "notFound",
        "forbidden",
        "insufficientPermissions",
        "accessNotConfigured",
        "authError",
        "unauthorized",
        "domainPolicy",
        "failedPrecondition",
        "rateLimitExceeded",
        "userRateLimitExceeded",
        "quotaExceeded",
        "dailyLimitExceeded",
        "backendError",
        "internalError",
        "INVALID_ARGUMENT",
        "FAILED_PRECONDITION",
        "NOT_FOUND",
        "PERMISSION_DENIED",
        "UNAUTHENTICATED",
        "RESOURCE_EXHAUSTED",
        "RATE_LIMIT_EXCEEDED",
        "INTERNAL",
        "UNAVAILABLE",
        "SERVICE_DISABLED",
        "ACCESS_TOKEN_SCOPE_INSUFFICIENT",
        "USER_PROJECT_DENIED",
        "BILLING_DISABLED",
        "CONSUMER_INVALID",
    ))


POLICY_ERROR_REASONS = _policy_error_reasons()

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
    error_class, message = classify_google_error(exc)
    if isinstance(exc, PolicyReadError) and exc.error_class:
        return error_class, message  # a page that could not be read: its own fixed text
    status = getattr(getattr(exc, "resp", None), "status", None) or getattr(exc, "status_code", None)
    detail = f"HTTP {status}" if isinstance(status, int) else error_class
    return error_class, f"A later page failed after its retries ({detail}); the rows read before it are kept."


class PolicyReadError(RuntimeError):
    """A Cloud Identity policies read that failed, with a fixed message.

    The library's error text names the request URL, whose query holds the customer id (and could echo a path or a
    token), so it is never copied. The HTTP status and the structured reasons are kept, so the error class and the
    token-refusal check are those of the original error.
    """

    def __init__(
        self, message: str, *, status_code: int | None = None, reasons: tuple[str, ...] = (), error_class: str | None = None
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_details = [{"reason": reason} for reason in reasons]
        # Set for an answer whose shape could not be read (``malformed_response``); the class then is this one.
        self.error_class = error_class


POLICY_UNREADABLE_ROWS_TEXT = "Some policies returned by the Cloud Identity policies read cannot be read; the settings they hold are unknown."


def policy_malformed_error(*, later_page: bool) -> PolicyReadError:
    """A fixed error for a policies answer that cannot be read: no policies at all, or a page of the wrong shape."""
    text = (
        "A later page of the Cloud Identity policies read could not be read; the rows read before it are kept."
        if later_page
        else "The Cloud Identity policies read returned no readable policies, so no setting could be read."
    )
    return PolicyReadError(text, error_class=POLICY_MALFORMED_ERROR_CLASS)


def policy_read_error(exc: Exception, *, surface: str = "Cloud Identity policies") -> Exception:
    """``exc`` as a :class:`PolicyReadError` with a bounded message (a fixed actionable error is kept as it is)."""
    if isinstance(exc, PolicyReadError) or (surface == "Cloud Identity policies" and isinstance(exc, GoogleWorkspaceError)):
        return exc
    error_class, message = classify_google_error(exc)
    status = getattr(getattr(exc, "resp", None), "status", None) or getattr(exc, "status_code", None)
    status = status if isinstance(status, int) and not isinstance(status, bool) else None
    # Structured reasons are API codes (``badRequest``, ``SERVICE_DISABLED``); anything else is not copied.
    reasons = tuple(sorted(reason for reason in _error_reasons(exc) if reason in POLICY_ERROR_REASONS))
    if is_token_refusal(message):
        text = (
            f"The token exchange for the {surface} scope was refused (unauthorized_client): "
            "the domain-wide delegation does not grant that scope."
        )
    else:
        detail = f"HTTP {status}" if status is not None else error_class
        named = f"; reason {', '.join(reasons)}" if reasons else ""
        text = f"The {surface} read failed ({detail}{named})."
    return PolicyReadError(text, status_code=status, reasons=reasons)


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
    """Class and text of a Google error. The library's text names the request URL, whose path or query holds the
    customer id: it is replaced by a marker, so no coverage row, blocker or log carries it (PRIV-CUSTOMER-ID)."""
    error_class, message = _classify_google_error(exc)
    return error_class, withhold_request_customer_ids(message, getattr(exc, "error_details", None))


def _classify_google_error(exc: Exception) -> tuple[str, str]:
    status = getattr(getattr(exc, "resp", None), "status", None) or getattr(exc, "status_code", None)
    message = str(exc)
    if isinstance(exc, PolicyReadError) and exc.error_class:
        return exc.error_class, message
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
            response = call()
            learn_response_customer_ids(response)
            return response
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
    # Why the list was cut when that was not the operator's limit (for example a collector's own safety cap).
    truncation_reason: str | None = None
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


def _policy_page(
    payload: Any, *, row_field: str = "policies", allow_empty: bool = False,
) -> tuple[list[dict[str, Any]], str | None] | None:
    """One ``policies.list`` page as (policies, next cursor), or ``None`` when its shape cannot be read.

    Only ``policies`` holds rows (an ``items`` or ``value`` list is not a policies answer), as a list of objects. A
    page may hold no rows and still carry a cursor (Google may return an empty page before the end of a list; proto3
    JSON then leaves ``policies`` out, so ``{"nextPageToken": ...}`` alone is such a page): the read goes on. An empty
    page with no cursor proves nothing and is not read as the end of a complete list. A cursor must be a non-blank
    string of bounded length; ``""`` is proto3's unset cursor (the last page), an explicit null is not a cursor.
    """
    if not isinstance(payload, dict):
        return None
    if allow_empty:
        envelope = {row_field, "nextPageToken"}
        if row_field == "items":
            envelope.update(("kind", "etag"))
            if payload.get("kind", "admin#reports#activities") != "admin#reports#activities":
                return None
        if not payload.keys() <= envelope:
            return None
    token: str | None = None
    if "nextPageToken" in payload:
        raw = payload["nextPageToken"]
        if raw != "":
            if not isinstance(raw, str) or not raw.strip() or len(raw) > POLICY_CURSOR_MAX:
                return None
            token = raw
    if row_field not in payload:
        if allow_empty:
            return [], token
        return ([], token) if token is not None and set(payload) == {"nextPageToken"} else None
    values = payload[row_field]
    if not isinstance(values, list) or not all(isinstance(item, dict) for item in values):
        return None
    if not values and token is None and not allow_empty:
        return None
    return values, token


def _collect_policy_pages(
    request_factory: Callable[[str | None], Any], *, cap: int, bounded: bool,
    row_field: str = "policies", surface: str | None = None,
) -> CollectedRows:
    """Page through ``policies.list`` with the shape checked on every page and every bound marked.

    ``bounded`` is a probe's own limit (a cut there is the operator-style limit); otherwise ``cap`` is the safety cap
    and a cut there is ``pagination_not_followed``. A first page that fails or cannot be read raises (a malformed one
    as ``malformed_response``): nothing was read. An empty page with a new cursor is followed within the bounds. A
    later page that fails or cannot be read keeps the rows read before it as a list cut by a page error. A repeated cursor or ``POLICY_PAGE_BUDGET`` requests stop the read as not
    followed.
    """
    rows: list[dict[str, Any]] = []
    token: str | None = None
    seen_tokens: set[str] = set()
    for request in range(POLICY_PAGE_BUDGET):
        try:
            payload = _execute(lambda token=token: request_factory(token).execute())
        except Exception as exc:
            if request == 0:
                raise
            # A later page failed after its retries: keep what was read, recorded as a list cut short.
            return CollectedRows(rows, truncated=True, result_limit=cap if bounded else None, page_error=exc)
        page = _policy_page(payload, row_field=row_field, allow_empty=surface is not None)
        if page is None:
            error = (
                policy_malformed_error(later_page=request > 0) if surface is None else
                PolicyReadError(f"The {surface} read returned an unreadable page.", error_class=POLICY_MALFORMED_ERROR_CLASS)
            )
            if request == 0:
                raise error
            return CollectedRows(rows, truncated=True, result_limit=cap if bounded else None, page_error=error)
        values, token = page
        rows.extend(values)
        if len(rows) > cap or (len(rows) == cap and (bounded or surface is None)):
            cut = len(rows) > cap or bool(token)
            result = CollectedRows(rows[:cap], truncated=cut, result_limit=cap if (bounded or cut) else None)
            if cut and not bounded:
                result.truncation_reason = REASON_PAGINATION_NOT_FOLLOWED
            return result
        if not token:
            return CollectedRows(rows, result_limit=None)
        if token in seen_tokens:
            break
        seen_tokens.add(token)
    # The page budget ran out or a cursor came back a second time: the read never ended.
    result = CollectedRows(rows, truncated=True, result_limit=None)
    result.truncation_reason = REASON_PAGINATION_NOT_FOLLOWED
    return result


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
    _services: dict[tuple[str, ...], Any] | None = None
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
        # Cloud Identity has two independently delegated reads. Keep their discovery clients on separate tokens,
        # including when both methods are called directly on the same GoogleWorkspaceClient.
        key = (api, version, INBOUND_SSO_SCOPE) if scopes == (INBOUND_SSO_SCOPE,) else (api, version)
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
            payload = _execute(lambda: service.orgunits().list(customerId=self.customer, type="allIncludingParent").execute())
            return _cut(payload.get("organizationUnits") or [], top)
        if resource == "domains":
            payload = _execute(lambda: service.domains().list(customer=self.customer).execute())
            domains = payload.get("domains") if isinstance(payload, dict) else None
            if not isinstance(domains, list):
                raise PolicyReadError("The Google Workspace domains list is unreadable.",
                                      error_class=POLICY_MALFORMED_ERROR_CLASS)
            rows = _cut(domains, top)
            if any(not isinstance(item, dict) for item in domains) or payload.get("nextPageToken", "") != "":
                rows.page_error = PolicyReadError("The Google Workspace domains list could not be read in full.",
                                                  error_class=POLICY_MALFORMED_ERROR_CLASS)
            return rows
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

    def list_admin_setting_events(self, event_name: str, *, limit: int | None = None) -> CollectedRows:
        """Read one pinned Admin Reports event stream over its full retention, or sample it for probe."""
        if event_name not in SCUBA_ADMIN_EVENTS:
            raise ValueError("Unsupported SCuBA admin event.")
        surface = "Admin Reports setting events"
        cap = SCUBA_EVENT_LIMIT if limit is None else min(limit, SCUBA_EVENT_LIMIT)
        try:
            service = self._service("admin", "reports_v1")
            rows = _collect_policy_pages(
                lambda token: service.activities().list(
                    userKey="all", applicationName="admin", eventName=event_name, pageToken=token,
                    maxResults=min(self.page_size, cap, 1000), fields="kind,nextPageToken,items(id(time),events(name,parameters))",
                ),
                cap=cap, bounded=limit is not None, row_field="items", surface=surface,
            )
        except Exception as exc:
            raise policy_read_error(exc, surface=surface) from None
        if rows.page_error is not None:
            rows.page_error = policy_read_error(rows.page_error, surface=surface)
        return rows

    def list_inbound_sso_assignments(self, *, limit: int | None = None) -> CollectedRows:
        """Read Cloud Identity assignments on the inbound-SSO scope, or sample them for probe."""
        surface = "Cloud Identity inbound SSO assignments"
        if not POLICY_UNIT_ID.fullmatch(self.customer):
            raise PolicyReadError("The Cloud Identity customer identifier is invalid.", error_class=POLICY_MALFORMED_ERROR_CLASS)
        try:
            service = self._service("cloudidentity", "v1", scopes=(INBOUND_SSO_SCOPE,))
            rows = _collect_policy_pages(
                lambda token: service.inboundSsoAssignments().list(
                    filter=f'customer=="customers/{self.customer}"', pageToken=token,
                    pageSize=min(self.page_size, limit or 100, 100),
                    fields="nextPageToken,inboundSsoAssignments(targetOrgUnit,targetGroup,ssoMode)",
                ),
                cap=limit or POLICY_PAGE_BUDGET * 100, bounded=limit is not None,
                row_field="inboundSsoAssignments", surface=surface,
            )
        except Exception as exc:
            raise policy_read_error(exc, surface=surface) from None
        if rows.page_error is not None:
            rows.page_error = policy_read_error(rows.page_error, surface=surface)
        return rows

    def list_policies(self, *, limit: int | None = None) -> list[dict[str, Any]]:
        """Cloud Identity policies for the SCuBA setting types (read-only policies scope).

        One paged read of every allow-listed setting type (``_POLICY_SETTINGS_FILTER``). The operator's ``--top`` never
        bounds it; only the preflight probe passes a ``limit``. Otherwise ``POLICY_SETTINGS_ROW_CAP``,
        ``POLICY_PAGE_BUDGET`` and cursor repeat detection stop a runaway read. A read cut by any of them, by a later
        page error or by a later page whose shape cannot be read comes back marked, so the collector and the probe
        record it as incomplete. A first page that cannot be read, or no policies at all, raises ``malformed_response``.
        Any error raised carries a fixed message (see :func:`policy_read_error`).
        """
        try:
            service = self._service("cloudidentity", "v1", scopes=(POLICIES_SCOPE,))
            policies = getattr(service, "policies", None)
            if policies is None:
                raise GoogleWorkspaceError(
                    "the installed google-api-python-client has no cloudidentity v1 policies resource; upgrade it",
                    surface="policies",
                )
            cap = limit or POLICY_SETTINGS_ROW_CAP
            page_size = min(self.page_size, cap, 100)
            policy_filter = f'customer == "customers/{self.customer}" && {_POLICY_SETTINGS_FILTER}'
            rows = _collect_policy_pages(
                lambda page_token: policies().list(pageSize=page_size, pageToken=page_token, filter=policy_filter),
                cap=cap,
                bounded=limit is not None,
            )
            if limit is not None:
                # The probe has no collector behind it to check the rows: a read whose rows cannot be read did not
                # read a setting, and one where only some can be read is not a complete read.
                from .collectors import policy_row_readable

                readable = [row for row in rows if policy_row_readable(row)]
                if not readable:
                    raise policy_malformed_error(later_page=False)
                if len(readable) < len(rows) and rows.page_error is None:
                    rows.page_error = PolicyReadError(POLICY_UNREADABLE_ROWS_TEXT, error_class=POLICY_MALFORMED_ERROR_CLASS)
                rows[:] = readable
        except Exception as exc:
            raise policy_read_error(exc) from None
        if rows.page_error is not None:
            rows.page_error = policy_read_error(rows.page_error)
        return rows

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
