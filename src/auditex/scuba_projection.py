"""Read-only, fail-closed bundle projection into ScubaGear ProviderExport shapes.

Provenance and privacy metadata stay on ``Projection.report``, outside evidence.
No collection, network calls, defaults for unread settings or sidecar writes.
"""
from __future__ import annotations

from collections.abc import Iterator
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import re
from typing import Any

from azure_tenant_audit.chunk_reader import _open_chunk
from azure_tenant_audit.external_sharing import ENUM_NAME_KEYS, annotate_enum_names
from azure_tenant_audit.model_assessment import collector_error_class, safe_projection_enum_value
from azure_tenant_audit.model_evidence import NOT_COLLECTED
from azure_tenant_audit.resources import open_text_resource
from azure_tenant_audit.tenant_identity import canonical_tenant_uuid

PROJECTION_VERSION = "2026-10-29"
# The projection budget: the most items and canonical JSON characters one projected section may hold.
DEFAULT_MAX_ITEMS = 40
DEFAULT_MAX_CHARS = 12_000
# Scan safety bounds on one source read, whatever the projection budget: rows examined, bytes read (the chunk
# lines, or the whole JSON file an inline list sits in) and chunk files listed. Exhausting one withholds the
# section as ``oversize`` with detail kind ``scan_bound``.
DEFAULT_SCAN_MAX_ROWS = 250_000
DEFAULT_SCAN_MAX_BYTES = 256 * 1024 * 1024
DEFAULT_SCAN_MAX_CHUNKS = 10_000
# Provider metadata read only by rules; keep the model catalogue and its prompts frozen.
RULE_ONLY_SECTIONS = frozenset({"securitysuite_unsuccessful_commands"})


class Projection(dict):
    """Evidence mapping with a separate local projection report.

    ``views`` holds the evidence a section shows one policy where it differs by policy (``scuba_config``), keyed by
    policy then section; :func:`policy_section` reads it.
    """

    report: dict[str, Any]
    views: dict[str, dict[str, Any]]
    # In-memory evidence for deterministic rules. Never serialise these attributes.
    rule_sections: dict[str, Any]
    rule_views: dict[str, dict[str, Any]]


class Unavailable(ValueError):
    def __init__(self, reason: str = "incomplete_shape", unsupported: list[str] | None = None,
                 *, field: str = "$", kind: str = "unseen_shape", value: Any = None):
        self.unsupported = unsupported or []
        self.reason = reason
        self.detail = {"field": field, "kind": kind}
        if kind == "unseen_enum_value" and safe_projection_enum_value(field, value):
            self.detail["value"] = value
        super().__init__(reason)


def _require(condition: bool, field: str = "$", kind: str = "unseen_shape") -> None:
    if not condition:
        raise Unavailable(field=field, kind=kind)


# A field name recorded under ``ignored_fields``: an identifier, else masked, since an arbitrary key can be a person's name.
_FIELD_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}")
# A Conditional Access policy's identifier, as recorded against its dropped content; anything else is its list position.
_POLICY_ID = re.compile(r"[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}")


def _annotation(key: Any) -> bool:
    """An OData annotation (``@odata.type``, ``authenticationStrength@odata.context``): metadata, never a field."""
    return isinstance(key, str) and "@odata." in key


def _empty(value: Any) -> bool:
    return value is None or isinstance(value, (str, list, dict)) and not value


def _blank(value: Any) -> bool:
    """No content at any depth: null, an empty string, list or object, or a container holding only such values.

    ``False`` and ``0`` are values (a disabled session control still says something), so they are not blank.
    """
    if isinstance(value, dict):
        return all(_blank(child) for child in value.values())
    if isinstance(value, list):
        return all(_blank(child) for child in value)
    return value is None or value == "" and isinstance(value, str)


def _collector_error(marker: dict[str, Any]) -> Unavailable:
    """A failure the collector recorded (``{"error": ..., "error_class": ...}``): the cause, never the message."""
    value = marker.get("error_class")
    classes = marker.get("error_classes")
    if not value and isinstance(classes, list) and len(set(map(str, classes))) == 1:
        value = classes[0]
    exc = Unavailable("collector_error")
    # Only the collectors' own vocabulary is echoed (``COLLECTOR_ERROR_CLASSES``, shared with the validator).
    exc.detail = {"error_class": collector_error_class(value)}
    return exc


def _attribute(exc: Unavailable, collector: str, operation: Any) -> Unavailable:
    """Name the operation behind a collector error, when it is one the collector writes."""
    if (exc.reason == "collector_error" and "operation" not in exc.detail and isinstance(operation, str)
            and _OPERATION_NAME.fullmatch(collector) and _OPERATION_NAME.fullmatch(operation)):
        exc.detail["operation"] = f"{collector}.{operation}"
    return exc


def _enum(value: Any, domain: set[str], field: str) -> None:
    _require(isinstance(value, str), field, "invalid_type")
    if value not in domain:
        raise Unavailable(field=field, kind="unseen_enum_value", value=value)


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _clean_text(value: Any) -> bool:
    """A str that is valid interchange text: no lone surrogate (a JSON \\ud800 escape decodes to one, and such a value
    can neither be hashed nor sent as UTF-8 without special handling). Treated as an invalid type, so the section withholds."""
    return isinstance(value, str) and not any(0xD800 <= ord(ch) <= 0xDFFF for ch in value)


def _strings(value: Any) -> bool:
    return isinstance(value, list) and all(_clean_text(v) for v in value)


def _text(value: Any) -> bool:
    return _clean_text(value) and bool(value)


def _boolean(value: Any) -> bool:
    return type(value) is bool


def _nullable_text(value: Any) -> bool:
    return value is None or _clean_text(value)


# Deeper than any collector writes (examples and fixtures reach 13 container levels, 14 counting a leaf). The checks
# below recurse, so depth is bounded where a file is parsed, and a deeper value withholds like a malformed one.
_MAX_DEPTH = 64


def _shallow(value: Any) -> bool:
    """True when ``value`` nests no deeper than ``_MAX_DEPTH``; iterative, so it never depends on the stack.

    The stack holds one iterator per open container, so memory is bounded by the depth, not by the size of the file.
    """
    if not isinstance(value, (dict, list)):
        return True
    stack = [iter(value.values() if isinstance(value, dict) else value)]
    while stack:
        for child in stack[-1]:
            if isinstance(child, (dict, list)):
                if len(stack) >= _MAX_DEPTH:
                    return False
                stack.append(iter(child.values() if isinstance(child, dict) else child))
                break
        else:
            stack.pop()
    return True


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        _require(key not in result)
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise Unavailable()


def _fields(row: Any, spec: dict[str, Any], *, graph: bool = False, path: str = "") -> dict[str, Any]:
    _require(isinstance(row, dict), path or "$", "invalid_type")
    if row.get("error") or row.get("error_class"):
        raise _collector_error(row)
    for key in ("read_state", "collection_status"):
        _require(row.get(key, "collected") == "collected", path + "." + key if path else key)
    result = {}
    for key, check in spec.items():
        source = key[0].lower() + key[1:] if graph else key
        field = path + "." + key if path else key
        _require(source in row, field, "missing_field")
        value = row[source]
        if isinstance(check, dict):
            result[key] = _fields(value, check, graph=graph, path=field)
        else:
            _require(check(value), field, "invalid_type")
            result[key] = deepcopy(value)
    return result


def _healthy(value: Any, *, recursive: bool = True, metadata: bool = True) -> None:
    """Reject failure markers anywhere in an endpoint or normalised record.

    ``status`` is a collection-health flag only in the collector's own metadata: an operation
    envelope, a normalised file envelope or a coverage row (``metadata``). Below that it is Graph
    record data (a role schedule's ``Provisioned``) and is never read as health. The collector-owned
    markers (``error``, ``read_state``, truncation flags and the rest) stay checked at every depth.
    """
    if isinstance(value, dict):
        if value.get("error") or value.get("error_class"):
            raise _collector_error(value)
        for key in ("resolver_error", "collection_truncated",
                    "bounded_sample", "@odata.nextLink", "truncation_reason", "incomplete", "partial"):
            _require(not value.get(key), "odata.nextLink" if key == "@odata.nextLink" else key)
        if "complete" in value:
            _require(value["complete"] is True, "complete")
        if metadata and "status" in value:
            _enum(value["status"], {"ok", "success", "collected", "complete"}, "status")
        for key in ("read_state", "collection_status"):
            _require(key not in value or value[key] == "collected", key)
        if recursive:
            for child in value.values():
                _healthy(child, metadata=False)
    elif recursive and isinstance(value, list):
        for child in value:
            _healthy(child, metadata=False)


def _shape(value: Any) -> Any:
    if isinstance(value, dict) and value and all(k.startswith("User") and k[4:].isdigit() for k in value):
        return {"users": sorted({_json(_shape(v)) for v in value.values()})}
    if isinstance(value, dict):
        return {"object": {k: _shape(v) for k, v in value.items()}}
    if isinstance(value, list):
        return {"array": sorted({_json(_shape(v)) for v in value})}
    return type(value).__name__


def _seen_shape(section: str, value: Any) -> None:
    # Empty collections need both explicit completeness and an observed empty shape.
    _require(sha256(_json(_shape(value)).encode()).hexdigest() in PACK_SHAPE_DIGESTS.get(section, []))
    def validate(item: Any, path: str = "", field: str = "") -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                domain = PACK_ENUM_DOMAINS.get(section, {}).get(path + "." + key)
                child_field = field + "." + key if field else key
                if domain is not None:
                    for v in (child if isinstance(child, list) else [child]):
                        if _json(v) not in domain:
                            raise Unavailable(field=child_field, kind="unseen_enum_value", value=v)
                validate(child, path + "." + key, child_field)
        elif isinstance(item, list):
            for child in item:
                validate(child, path + "[]", field)
    validate(value)


# Operations the privileged sections are built from, by collector. A failure on another operation of the same
# collector that the payload also carries (a refused sign-in activity read, say) is recorded and never withholds.
# ``privilegedGroupFanout`` is the derived coverage row of the group fan-out; ``groupMembers`` is not a name the
# collector writes today, but a bundle that names the fan-out that way is read as the same dependency and fails closed.
ADMIN_SET_READS = {
    "identity": frozenset({"users", "groups", "servicePrincipals", "roleDefinitions", "roleAssignments",
                           "roleAssignableGroupMembers", "privilegedGroupFanout", "groupMembers"}),
    "identity_governance": frozenset({"roleAssignmentSchedules", "roleEligibilitySchedules"}),
}
# Role policy rules come only from the artefact; the schedules are the assignments it describes. The normaliser writes the
# artefact only when the collector's policy reads (``roleManagementPolicyAssignments``, ``roleManagementPolicyRules``) and
# the schedules all succeeded in full, so a failure of a policy read leaves no artefact (``missing_artifact``) and is
# listed in ``ignored_failures`` like any other operation this section does not read.
PRIVILEGED_ROLES_READS = {"identity_governance": frozenset({"roleAssignmentSchedules", "roleEligibilitySchedules"})}
# Names a gap or coverage row may carry for a collector although the collector's payload has no operation of that name: the
# normaliser records an artefact it withheld after every read succeeded (``collection_gaps``: ``identity_governance.
# privileged_roles``, reason ``artefact_withheld``). Like a policy read, it is listed in ``ignored_failures`` and never
# withholds a section that does not read it, the artefact's own section included (it stays ``missing_artifact``).
# The identity collector's ``privilegedGroupFanout`` coverage row is derived the same way (a ledger diagnostic names it), so
# a failed fan-out is recorded for the sections that do not read it (``tenant_id``) and withholds those that do.
DERIVED_NAMES = {"identity_governance": frozenset({"privileged_roles"}), "identity": frozenset({"privilegedGroupFanout"})}
# Reads a section can do without when the collector reports them refused for want of a licence (``license_required``) and
# empty: privileged users come from the directory role assignments when PIM is not licensed, as the effective admin set
# records (its schedule sources ``not_applicable``). The refused reads are listed under ``ignored_failures``.
LICENCE_OPTIONAL_READS = {"identity_governance": frozenset({"roleAssignmentSchedules", "roleEligibilitySchedules"})}
_OPERATION_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]*")
_COVERAGE_OK = {"ok", "complete_exact_scope", "complete_effective_role", "complete_equivalent_scope",
                "complete_offline_sample"}
# A ledger row that is partial or blocked says which operations failed in its diagnostics.
_LEDGER_ATTRIBUTABLE = _COVERAGE_OK | {"partial_success", "blocked_permission"}


def _scan_bound(field: str) -> Unavailable:
    return Unavailable("oversize", field=field, kind="scan_bound")


def _names(name: Any) -> frozenset[str]:
    """A coverage name, and the operation behind a derived ``<operation>Fanout`` row."""
    if not isinstance(name, str) or not name:
        return frozenset()
    base = name[:-len("Fanout")] if name.endswith("Fanout") and len(name) > len("Fanout") else name
    return frozenset({name, base})


def _licence_refused(envelope: Any) -> bool:
    """An operation envelope the collector wrote for a read refused for want of a licence, holding no rows."""
    return (isinstance(envelope, dict) and envelope.get("error_class") == "license_required" and not envelope.get("value")
            and not envelope.get("chunk_files") and envelope.get("item_count", 0) == 0)


class Bundle:
    def __init__(self, root: Path, scan_max_rows: int, scan_max_bytes: int, scan_max_chunks: int):
        self.root = root
        self.scan_max_rows, self.scan_max_bytes, self.scan_max_chunks = scan_max_rows, scan_max_bytes, scan_max_chunks
        self.manifest: dict[str, Any] = {}
        self.reset()

    def reset(self) -> None:
        """Start a new section: provenance, completeness, scan counts and ignored failures are per section."""
        self.sources: list[str] = []
        self.complete = False
        self.scan_rows = 0
        self.scan_chunk_bytes = 0
        self.scan_chunks: set[str] = set()
        self.scan_inline: dict[str, int] = {}
        self.sizes: dict[str, int] = {}
        self.ignored: set[str] = set()
        self.ignored_fields: set[str] = set()
        self.dropped_conditions: set[str] = set()
        self.null_lists: set[str] = set()

    def known_fields(self, row: Any, allowed: set[str], path: str = "") -> None:
        """Require an object; record its fields the training shape does not know, which are never projected.

        An extra field never withholds: the adapter projects only the fields it selects. Its name (never its value) is
        recorded in ``ignored_fields`` so drift stays visible; OData annotations are not fields and are not recorded.
        """
        self.qualified_fields(row, allowed, path, lenient=True)

    def qualified_fields(self, row: Any, allowed: set[str], path: str = "",
                         harmless: dict[str, Any] | None = None, *, lenient: bool = False) -> None:
        """:meth:`known_fields` for an object whose extra fields can qualify the ones kept: a scope, a target, a status.

        Such an extra is ignored and recorded only when it is empty or ``harmless[name](value)`` shows it changes nothing
        (a tenant-wide ``DirectoryScopeId`` of ``/``); a populated one withholds the section and names the field (kind
        ``unexpected_field``), as a populated unknown Conditional Access condition does.
        """
        _require(isinstance(row, dict), path or "$", "invalid_type")
        for key, value in row.items():
            if key in allowed or _annotation(key):
                continue
            name = key if isinstance(key, str) and _FIELD_NAME.fullmatch(key) else "unrecognisedField"
            field = path + "." + name if path else name
            check = (harmless or {}).get(key)
            _require(lenient or _empty(value) or check is not None and check(value), field, "unexpected_field")
            self.ignored_fields.add(field)

    @property
    def scan_counts(self) -> dict[str, int]:
        return {"rows": self.scan_rows, "bytes": self.scan_chunk_bytes + sum(self.scan_inline.values()),
                "chunks": len(self.scan_chunks)}

    def read(self, relative: str) -> Any:
        # Reuse no-symlink, regular-file, beneath-root bundle opens. A file is read whole, so the byte bound
        # applies before anything is parsed.
        try:
            with _open_chunk(self.root, relative) as handle:
                data = handle.read(self.scan_max_bytes + 1)
        except FileNotFoundError:
            raise Unavailable("missing_artifact") from None
        except (OSError, ValueError, UnicodeError):
            raise Unavailable() from None
        if len(data) > self.scan_max_bytes:
            raise _scan_bound("scan_max_bytes")
        try:
            value = json.loads(data, object_pairs_hook=_unique_pairs, parse_constant=_invalid_constant)
        except (OSError, ValueError, UnicodeError, RecursionError):
            raise Unavailable() from None
        _require(_shallow(value))
        if relative not in self.sources:
            self.sources.append(relative)
        self.sizes[relative] = len(data)
        return value

    def normalised(self, name: str) -> list[dict[str, Any]]:
        data = self.read(f"normalized/{name}.json")
        _require(isinstance(data, dict), kind="invalid_type")
        _require("records" in data, "records", "missing_field")
        _require(isinstance(data["records"], list), "records", "invalid_type")
        if data.get("error") or data.get("error_class"):
            raise _collector_error(data)
        _require(data.get("collection_status", "collected") == "collected", "collection_status")
        _require(all(isinstance(row, dict) for row in data["records"]), "records", "invalid_type")
        _healthy(data)
        self.complete = data.get("complete") is True or data.get("collection_status") == "collected" or data.get("status") in {"ok", "collected", "complete"}
        _require(bool(data["records"]) or self.complete, "records")
        return data["records"]

    @staticmethod
    def _attribution(row: dict[str, Any], collector: str) -> tuple[list[frozenset[str]] | None, bool]:
        """The operations a coverage row attributes its status to, and whether it names them itself.

        A row names its operation (``list`` or ``name``, else the operation of its ``source``). A
        coverage-ledger row covers the whole collector and lists the failed operations in ``diagnostics``
        (``item``). Without either (``None``) the row is about the collector as a whole.
        """
        name = row.get("list", row.get("name"))
        if name:
            return [_names(name)], True
        source = row.get("source")
        if isinstance(source, str) and source.startswith(collector + "."):
            return [_names(source[len(collector) + 1:])], True
        diagnostics = row.get("diagnostics")
        if isinstance(diagnostics, list) and diagnostics:
            return [_names(item.get("item")) if isinstance(item, dict) else frozenset() for item in diagnostics], False
        return None, False

    @staticmethod
    def _unrelated(groups: list[frozenset[str]] | None, reads: frozenset[str], known: frozenset[str]) -> list[str] | None:
        """The operations to record when each one is carried by the payload and none is read by the section."""
        if not groups:
            return None
        found = []
        for names in groups:
            match = sorted(n for n in names if n in known and _OPERATION_NAME.fullmatch(n))
            if not match or names & reads:
                return None
            found.append(match[0])
        return found

    def coverage(self, collector: str, reads: Any, known: frozenset[str] = frozenset(), *, health: bool = False) -> bool:
        """Fail when coverage evidence for an operation the section reads reports a failure.

        A row about another operation that the collector's payload also carries does not withhold; it is
        recorded in ``ignored``. A row that cannot be attributed that way (the collector as a whole, or a name
        the payload does not carry) still fails, except that a named row of a single read (``health`` False)
        that names some other operation is skipped. Returns whether a complete coverage row was found.
        """
        reads = frozenset([reads]) if isinstance(reads, str) else frozenset(reads)
        complete = surveyed = False
        gaps = self.manifest.get("coverage_gaps", [])
        _require(isinstance(gaps, (list, dict)), "coverage_gaps", "invalid_type")
        summary_only = self._manifest_gaps(gaps, collector, reads, known)
        for path in ("coverage.json", "normalized/coverage_ledger.json", "normalized/collection_gaps.json"):
            try:
                data = self.read(path)
            except Unavailable as exc:
                if exc.reason == "missing_artifact":
                    continue
                raise
            _healthy(data, recursive=False)
            rows = data.get("records") if isinstance(data, dict) else data
            _require(isinstance(rows, list))
            gap_rows = path.endswith("collection_gaps.json")
            for row in rows:
                _require(isinstance(row, dict))
                source = row.get("source", "")
                if row.get("collector") != collector and not (isinstance(source, str) and source.startswith(collector + ".")):
                    continue
                surveyed = surveyed or not gap_rows
                groups, named = self._attribution(row, collector)
                if groups and not any(names & reads for names in groups):
                    ledger = "coverage_status" in row
                    unrelated = None if ledger and row["coverage_status"] not in _LEDGER_ATTRIBUTABLE \
                        else self._unrelated(groups, reads, known)
                    if unrelated is not None:
                        failed = gap_rows
                        if not gap_rows:
                            try:
                                self._row_health(row)
                            except Unavailable:
                                failed = True
                        if failed:
                            self.ignored.update(f"{collector}.{name}" for name in unrelated)
                        continue
                    if named and not health:
                        # A single read: a row naming some other operation is not about this read.
                        continue
                try:
                    if gap_rows:
                        _healthy(row)
                        raise _collector_error(row) if row.get("error_classes") else Unavailable()
                    self._row_health(row)
                except Unavailable as exc:
                    raise self._attribute_row(exc, row, groups, named, collector, reads)
                complete = True
        if summary_only and not surveyed:
            raise Unavailable(field="coverage_gaps")
        return complete

    @staticmethod
    def _attribute_row(exc: Unavailable, row: dict[str, Any], groups: list[frozenset[str]] | None, named: bool,
                       collector: str, reads: frozenset[str]) -> Unavailable:
        """Name the read a failed coverage row is about; a ledger row reports the failed diagnostic of that read."""
        if exc.reason != "collector_error" or not groups:
            return exc
        if named:
            return _attribute(exc, collector, next(iter(sorted(n for n in groups[0] if n in reads) or [None])))
        for item, names in zip(row.get("diagnostics", []), groups):
            if names & reads and isinstance(item, dict) and (item.get("error") or item.get("error_class")):
                return _attribute(_collector_error(item), collector, item.get("item"))
        return exc

    @staticmethod
    def _row_health(row: dict[str, Any]) -> None:
        _healthy(row)
        _require("actual_status" not in row or row["actual_status"] == "ok", "actual_status")
        status = row.get("coverage_status", row.get("status"))
        _require(status in _COVERAGE_OK, "coverage_status" if "coverage_status" in row else "status")

    def _manifest_gaps(self, gaps: Any, collector: str, reads: frozenset[str], known: frozenset[str]) -> bool:
        """Check the manifest's coverage gaps; True when they only list the collector in a surface summary.

        A gap that names this collector and an operation is judged like a coverage row. A surface summary that
        merely lists the collector repeats the per-operation rows, so it stands only when no coverage row exists
        to say which operation failed.
        """
        summary_only = False
        def operation_gap(names: frozenset[str] | None) -> None:
            if names and not names & reads:
                unrelated = self._unrelated([names], reads, known)
                if unrelated is not None:
                    self.ignored.update(f"{collector}.{name}" for name in unrelated)
                    return
            raise Unavailable(field="coverage_gaps")
        def walk(value: Any) -> None:
            nonlocal summary_only
            if isinstance(value, dict):
                if value.get("collector") == collector:
                    key = next((k for k in ("list", "section", "name", "item") if value.get(k)), None)
                    operation_gap(_names(value[key]) if key else None)
                    return
                for child in value.values():
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)
            elif isinstance(value, str):
                if value == collector:
                    summary_only = True
                elif value.startswith(collector + "."):
                    names = _names(value[len(collector) + 1:])
                    if names & reads:
                        raise Unavailable(field="coverage_gaps")
                    unrelated = self._unrelated([names], reads, known)
                    if unrelated is not None:
                        self.ignored.update(f"{collector}.{name}" for name in unrelated)
        walk(gaps)
        return summary_only

    def _collector_payload(self, collector: str) -> tuple[dict[str, Any] | None, str | None]:
        """The collector's operation envelopes with the file they came from: its raw file, else the offline sample's entry."""
        origin = f"raw/{collector}.json"
        try:
            payload = self.read(origin)
        except Unavailable as exc:
            if exc.reason != "missing_artifact":
                raise
            origin = "raw/sample_input.json"
            try:
                sample = self.read(origin)
            except Unavailable as sample_exc:
                if sample_exc.reason != "missing_artifact":
                    raise
                return None, None
            _require(isinstance(sample, dict))
            payload = sample.get(collector, {})
        _require(isinstance(payload, dict))
        return payload, origin

    def collector_health(self, collector: str, reads: Any, licence_optional: frozenset[str] = frozenset()) -> None:
        """Withhold when an operation read from this collector, or the collector itself, reports a failure.

        The failure of another operation is recorded in ``ignored`` and does not withhold; so is a read in
        ``licence_optional`` that the collector reports refused for want of a licence and empty.
        """
        reads = frozenset(reads)
        payload, _ = self._collector_payload(collector)
        if payload is not None:
            refused = {name for name in reads & licence_optional if _licence_refused(payload.get(name))}
            self.ignored.update(f"{collector}.{name}" for name in refused)
            reads -= refused
        self.coverage(collector, reads, frozenset(payload or ()) | DERIVED_NAMES.get(collector, frozenset()), health=True)
        if payload is None:
            return
        # The payload maps operation names to their envelopes; keys beside them are the collector's own metadata.
        _healthy(payload, recursive=False)
        for name, envelope in payload.items():
            try:
                _healthy(envelope)
            except Unavailable as exc:
                if name in reads or not _OPERATION_NAME.fullmatch(name) or not isinstance(envelope, dict):
                    raise _attribute(exc, collector, name)
                self.ignored.add(f"{collector}.{name}")

    def operation(self, collector: str, operation: str) -> list[dict[str, Any]]:
        return list(self.scan(collector, operation))

    def scan(self, collector: str, operation: str) -> Iterator[dict[str, Any]]:
        """Yield one operation's rows after its health checks, without keeping them.

        The checks that need every row (the item count, an empty collection's completeness) run once the
        iterator is exhausted, so a caller must consume it fully before it trusts what it kept. Source reads
        are bounded by the scan bounds only; the section's projection budget applies to the projected object,
        not to how many rows were read to build it.
        """
        payload, origin = self._collector_payload(collector)
        if payload is None:
            origin = f"raw/{collector}/{operation}/summary.json"
            section = self.read(origin)
        else:
            _healthy(payload, recursive=False)
            if operation not in payload:
                raise Unavailable("missing_artifact")
            section = payload[operation]
        complete = self.coverage(collector, operation, frozenset(payload or ()) | DERIVED_NAMES.get(collector, frozenset()))
        _require(isinstance(section, dict))
        self.complete = complete or section.get("complete") is True or section.get("collection_status") == "collected" or section.get("status") in {"ok", "collected", "success"}
        try:
            _healthy(section)
        except Unavailable as exc:
            raise _attribute(exc, collector, operation)
        _require(not any(section.get(k) for k in (
            "error", "error_class", "collection_truncated", "bounded_sample", "@odata.nextLink",
            "truncation_reason", "incomplete", "partial")))
        _require(section.get("status", "ok") in {"ok", "success", "collected"})
        if not any(k in section for k in ("value", "chunk_files")):
            _require(bool(section) and not any(k in section for k in ("item_count", "sample_truncated")))
            self.scan_rows += 1
            self.scan_inline[origin] = self.sizes[origin]
            yield section
            return
        chunks = section.get("chunk_files", [])
        _require(isinstance(chunks, list) and all(isinstance(p, str) for p in chunks), "chunk_files", "invalid_type")
        _require(all(p.startswith((f"raw/{collector}/{operation}/", f"chunks/{collector}/")) for p in chunks), "chunk_files")
        _require(all(not any(part == ".secrets" or part.startswith(".env") for part in Path(p).parts) for p in chunks), "chunk_files")
        _require(len(set(chunks)) == len(chunks), "chunk_files")
        if len(chunks) > self.scan_max_chunks:
            raise _scan_bound("scan_max_chunks")
        _require("chunk_count" not in section or type(section["chunk_count"]) is int
                 and section["chunk_count"] == len(chunks), "chunk_count")
        count = 0
        def valid(row: Any) -> Any:
            _require(isinstance(row, dict), "value", "invalid_type")
            _healthy(row, metadata=False)
            return row
        if chunks:
            seen = set()
            consumed_bytes = 0
            for path in chunks:
                try:
                    with _open_chunk(self.root, path) as handle:
                        stat = os.fstat(handle.fileno())
                        _require((stat.st_dev, stat.st_ino) not in seen)
                        seen.add((stat.st_dev, stat.st_ino))
                        if path not in self.sources:
                            self.sources.append(path)
                        self.scan_chunks.add(path)
                        while True:
                            # Never materialise an unbounded line or the full collection.
                            line = handle.readline(self.scan_max_bytes - consumed_bytes + 1)
                            if not line:
                                break
                            consumed_bytes += len(line)
                            self.scan_chunk_bytes += len(line)
                            if consumed_bytes > self.scan_max_bytes:
                                raise _scan_bound("scan_max_bytes")
                            if not line.strip():
                                continue
                            if count >= self.scan_max_rows:
                                raise _scan_bound("scan_max_rows")
                            row = json.loads(line, object_pairs_hook=_unique_pairs, parse_constant=_invalid_constant)
                            _require(_shallow(row), "chunk_files")
                            row = valid(row)
                            count += 1
                            self.scan_rows += 1
                            yield row
                except Unavailable:
                    raise
                except (OSError, ValueError, UnicodeError, RecursionError):
                    raise Unavailable(field="chunk_files") from None
        else:
            _require("value" in section, "value", "missing_field")
            _require(isinstance(section["value"], list), "value", "invalid_type")
            _require(not section.get("sample_truncated"), "sample_truncated")
            self.scan_inline[origin] = self.sizes[origin]
            for row in section["value"]:
                if count >= self.scan_max_rows:
                    raise _scan_bound("scan_max_rows")
                row = valid(row)
                count += 1
                self.scan_rows += 1
                yield row
        if "item_count" in section:
            _require(type(section["item_count"]) is int, "item_count", "invalid_type")
            _require(section["item_count"] == count, "item_count")
        _require(not section.get("sample_truncated") or "item_count" in section, "item_count", "missing_field")
        if not count:
            _require(complete or section.get("complete") is True
                     or section.get("collection_status") == "collected" or section.get("status") in {"ok", "collected", "success"})

    def alternatives(self, operations: list[tuple[str, str]]) -> list[dict[str, Any]]:
        found = []
        for collector, operation in operations:
            try:
                rows = self.operation(collector, operation)
            except Unavailable as exc:
                if exc.reason != "missing_artifact":
                    raise
            else:
                found.append(rows)
        if not found:
            raise Unavailable("missing_artifact")
        _require(all(rows == found[0] for rows in found))
        return found[0]


SPO_SCALARS = ("RequireAnonymousLinksExpireInDays", "EmailAttestationRequired", "EmailAttestationReAuthDays")


def _spo(bundle: Bundle) -> Any:
    normal = bundle.normalised("sharepoint_tenant_settings")
    rows = bundle.alternatives([("sharepoint_access", "sharePointSettings"), ("onedrive_posture", "sharePointSettings")])
    _require(len(rows) == 1)
    raw, result = rows[0], {}
    read = [*ENUM_NAME_KEYS, *SPO_SCALARS]
    bundle.known_fields(raw, {*read, *(k[0].lower() + k[1:] for k in read), "oneDriveSharingCapability", "odbSharingCapability"})
    canonical = {"SharingCapability": "sharing_capability", "ODBSharingCapability": "onedrive_sharing_capability"}
    for key, names in ENUM_NAME_KEYS.items():
        value = raw.get(key, raw.get(key[0].lower() + key[1:]))
        if key == "ODBSharingCapability":
            value = raw.get(key, raw.get("oneDriveSharingCapability", raw.get("odbSharingCapability")))
        if key in canonical:
            values = [r[canonical[key]] for r in normal if r.get("read_state") == "collected" and canonical[key] in r]
            _require(bool(values), key, "missing_field")
            _require(all(v == values[0] for v in values), key)
            reverse = {str(v).split(" (")[0]: n for n, v in names.items()}
            _require(isinstance(values[0], str), key, "invalid_type")
            if values[0] not in reverse:
                raise Unavailable(field=key, kind="unseen_enum_value", value=values[0])
            number = reverse[values[0]]
            if value is not None:
                _require(type(value) in (int, str), key, "invalid_type")
                _require((type(value) is int and value == number) or value == values[0], key)
        else:
            _require(key in raw or key[0].lower() + key[1:] in raw, key, "missing_field")
            _require(type(value) in (int, str), key, "invalid_type")
            reverse = {v: n for n, v in names.items()}
            number = value if type(value) is int else reverse.get(value) if isinstance(value, str) else None
            if type(number) is not int or number not in names:
                raise Unavailable(field=key, kind="unseen_enum_value", value=value)
        result[key] = number
    for key, allowed in {"DefaultLinkPermission": {1, 2}, "DefaultSharingLinkType": {1, 2},
                         "SharingDomainRestrictionMode": {0, 1}}.items():
        if result[key] not in allowed:
            raise Unavailable(field=key, kind="unseen_enum_value", value=result[key])
    for key in SPO_SCALARS:
        value = raw.get(key, raw.get(key[0].lower() + key[1:]))
        _require(key in raw or key[0].lower() + key[1:] in raw, key, "missing_field")
        _require(type(value) is (bool if key == "EmailAttestationRequired" else int), key, "invalid_type")
        if key != "EmailAttestationRequired":
            _require(value >= (-1 if key == "RequireAnonymousLinksExpireInDays" else 0), key)
        result[key] = value
    return [result]


def _ca(bundle: Bundle) -> Any:
    # Whitelists describe representable fields, not a union used to authorise shapes.
    spec = {
        "DisplayName": _text, "State": _text,
        "Conditions": {
            "Applications": {k: _strings for k in ("IncludeApplications", "ExcludeApplications", "IncludeUserActions")},
            "AuthenticationFlows": {"TransferMethods": _nullable_text},
            "ClientAppTypes": _strings,
            "ClientApplications": {"IncludeAgentIdServicePrincipals": _strings},
            "SignInRiskLevels": _strings, "UserRiskLevels": _strings, "AgentIdRiskLevels": _nullable_text,
            "Users": {**{k: _strings for k in ("IncludeUsers", "ExcludeUsers", "IncludeRoles", "ExcludeRoles", "ExcludeGroups")},
                      "ExcludeGuestsOrExternalUsers": {"GuestOrExternalUserTypes": _text,
                                                       "ExternalTenants": {"MembershipKind": _text}}}},
        "GrantControls": {"BuiltInControls": _strings, "Operator": _nullable_text,
                          "AuthenticationStrength": {"AllowedCombinations": lambda v: v is None or _strings(v)}}}
    # Only schema field names enter diagnostics; unknown keys can themselves contain PII. A known restriction withholds
    # when it carries a value (see ``_blank``): a null, empty or all-empty one restricts nothing, so it is read as absent
    # whatever the Graph serialisation of an unset condition is. An unrecognised field is ignored (and recorded) when it
    # is empty or outside the conditions and controls; a populated one inside them can narrow who or what the policy
    # covers, so it still withholds. Only a policy in the ``enabled`` state is read by any pinned ScubaGear rule
    # (AADConfig.rego: every ``*BaseCheck`` requires ``policy.State == "enabled"``), so a disabled or report-only policy
    # cannot change a verdict: its unsupported keys are dropped and recorded under ``dropped_conditions``, not withheld.
    restriction_names = {"locations", "devices", "platforms", "sessionControls", "includeGroups",
                         "includeGuestsOrExternalUsers", "authenticationContextClassReferences",
                         "servicePrincipalRiskLevels", "customAuthenticationFactors", "termsOfUse",
                         "applicationFilter", "includeServicePrincipals", "excludeServicePrincipals",
                         "servicePrincipalFilter", "id", "displayName"}
    found: set[str] = set()
    def convert(row: Any, fields: dict, path: str = "", field_path: str = "") -> dict:
        _require(isinstance(row, dict), field_path or "$", "invalid_type")
        output = {}
        for key, value in row.items():
            if _annotation(key):
                continue
            target = key[0].upper() + key[1:] if key else ""
            if target not in fields:
                # The policy's own ``id`` (like createdDateTime and templateId) is recorded; a nested one is a restriction.
                restricted = key in restriction_names and (path or key != "id")
                if restricted and not _blank(value):
                    found.add(path + key)
                elif not restricted and path and value not in (None, [], {}, ""):
                    found.add(path + "unrecognisedField")
                else:
                    bundle.known_fields({key: value}, set(), path.rstrip("."))
                continue
            field = field_path + "." + target if field_path else target
            _require(key == target[0].lower() + target[1:] and target not in output,
                     field, "unexpected_field")
            check = fields[target]
            if isinstance(check, dict):
                output[target] = None if value is None else convert(value, check, path + key + ".", field)
            else:
                if value is None and check is _strings:
                    # Count, ContainsValue and ConvertToSet in the pinned Rego (utils/KeyFunctions.rego) read null as an empty
                    # list, and so does every ``in`` over these fields; Graph documents no nullability for a collection.
                    value = []
                    bundle.null_lists.add(field)
                _require(check(value), field, "invalid_type")
                if target == "State":
                    _enum(value, {"enabled", "disabled", "enabledForReportingButNotEnforced"}, "State")
                output[target] = deepcopy(value)
        return output
    result, unsupported = [], set()
    for index, row in enumerate(bundle.operation("conditional_access", "conditionalAccessPolicies")):
        found.clear()
        result.append(convert(row, spec))
        if result[-1].get("State") not in {"disabled", "enabledForReportingButNotEnforced"}:
            unsupported |= found
        else:
            identifier = row.get("id") if isinstance(row.get("id"), str) else ""
            reference = identifier if _POLICY_ID.fullmatch(identifier) else f"policy{index}"
            bundle.dropped_conditions.update(f"{reference}:{name}" for name in found)
    if unsupported:
        raise Unavailable(unsupported=sorted(unsupported), field=sorted(unsupported)[0], kind="unexpected_field")
    return result


def _authorization(bundle: Bundle) -> Any:
    rows = bundle.alternatives([("external_identity", "authorizationPolicy"), ("consent_policy", "authorizationPolicy")])
    _require(len(rows) == 1)
    row = rows[0]
    bundle.known_fields(row, {"id", "allowInvitesFrom", "guestUserRoleId", "defaultUserRolePermissions"})
    result = _fields(row, {"Id": _text, "AllowInvitesFrom": _text, "GuestUserRoleId": _text}, graph=True)
    _require("defaultUserRolePermissions" in row, "DefaultUserRolePermissions", "missing_field")
    permissions = row.get("defaultUserRolePermissions")
    bundle.known_fields(permissions, {
        "allowedToCreateApps", "permissionGrantPoliciesAssigned", "permissionGrantPolicyIdsAssignedToDefaultUserRole",
        "allowedToCreateSecurityGroups", "allowedToReadOtherUsers"}, "DefaultUserRolePermissions")
    # These two Graph settings are not read by the dependent SCuBA policies and
    # have no corresponding field in the frozen ProviderExport shape.
    result["DefaultUserRolePermissions"] = _fields(
        permissions, {"AllowedToCreateApps": _boolean}, graph=True, path="DefaultUserRolePermissions")
    if "permissionGrantPoliciesAssigned" in permissions and "permissionGrantPolicyIdsAssignedToDefaultUserRole" in permissions:
        _require(permissions["permissionGrantPoliciesAssigned"] == permissions["permissionGrantPolicyIdsAssignedToDefaultUserRole"],
                 "PermissionGrantPolicyIdsAssignedToDefaultUserRole")
    _require(any(k in permissions for k in ("permissionGrantPoliciesAssigned", "permissionGrantPolicyIdsAssignedToDefaultUserRole")),
             "PermissionGrantPolicyIdsAssignedToDefaultUserRole", "missing_field")
    assigned = permissions.get("permissionGrantPoliciesAssigned", permissions.get("permissionGrantPolicyIdsAssignedToDefaultUserRole"))
    _require(_strings(assigned), "PermissionGrantPolicyIdsAssignedToDefaultUserRole", "invalid_type")
    result["PermissionGrantPolicyIdsAssignedToDefaultUserRole"] = assigned
    return [result]


def _plans(bundle: Bundle) -> Any:
    # Each SKU row is far larger than the plan names kept from it: stream the rows, keep only the plans. ScubaGear keeps
    # only the plans whose provisioningStatus is Success (ExportAADProvider.psm1): a disabled or pending plan is not one
    # the tenant has, so it is left out, as there; a plan without a status cannot be called provisioned and withholds the section.
    result = {}
    for row in bundle.scan("licensing", "subscribedSkus"):
        bundle.known_fields(row, {"servicePlans"})
        _require("servicePlans" in row, "servicePlans", "missing_field")
        _require(isinstance(row.get("servicePlans"), list), "servicePlans", "invalid_type")
        for plan in row["servicePlans"]:
            bundle.known_fields(plan, {"servicePlanId", "servicePlanName", "provisioningStatus", "appliesTo"}, "servicePlans")
            # A raw plan without a provisioning status cannot be called provisioned: ScubaGear's exporter keeps plans whose
            # status is an explicit Success, so a status-less plan withholds the section rather than asserting a licence.
            _require("provisioningStatus" in plan, "servicePlans.provisioningStatus", "missing_field")
            _enum(plan["provisioningStatus"], {
                "Success", "Disabled", "Error", "PendingInput", "PendingActivation", "PendingProvisioning"},
                "servicePlans.provisioningStatus")
            if "appliesTo" in plan:
                _enum(plan["appliesTo"], {"User", "Company"}, "servicePlans.appliesTo")
            item = _fields(plan, {"ServicePlanId": _text, "ServicePlanName": _text}, graph=True)
            if plan["provisioningStatus"] != "Success":
                continue
            key = item["ServicePlanId"]
            _require(key not in result or result[key] == item, "ServicePlanId")
            result[key] = item
    return list(result.values())


def _users(bundle: Bundle) -> Any:
    for collector, reads in ADMIN_SET_READS.items():
        bundle.collector_health(collector, reads, LICENCE_OPTIONAL_READS.get(collector, frozenset()))
    admins = bundle.normalised("effective_admin_set")
    summaries = [r for r in admins if r.get("kind") == "effective_admin_set_summary"]
    _require(len(summaries) == 1)
    _require("state" in summaries[0], "state", "missing_field")
    _require(summaries[0]["state"] == "complete", "state")
    _require("unresolved_principal_count" in summaries[0], "unresolved_principal_count", "missing_field")
    _require(summaries[0]["unresolved_principal_count"] == 0, "unresolved_principal_count")
    admin_rows = [r for r in admins if r.get("is_user") is True]
    _require("admin_count" in summaries[0], "admin_count", "missing_field")
    _require(type(summaries[0]["admin_count"]) is int, "admin_count", "invalid_type")
    _require(summaries[0]["admin_count"] == len(admin_rows), "admin_count")
    _require(len({r.get("principal_id") for r in admin_rows}) == len(admin_rows), "principal_id")
    # The administrators are few and listed above; the user list is large. Stream it once and keep only
    # the rows whose id is an administrator's, never the list or an index of it.
    wanted = {r.get("principal_id") for r in admin_rows}
    index: dict[str, dict[str, Any]] = {}
    for row in bundle.scan("identity", "users"):
        _require(_text(row.get("id")), "id")
        if row["id"] in wanted:
            _require(row["id"] not in index, "id")
            index[row["id"]] = row
    # Current identity reads select onPremisesImmutableId for every user. Older bundles can supply it from the hybrid
    # collector's first-100 sync sample; an administrator in neither read withholds the section.
    missing = {key for key, row in index.items() if "onPremisesImmutableId" not in row}
    if missing:
        found: dict[str, Any] = {}
        try:
            for row in bundle.scan("domains_hybrid", "syncSampleUsers"):
                if row.get("id") in missing and "onPremisesImmutableId" in row:
                    _require(found.get(row["id"], row["onPremisesImmutableId"]) == row["onPremisesImmutableId"], "id")
                    found[row["id"]] = row["onPremisesImmutableId"]
        except Unavailable as exc:
            if exc.reason != "missing_artifact":
                raise
        for key, value in found.items():
            index[key] = {**index[key], "onPremisesImmutableId": value}
    result = {}
    for admin in sorted(admin_rows, key=lambda r: r.get("principal_id", "")):
        _require("state" in admin, "state", "missing_field")
        _require(admin["state"] == "complete", "state")
        _require("principal_id" in admin, "principal_id", "missing_field")
        _require(admin["principal_id"] in index, "principal_id")
        row = index[admin["principal_id"]]
        bundle.known_fields(row, {"id", "displayName", "onPremisesImmutableId"})
        item = _fields(row, {"DisplayName": _text, "OnPremisesImmutableId": _nullable_text}, graph=True)
        _require("role_names" in admin, "role_names", "missing_field")
        _require(_strings(admin["role_names"]), "role_names", "invalid_type")
        _require(bool(admin["role_names"]), "role_names")
        _tenant_wide_roles(admin)
        item["roles"] = list(admin["role_names"])
        result[f"User{len(result) + 1}"] = item
    return result


def _tenant_wide_roles(admin: dict[str, Any]) -> None:
    """Every role an administrator is listed with must be held tenant-wide (directory scope ``/``).

    The frozen shape lists role names only, as ScubaGear does from the directory role members, which are tenant-wide. A
    role held only at an administrative unit or another scope (or at a scope the admin set does not know) cannot be told
    apart from a tenant-wide one there, so it withholds the section. A scoped assignment of a role also held tenant-wide
    changes nothing and is allowed.
    """
    _require("roles" in admin, "roles", "missing_field")
    _require(isinstance(admin["roles"], list), "roles", "invalid_type")
    scopes: dict[str, set[Any]] = {}
    for entry in admin["roles"]:
        _require(isinstance(entry, dict) and _text(entry.get("role")), "roles.role", "invalid_type")
        scopes.setdefault(entry["role"], set()).add(entry.get("scope"))
    for name in admin["role_names"]:
        held = scopes.get(name, set())
        _require(bool(held), "roles.role", "missing_field")
        if "/" not in held:
            _require(held != {None}, "roles.scope", "missing_field")
            raise Unavailable(field="roles.scope", kind="unseen_enum_value")


def _role_date(value: Any) -> bool:
    return value is None or isinstance(value, str) and re.fullmatch(r"/Date\(-?[0-9]+\)/", value) is not None


def _any(_value: Any) -> bool:
    return True


def _rule_target(rule_id: Any) -> Any:
    """Whether a rule's ``Target`` says no more than its ``Id`` (``<Kind>_[<Recipient>_]<Caller>_<Level>``) does."""
    parts = rule_id.split("_") if isinstance(rule_id, str) else []

    def harmless(target: Any) -> bool:
        if len(parts) < 3 or not isinstance(target, dict):
            return False
        fields = {k.lower(): v for k, v in target.items() if isinstance(k, str) and not _annotation(k)}
        if len(fields) != len([k for k in target if not _annotation(k)]):
            return False
        expected = {"caller": parts[-2].lower(), "level": parts[-1].lower()}
        for key, value in fields.items():
            if key in expected:
                if not isinstance(value, str) or value.lower() != expected[key]:
                    return False
            elif key == "operations":
                if not (_empty(value) or _strings(value) and [v.lower() for v in value] == ["all"]):
                    return False
            elif not _empty(value):
                # targetObjects, inheritableSettings, enforcedSettings or anything else: it narrows or shifts the rule.
                return False
        return True
    return harmless


# The privileged_roles qualifiers: an extra field on a role, assignment or rule is ignored only when it is empty or shown
# to change nothing. A populated scope (``DirectoryScopeId`` other than ``/``, any ``AppScopeId``), a membership or status
# qualifier (``MemberType``, ``AssignmentType``, ``Status``), a rule ``Target`` that says more than the rule id, notification
# qualifiers (``NotificationLevel``, ``IsDefaultRecipientsEnabled``) or anything unknown withholds the section: the frozen
# shape cannot say that an assignment is scoped, so projecting it would read as tenant-wide.
ROLE_HARMLESS = {"Id": _any, "Description": _any, "IsBuiltIn": _any}
ASSIGNMENT_HARMLESS = {"Id": _any, "CreatedDateTime": _any, "ModifiedDateTime": _any, "CreatedUsing": _any,
                       "DirectoryScopeId": lambda value: value == "/"}


def _roles(bundle: Bundle) -> Any:
    # PIM policy Rules come only from a complete ProviderExport-shaped artefact (the ``identity_governance`` policy reads
    # write one), never from policy defaults.
    for collector, reads in PRIVILEGED_ROLES_READS.items():
        bundle.collector_health(collector, reads)
    result = []
    for row in bundle.normalised("privileged_roles"):
        _require(isinstance(row, dict), "$", "invalid_type")
        template = row.get("RoleTemplateId")
        # A role id that is this role's template id says nothing new; another one would attribute the row elsewhere.
        def same_role(value: Any) -> bool:
            return isinstance(value, str) and isinstance(template, str) and value.lower() == template.lower()
        # ``key`` is the normalized record's own identity (the bundle contract needs one); it is never projected.
        bundle.qualified_fields(row, {"DisplayName", "RoleTemplateId", "Assignments", "Rules", "key"}, "",
                                {**ROLE_HARMLESS, "TemplateId": same_role})
        item = _fields(row, {"DisplayName": _text, "RoleTemplateId": _text})
        for key in ("Assignments", "Rules"):
            _require(key in row, key, "missing_field")
            _require(isinstance(row[key], list), key, "invalid_type")
        _require(bool(row["Rules"]), "Rules")
        item["Assignments"] = []
        assignment_fields = {"PrincipalId": _text, "StartDateTime": _role_date, "EndDateTime": _role_date}
        for assignment in row["Assignments"]:
            bundle.qualified_fields(assignment, set(assignment_fields), "Assignments",
                                    {**ASSIGNMENT_HARMLESS, "RoleDefinitionId": same_role})
            _require("PrincipalId" in assignment, "Assignments.PrincipalId", "missing_field")
            item["Assignments"].append(_fields(
                assignment, {k: v for k, v in assignment_fields.items() if k in assignment}, path="Assignments"))
        item["Rules"] = []
        rule_fields = {"Id": _text, "RuleSource": _text, "RuleSourceType": _text,
                       "IsExpirationRequired": _boolean, "MaximumDuration": _text,
                       "NotificationRecipients": _strings, "NotificationType": _nullable_text,
                       "Setting": {"IsApprovalRequired": _boolean}}
        for rule in row["Rules"]:
            _require(isinstance(rule, dict), "Rules", "invalid_type")
            parts = rule.get("Id").split("_") if isinstance(rule.get("Id"), str) else []
            bundle.qualified_fields(rule, set(rule_fields), "Rules", {
                "Target": _rule_target(rule.get("Id")),
                # Notification_<Recipient>_<Caller>_<Level>: the recipient type the id already names.
                "RecipientType": lambda value: len(parts) == 4 and isinstance(value, str) and value.lower() == parts[1].lower()})
            for key in ("Id", "RuleSource", "RuleSourceType"):
                _require(key in rule, "Rules." + key, "missing_field")
            _require(_text(rule["Id"]), "Rules.Id", "invalid_type")
            if rule["Id"].startswith("Expiration_"):
                for key in ("IsExpirationRequired", "MaximumDuration"):
                    _require(key in rule, "Rules." + key, "missing_field")
            elif rule["Id"].startswith("Notification_"):
                _require("NotificationRecipients" in rule, "Rules.NotificationRecipients", "missing_field")
            elif rule["Id"].startswith("Approval_"):
                _require("Setting" in rule, "Rules.Setting", "missing_field")
            else:
                raise Unavailable(field="Rules.Id", kind="unseen_enum_value")
            if "Setting" in rule:
                # Approval stages, mode and justification say how and by whom a request is approved: unrepresented.
                bundle.qualified_fields(rule["Setting"], {"IsApprovalRequired"}, "Rules.Setting")
                _require("IsApprovalRequired" in rule["Setting"], "Rules.Setting.IsApprovalRequired", "missing_field")
            item["Rules"].append(_fields(rule, {k: v for k, v in rule_fields.items() if k in rule}, path="Rules"))
        result.append(item)
    return result


def _tenant(bundle: Bundle, manifest: dict[str, Any]) -> Any:
    identity = manifest.get("tenant_identity", {})
    _require(isinstance(identity, dict), "tenant_identity", "invalid_type")
    _require(identity.get("status") != "conflict", "tenant_identity.status")
    _require(not identity.get("conflicts"), "tenant_identity.conflicts")
    observed = set()
    for collector in ("identity", "domains_hybrid"):
        try:
            rows = bundle.operation(collector, "organization")
        except Unavailable as exc:
            if exc.reason != "missing_artifact":
                raise
            continue
        for row in rows:
            tenant = canonical_tenant_uuid(row.get("id"))
            _require("id" in row, "id", "missing_field")
            _require(tenant is not None, "id", "invalid_type")
            observed.add(tenant)
    recorded = canonical_tenant_uuid(manifest.get("tenant_id"))
    if recorded:
        observed.add(recorded)
    _require(len(observed) == 1, "tenant_id")
    return next(iter(observed))


# ``scuba_config`` is ScubaGear's operator configuration file, which no tenant read returns. It is synthesised from
# ScubaGear's default configuration, the cloud the tenant runs in and the operator's emergency-access list, in the shape
# each policy family's training rows carry (configs/scuba-policy-sections.json lists the 19 policies that read it):
#   AAD                {"Aad": null, "CapExclusions": <empty>, "RoleExclusions": <empty>}; MS.AAD.9.1v1 adds M365Environment.
#                      With an emergency-access list, the policies whose Rego honours an exclusion carry it under
#                      Aad[<entry the Rego reads>] (CapExclusions for SCUBA_CAP_EXCLUSION_POLICIES, RoleExclusions for
#                      MS.AAD.7.4v1; SCUBA_CONFIG_EXCLUSION_KEYS names the entries that differ from the policy id).
#   MS.EXO.1.1v2       null: no allowed forwarding domains, ScubaGear's default.
#   MS.TEAMS.*         {"M365Environment": <environment>}.
#   MS.SECURITYSUITE.* not collected (``operator_input_required``): their rows carry the operator's sensitive users and
#                      partner domains, an input Auditex does not take, and an empty list is a shape training never held.
# Each view passes the same shape gate as a collected section; one that fails is withheld for that policy alone.
SCUBA_CAP_EXCLUSION_POLICIES = frozenset({
    "MS.AAD.1.1v1", "MS.AAD.2.1v1", "MS.AAD.2.3v1", "MS.AAD.3.1v1", "MS.AAD.3.2v2", "MS.AAD.3.6v1", "MS.AAD.3.7v1",
    "MS.AAD.3.8v1", "MS.AAD.3.9v1"})
SCUBA_ROLE_EXCLUSION_POLICIES = frozenset({"MS.AAD.7.4v1"})
# The scuba_config entry a policy's Rego reads its exclusions from. MS.AAD.3.2v2 still reads Aad["MS.AAD.3.2v1"]
# (CISA finding F2; scripts/build-oracle-cases.py): an entry written under the v2 id would be ignored by the oracle.
SCUBA_CONFIG_EXCLUSION_KEYS = {"MS.AAD.3.2v2": "MS.AAD.3.2v1"}
SCUBA_ENVIRONMENT_POLICIES = frozenset({"MS.AAD.9.1v1"})
SCUBA_CONFIG_SOURCE = "synthesised:default-config"
_EMPTY_CAP = {"Applications": [], "Groups": [], "GuestUserTypes": [], "Users": []}
_EMPTY_ROLE = {"Groups": [], "Users": []}
# OpenID discovery: tenant_region_sub_scope "GCC" marks GCC; under the US Government scope (cloud instance
# microsoftonline.us) "DODCON" is GCC High and "DOD" is DoD. Any other US Government answer is ambiguous.
_US_GOV_SUB_SCOPES = {"DODCON": "gcchigh", "DOD": "dod"}
# Every discovery_status the public-footprint lookup writes (azure_tenant_audit/exposure_lookup.py); any other value is
# not a row the collector produced.
_DISCOVERY_STATUSES = frozenset({"ok", "skipped", "unreachable", "not_found", "http_error", "invalid_document"})


def _sku_environment(sku: str) -> str | None:
    """The US Government cloud a SKU is sold in; None for a commercial (or unmarked) SKU."""
    name = sku.upper()
    if "USGOV_DOD" in name:
        return "dod"
    if "USGOV_GCCHIGH" in name:
        return "gcchigh"
    if name.endswith(("_GOV", "_GCC")) or "_GOV_" in name:
        return "gcc"
    return None


def _environment(bundle: Bundle) -> tuple[str | None, str]:
    """ScubaGear's M365Environment for the tenant and the evidence it came from.

    The public OpenID discovery the ``dns_posture`` collector saves decides when it is present; without it, licence
    SKUs sold only in a US Government cloud do; a bundle with neither is taken as commercial (``assumed_default``).
    Fail closed: discovery or licence evidence that exists but cannot be read (a scan bound, malformed rows), an
    ``ok`` discovery answer without cloud fields, an instance outside the global and US Government clouds, and
    signals that disagree all return None (``unreadable`` or ``ambiguous``), and the environment-gated policies
    are withheld.
    """
    discovery: list[dict[str, Any]] | None
    try:
        discovery = [row for row in bundle.scan("dns_posture", "publicFootprint") if isinstance(row, dict)]
    except Unavailable as exc:
        if exc.reason != "missing_artifact":
            return None, "unreadable"
        discovery = None
    except (ValueError, TypeError, KeyError):
        return None, "unreadable"
    if discovery is not None:
        found: set[str | None] = set()
        for row in discovery:
            fields = {k: row.get(k) for k in ("discovery_status", "tenant_region_scope", "tenant_region_sub_scope",
                                               "cloud_instance_name")}
            if (fields["discovery_status"] not in _DISCOVERY_STATUSES
                    or any(v is not None and not isinstance(v, str) for v in fields.values())):
                return None, "unreadable"  # not a row the collector writes: an unknown status or a field of the wrong type
            if fields["discovery_status"] != "ok":
                continue
            scope = (fields["tenant_region_scope"] or "").lower()
            sub = (fields["tenant_region_sub_scope"] or "").upper()
            instance = (fields["cloud_instance_name"] or "").lower()
            gov_scope = scope in {"usgov", "usg"}
            if instance not in {"", "microsoftonline.com", "microsoftonline.us"}:
                found.add(None)  # China (partner.microsoftonline.cn) or another sovereign cloud: no ScubaGear value
            elif not scope and not instance:
                found.add(None)  # an answer without cloud fields says nothing about the cloud
            elif scope and instance and (instance == "microsoftonline.us") != gov_scope:
                found.add(None)  # the region scope and the cloud instance disagree
            elif gov_scope or instance == "microsoftonline.us":
                found.add(_US_GOV_SUB_SCOPES.get(sub))
            else:
                found.add("gcc" if sub == "GCC" else "commercial")
        if found:
            return (found.pop(), "openid_discovery") if len(found) == 1 and None not in found else (None, "ambiguous")
    skus: set[str | None] = set()
    try:
        for row in bundle.scan("licensing", "subscribedSkus"):
            sku = row.get("skuPartNumber") if isinstance(row, dict) else None
            if not isinstance(sku, str) or not sku:
                return None, "unreadable"  # a licence row without a SKU is not a row the collector writes
            skus.add(_sku_environment(sku))
    except Unavailable as exc:
        if exc.reason != "missing_artifact":
            return None, "unreadable"
    except (ValueError, TypeError, KeyError, AttributeError):
        return None, "unreadable"
    skus.discard(None)
    if skus:
        return (skus.pop(), "licence_sku") if len(skus) == 1 else (None, "ambiguous")
    return "commercial", "assumed_default"


def _break_glass(bundle: Bundle, manifest: dict[str, Any]) -> tuple[dict[str, list[str]] | None, dict[str, Any]]:
    """The operator's emergency-access list as ScubaGear exclusions: object IDs of users and groups.

    Entries resolve as ``--break-glass-accounts`` does (``break_glass.resolve_accounts``) against the full user and
    group lists the run read. An object ID found in neither is kept as a user, as ScubaGear takes it unverified. An
    entry that cannot be resolved, an unreadable identity list or a run that did not record its list returns None:
    a partial exclusion list would judge an exempted account as a gap.
    """
    from azure_tenant_audit import break_glass

    parameters = manifest.get("rule_parameters")
    entries = parameters.get("break_glass_accounts") if isinstance(parameters, dict) else None
    if not isinstance(entries, list) or not all(isinstance(e, str) and e for e in entries):
        return None, {"source": "unrecorded"}
    if not entries:
        return {"Users": [], "Groups": []}, {"source": "none"}
    keys = {entry.lower() for entry in entries}

    def wanted(row: dict[str, Any]) -> bool:
        return any(str(row.get(k) or "").lower() in keys for k in ("id", "userPrincipalName", "mail", "displayName"))
    try:
        users = [row for row in bundle.scan("identity", "users") if wanted(row)]
        groups = [row for row in bundle.scan("identity", "groups") if wanted(row)]
    except Unavailable:
        return None, {"source": "operator", "entries": len(entries), "state": "identity_unreadable"}
    accounts = break_glass.resolve_accounts(entries, users=users, groups=groups, role_assignments=(), role_definitions=())
    summary = {"source": "operator", "entries": len(entries), "unresolved": len(accounts.unresolved),
               "unverified": len(accounts.unverified)}
    if accounts.unresolved:
        return None, {**summary, "state": "unresolved"}
    group_ids = {str(g["id"]).lower() for g in groups if g.get("id")}
    result = {"Users": sorted(i for i in accounts.ids if i not in group_ids), "Groups": sorted(accounts.ids & group_ids)}
    return result, {**summary, "state": "resolved", "users": len(result["Users"]), "groups": len(result["Groups"])}


def _scuba_config(bundle: Bundle, manifest: dict[str, Any], catalogue: dict[str, Any],
                  max_items: int, max_chars: int) -> tuple[Any, dict[str, Any], dict[str, Any]]:
    """The default ``scuba_config``, a per-policy view for each policy that reads it, and the synthesis record."""
    bundle.sources.append("run-manifest.json")
    environment, environment_basis = _environment(bundle)
    exclusions, break_glass_summary = _break_glass(bundle, manifest)
    base = {"Aad": None, "CapExclusions": deepcopy(_EMPTY_CAP), "RoleExclusions": deepcopy(_EMPTY_ROLE)}
    views: dict[str, Any] = {}
    outcomes: dict[str, str] = {}
    for policy_id in sorted(p for p, entry in catalogue.items() if "scuba_config" in entry["sections"]):
        family = policy_id.split(".")[1]
        try:
            if family == "AAD":
                view = deepcopy(base)
                if policy_id in SCUBA_ENVIRONMENT_POLICIES:
                    if environment is None:
                        raise Unavailable("environment_ambiguous")
                    view["M365Environment"] = environment
                honours = "CapExclusions" if policy_id in SCUBA_CAP_EXCLUSION_POLICIES else \
                    "RoleExclusions" if policy_id in SCUBA_ROLE_EXCLUSION_POLICIES else None
                if honours:
                    if exclusions is None:
                        raise Unavailable("break_glass_unresolved")
                    if exclusions["Users"] or exclusions["Groups"]:
                        entry = {"CapExclusions": deepcopy(_EMPTY_CAP), "RoleExclusions": deepcopy(_EMPTY_ROLE)}
                        entry[honours].update(Users=list(exclusions["Users"]), Groups=list(exclusions["Groups"]))
                        view["Aad"] = {SCUBA_CONFIG_EXCLUSION_KEYS.get(policy_id, policy_id): entry}
            elif policy_id == "MS.EXO.1.1v2":
                view = None
            elif family == "TEAMS":
                if environment is None:
                    raise Unavailable("environment_ambiguous")
                view = {"M365Environment": environment}
            elif family == "SECURITYSUITE":
                raise Unavailable("operator_input_required")
            else:
                raise Unavailable()
            _seen_shape("scuba_config", view)
            if _oversize(view, max_items, max_chars):
                raise Unavailable("oversize")
        except Unavailable as exc:
            views[policy_id] = dict(NOT_COLLECTED)
            outcomes[policy_id] = "unseen_shape" if exc.reason == "incomplete_shape" else exc.reason
        else:
            views[policy_id] = view
            outcomes[policy_id] = "projected"
    synthesis = {"source": SCUBA_CONFIG_SOURCE, "basis": "scubagear_default_config",
                 "m365_environment": {"value": environment, "basis": environment_basis},
                 "break_glass": break_glass_summary, "policies": outcomes}
    if "projected" not in outcomes.values():
        raise Unavailable()
    return base, views, synthesis


def policy_section(projection: dict[str, Any], policy_id: str, section: str) -> Any:
    """The evidence one policy sees for a section: its own view where the projection keeps one, else the section."""
    views = getattr(projection, "views", None) or {}
    if section in views.get(policy_id, {}):
        return views[policy_id][section]
    if section == "scuba_config" and hasattr(projection, "views"):
        # A policy without a projected synthesis cannot inherit the base config.
        return dict(NOT_COLLECTED)
    return projection.get(section, dict(NOT_COLLECTED))


def rule_policy_section(projection: Projection, policy_id: str, section: str) -> Any:
    """Read a policy's private rule evidence without exposing it in a model case."""
    if section == "scuba_config":
        return projection.rule_views.get(policy_id, {}).get(section, dict(NOT_COLLECTED))
    return projection.rule_sections.get(section, dict(NOT_COLLECTED))




# Area adapter modules (src/auditex/scuba_adapters_<area>.py), each exposing ADAPTERS: dict[str, Callable].
# New model-view sections need PACK_SHAPE_DIGESTS entries (and enum domains where relevant), a shared hunk;
# rule-only sections do not. scubagear_export.py does not call project_run, so these adapters never apply there.
AREA_ADAPTER_MODULES: tuple[str, ...] = (
    # One module per line (keeps merges of the area branches small): "auditex.scuba_adapters_<area>",
    "auditex.scuba_adapters_exchange",
    "auditex.scuba_adapters_teams",
    "auditex.scuba_adapters_defender",
    "auditex.scuba_adapters_powerplat",
)

PS_SECTIONS = {
    "accepted_domains": ("exchange_policy", "acceptedDomains", {"Name": _text, "DomainName": _text}),
    "dkim_config": ("exchange_policy", "dkimSigningConfig", {"Domain": _text, "Enabled": _boolean}),
    "transport_config": ("exchange_policy", "transportConfig", {"Name": _text, "SmtpClientAuthenticationDisabled": _boolean}),
    "org_config": ("exchange_policy", "organizationAuditConfig", {"Identity": _text, "Name": _text, "AuditDisabled": _boolean}),
    "meeting_policies": ("teams_policy", "meetingPolicies", {
        "Identity": _text, "AllowAnonymousUsersToStartMeeting": _boolean, "AllowCloudRecording": _boolean,
        "AllowExternalParticipantGiveRequestControl": _boolean, "AllowPSTNUsersToBypassLobby": _boolean,
        "AutoAdmittedUsers": _text}),
}


def _powershell(bundle: Bundle, section: str) -> Any:
    collector, operation, fields = PS_SECTIONS[section]
    try:
        rows = bundle.operation(collector, operation)
    except Unavailable as exc:
        if exc.reason == "missing_artifact":
            try:
                normal = bundle.normalised("teams_policy_objects" if collector == "teams_policy" else "exchange_policy_objects")
            except Unavailable as normal_exc:
                if normal_exc.reason != "missing_artifact":
                    raise
                raise Unavailable("powershell_only") from None
            bundle.coverage(collector, operation)
            rows = [r for r in normal if r.get("source_name") == operation]
            if not rows:
                raise Unavailable("powershell_only") from None
        else:
            raise
    result = []
    for row in rows:
        item = _fields(row, fields)
        bundle.known_fields(row, set(fields) | {"source_name", "key", "kind"})
        result.append(item)
    return result


def _dns(bundle: Bundle, section: str, manifest: dict[str, Any]) -> Any:
    # Parsed dns_posture summaries cannot reconstruct all TXT answers: the section needs the complete answers saved as
    # their own operation, which the collector does not write today. A missing operation says which of the two it is.
    try:
        rows = bundle.operation("dns_posture", section)
    except Unavailable as exc:
        if exc.reason != "missing_artifact":
            raise
        ran = "dns_posture" in (manifest.get("selected_collectors") or manifest.get("collectors") or [])
        raise Unavailable("dns_records_not_saved" if ran else "dns_posture_not_run") from None
    result = []
    for row in rows:
        allowed = {"domain": _text, "doamin": _text, "rdata": _strings, "compliant": _boolean, "message": _text,
                   "log": _any}
        bundle.known_fields(row, set(allowed))
        item = _fields(row, {k: v for k, v in allowed.items() if k in row})
        result.append(item)
    return result


def _user_entries(users: Any) -> None:
    """The fields ``_redact`` reads from every privileged user, held by each entry. The pack admits a ``User<n>`` map
    that mixes an entry without ``OnPremisesImmutableId`` and one with a null (a training witness); ``_users`` never emits
    one, and a missing key is not a null to the Rego, so such a map withholds rather than projects."""
    _require(isinstance(users, dict), "$", "invalid_type")
    for name, item in users.items():
        _require(isinstance(item, dict), name, "invalid_type")
        _require("DisplayName" in item, name + ".DisplayName", "missing_field")
        _require(_text(item["DisplayName"]), name + ".DisplayName", "invalid_type")
        _require("OnPremisesImmutableId" in item, name + ".OnPremisesImmutableId", "missing_field")
        _require(_nullable_text(item["OnPremisesImmutableId"]), name + ".OnPremisesImmutableId", "invalid_type")


def _oversize(value: Any, max_items: int, max_chars: int) -> bool:
    def exceeds(item: Any) -> bool:
        if isinstance(item, list):
            return len(item) > max_items or any(exceeds(v) for v in item)
        if isinstance(item, dict):
            return any(exceeds(v) for v in item.values())
        return False
    return (exceeds(value) or isinstance(value, dict) and len(value) > max_items or len(_json(value)) > max_chars)


_EMAIL = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")


def _redact(projection: Projection, salt: str, enabled: bool) -> dict[str, Any]:
    counts = {"user_display_names": 0, "email_addresses": 0, "immutable_ids": 0}
    def pseudonym(text: str) -> str:
        return sha256((salt + "\0" + text).encode()).hexdigest()[:16]
    def emails(value: Any) -> Any:
        if isinstance(value, str):
            def mask(match: re.Match) -> str:
                counts["email_addresses"] += 1
                return "***@" + match[1]
            return _EMAIL.sub(mask, value)
        if isinstance(value, list):
            return [emails(v) for v in value]
        if isinstance(value, dict):
            return {k: emails(v) for k, v in value.items()}
        return value
    if enabled:
        users = projection.get("privileged_users", {})
        if users != NOT_COLLECTED:
            for item in users.values():
                item["DisplayName"] = "User " + pseudonym(item["DisplayName"])
                counts["user_display_names"] += 1
                if item["OnPremisesImmutableId"] is not None:
                    item["OnPremisesImmutableId"] = "Id " + pseudonym(item["OnPremisesImmutableId"])
                    counts["immutable_ids"] += 1
        for key in projection:
            projection[key] = emails(projection[key])
        for views in getattr(projection, "views", {}).values():
            for key in views:
                views[key] = emails(views[key])
    return {"enabled": enabled, "strategy": "run-salted-sha256-v1", **counts}


def project_run(run_dir: str | Path, *, redact: bool = True,
                max_items: int = DEFAULT_MAX_ITEMS, max_chars: int = DEFAULT_MAX_CHARS,
                scan_max_rows: int = DEFAULT_SCAN_MAX_ROWS, scan_max_bytes: int = DEFAULT_SCAN_MAX_BYTES,
                scan_max_chunks: int = DEFAULT_SCAN_MAX_CHUNKS) -> Projection:
    """Read a bundle without writes; manifest digest supplies a stable per-run salt.

    The salt stays in memory and is never persisted. ``max_items`` and ``max_chars`` budget the projected
    section itself, before and after redaction and enum annotation, including nested lists and user
    dictionaries; they do not limit how much source a section is built from. The scan bounds do that: a
    source read that exhausts one withholds the section as ``oversize`` (detail kind ``scan_bound``).
    """
    bounds = {"max_items": max_items, "max_chars": max_chars, "scan_max_rows": scan_max_rows,
              "scan_max_bytes": scan_max_bytes, "scan_max_chunks": scan_max_chunks}
    if any(type(value) is not int or value < 1 for value in bounds.values()):
        raise ValueError("Projection bounds must be positive integers")
    bundle = Bundle(Path(run_dir).resolve(), scan_max_rows, scan_max_bytes, scan_max_chunks)
    manifest_error: Unavailable | None = None
    try:
        manifest = bundle.read("run-manifest.json")
        _require(isinstance(manifest, dict))
        # The redaction salt is the digest of the canonical manifest; one that cannot be serialised (``1e999``, a lone
        # surrogate) is unusable, so it takes the same path as an unparseable manifest rather than raising later.
        try:
            salt = sha256(_json(manifest).encode()).hexdigest()
        except (ValueError, UnicodeError, TypeError, RecursionError):
            raise Unavailable() from None
    except Unavailable as exc:
        manifest_error = None if exc.reason == "missing_artifact" else exc
        manifest = {}
        salt = sha256(_json(manifest).encode()).hexdigest()
    bundle.manifest = manifest
    from azure_tenant_audit.scuba_precheck import optional_collection_entry
    optional = optional_collection_entry()
    selection = manifest.get("selected_collectors", manifest.get("collectors"))
    collector_names = json.loads(open_text_resource("configs/collector-definitions.json"))["collectors"]
    omitted_sections = set()
    # Probe manifests also list surfaces; they do not describe a run's collection opt-in.
    # Only unique canonical registry names establish selection; ambiguous metadata stays unknown.
    if (isinstance(selection, list) and selection
            and all(isinstance(s, str) and s in collector_names for s in selection)
            and len(selection) == len(set(selection))
            and manifest.get("executed_by") != "auditex_probe" and "probe_mode" not in manifest):
        omitted_sections = {s for policy in optional["policies"].values()
                            if policy["collector"] not in selection for s in policy["sections"]}
    catalogue = json.loads(open_text_resource("configs/scuba-policy-sections.json"))["policies"]
    sections = sorted({s for p in catalogue.values() for s in p["sections"]})
    result = Projection()
    result.views = {}
    result.rule_sections = {section: dict(NOT_COLLECTED) for section in set(sections) | RULE_ONLY_SECTIONS}
    result.rule_views = {}
    report = {}
    synthesis = None
    adapters = {"SPO_tenant": _spo, "conditional_access_policies": _ca, "authorization_policies": _authorization,
                "service_plans": _plans, "privileged_users": _users, "privileged_roles": _roles}
    import importlib

    valid_sections = set(sections)
    reserved_sections = {"scuba_config", "tenant_id"}
    registered_sections = adapters.keys() | PS_SECTIONS.keys() | {"dmarc_records", "spf_records", "dkim_records"}
    for name in AREA_ADAPTER_MODULES:
        mod = importlib.import_module(name)
        if not hasattr(mod, "ADAPTERS"):
            raise RuntimeError(f"Area adapter module {name!r} has no ADAPTERS")
        area_adapters = mod.ADAPTERS
        if not isinstance(area_adapters, dict):
            raise RuntimeError(f"Area adapter module {name!r} ADAPTERS must be a dict")
        for key, adapter in area_adapters.items():
            if key in reserved_sections:
                raise RuntimeError(f"Area adapter module {name!r} has reserved adapter key: {key!r}")
            if key not in valid_sections:
                raise RuntimeError(f"Area adapter module {name!r} has unknown adapter key: {key!r}")
            if not callable(adapter):
                raise RuntimeError(f"Area adapter module {name!r} has non-callable adapter for key: {key!r}")
        collisions = registered_sections & area_adapters.keys()
        if collisions:
            raise RuntimeError(f"Area adapter module {name!r} has duplicate adapter keys: {sorted(collisions)}")
        adapters.update(area_adapters)
        registered_sections.update(area_adapters)
    for section in sections:
        bundle.reset()
        try:
            if manifest_error is not None:
                raise manifest_error
            if manifest.get("platform", "m365") != "m365":
                raise Unavailable("not_applicable_to_platform")
            if section == "scuba_config":
                if not manifest:
                    raise Unavailable("missing_artifact")  # no run manifest, no run to synthesise a configuration for
                value, views, synthesis = _scuba_config(bundle, manifest, catalogue, max_items, max_chars)
            elif section == "tenant_id":
                bundle.sources.append("run-manifest.json")
                value = _tenant(bundle, manifest)
            elif section in adapters:
                value = adapters[section](bundle)
            elif section in PS_SECTIONS:
                value = _powershell(bundle, section)
            elif section in {"dmarc_records", "spf_records", "dkim_records"}:
                value = _dns(bundle, section, manifest)
            else:
                raise Unavailable("missing_artifact")
            # A complete, explicitly empty source collection is known empty.
            # Missing/failed sources have already raised and cannot reach here.
            _require(value is not None)
            if value in ([], {}):
                _require(bundle.complete)
            users_ok = True
            if section == "privileged_users":
                try:
                    _user_entries(value)
                except Unavailable:
                    users_ok = False
            # Redaction rewrites privileged users in place. Other model sections
            # are replaced, and serving copies only a rule's own read set.
            if users_ok:
                result.rule_sections[section] = deepcopy(value) if section == "privileged_users" else value
            if section == "scuba_config":
                for policy_id, view in views.items():
                    result.rule_views.setdefault(policy_id, {})[section] = view
            if section in {"dmarc_records", "spf_records", "dkim_records"}:
                # Resolver diagnostics are rule-only, as on the export path's pre-prune capture.
                value = [{k: v for k, v in row.items() if k != "log"} for row in value]
            _seen_shape(section, value)
            if section == "privileged_users":
                _user_entries(value)
            if _oversize(value, max_items, max_chars):
                raise Unavailable("oversize")
        except (Unavailable, ValueError, TypeError, KeyError, OverflowError) as exc:
            result[section] = dict(NOT_COLLECTED)
            reason = getattr(exc, "reason", "incomplete_shape")
            if reason == "missing_artifact" and section in omitted_sections:
                reason = optional["reason_code"]
                # Only the private rule view carries the cause. Prompt evidence remains the exact marker.
                result.rule_sections[section] = {**NOT_COLLECTED, "reason": reason}
            detail = getattr(exc, "detail", {"field": "$", "kind": "unseen_shape"})
            report[section] = {"status": "not_collected", "reason": reason, "source": list(bundle.sources)}
            # A projected-object bound is plain ``oversize``; the scan bounds say which one ran out.
            if reason in {"incomplete_shape", "collector_error"} or reason == "oversize" and detail.get("kind") == "scan_bound":
                report[section]["detail"] = detail
            if getattr(exc, "unsupported", None):
                report[section]["unsupported_conditions"] = exc.unsupported
        else:
            result[section] = value
            report[section] = {"status": "projected", "reason": None, "source": list(bundle.sources)}
            # What a Conditional Access projection dropped or normalised; a withheld section has no complete record.
            if bundle.dropped_conditions:
                report[section]["dropped_conditions"] = sorted(bundle.dropped_conditions)
            if bundle.null_lists:
                report[section]["null_lists_read_as_empty"] = sorted(bundle.null_lists)
            if section == "scuba_config":
                # Policy views reach prompts only once the section itself passed the gates above; a withheld
                # section leaves every reader on the not_collected marker the report describes.
                for policy_id, view in views.items():
                    result.views.setdefault(policy_id, {})[section] = view
                report[section]["synthesis"] = synthesis
        counts = bundle.scan_counts
        if counts["rows"] or counts["bytes"]:
            report[section]["scan"] = counts
        if bundle.ignored:
            report[section]["ignored_failures"] = sorted(bundle.ignored)
        if bundle.ignored_fields:
            report[section]["ignored_fields"] = sorted(bundle.ignored_fields)
    redaction = _redact(result, salt, redact)
    for section, value in result.items():
        if value != NOT_COLLECTED and _oversize(annotate_enum_names(section, value), max_items, max_chars):
            result[section] = dict(NOT_COLLECTED)
            report[section].update(status="not_collected", reason="oversize")
            # A withheld section carries no Conditional Access record (output-contract.md; the validator rejects one).
            # scuba_config's ``synthesis`` cannot get here: its value is the constant, string-free base object, which
            # redaction cannot grow and enum annotation does not touch, so the check above already passed it.
            report[section].pop("dropped_conditions", None)
            report[section].pop("null_lists_read_as_empty", None)
    result.report = {"schema_version": PROJECTION_VERSION, "sections": report, "redaction": redaction,
                     "bounds": bounds}
    return result


# Generated from complete v7 train/test objects; the fixture pins each digest
# to a source file hash, row number and evidence ID. Never union sparse paths.
PACK_SHAPE_DIGESTS = {'SPO_tenant': ['0431dbf090672152543d23384d46908c3a61402eb96cdab7f7196e19a7f6e51d',
                '047f3c221dd7b73d95d5c060aaabe80c3b96e2eed3d2996e8bfecc45162c33ba',
                '09ed20ece76dbe2ca2118fea9e6bf24de0657416f42678a2b2c8063cc8fe74b2',
                '0de38489604e0d66c66a7cb7a5426cde8fc13ab0032e301fa44f2d4ef28933b1',
                '52c3e827ed5d2682e0de163c3f130e3941df2ebed94cc580275c1a3b35672df1',
                '6e59c69226f3b212dff62231168516863c08fd75dc09ef75c9ccf9c51adb9442',
                '718222e62485098065163aa1c5f5e7412b145c3b763d11b7924d53746d986f06',
                '74e3bd6f36eb9cd41aa1971d538ab134048cfb30d9d7647580c8f2fed52f57c0',
                '8290e17678d11cbaaeb40d06ba64673ad4e379615ece9259c1cd4ded0291939e',
                '86b2382049fd823a68677dffadb5913cc0ff50c072d1e2baedc6481c2ff0081f',
                'a496895d274b1867e2b98f00219b75f1eb6aed717de5a1f50c71415a815490ae',
                'b2822f7835e9ec73fe8dc3bf731d8d0dbb4a3b246814634499399aa4aa72b47f',
                'bba8990d77dd449ec537975d16c26f6f3adcca460aafdf68c2e288e438f8e6c4',
                'c14f2e997d976371b33d12e711febed9be05218a051a5df03f820a35ae346482',
                'e300fb59bf985850acccb24e13f34450215ed0e8f631ebdc736638422e9d6fcc',
                'eac1565e041bd480423f09a9fb0ec4341fb2cbb2c9e92c0b6ed1e5182df28d3f'],
 'accepted_domains': ['49f477bb14284f2dc7b68efe2242d2ec4be1f5e6ca864bd52d62f1a2e50bc48b'],
 'authorization_policies': ['015eb674092ed1463dbc8e1f86bd0851bd204f870d00fc6cdcdb842a625ecd92',
                            '068b8e0b4cdaa3faa9e1c0605e947e46396789b61dbfd0cb228ea25f03bbbf58'],
 'conditional_access_policies': ['01b39c4c1e3a5f0e28288d6175580170ece3185c5bc0db7f192d8dbc631b666d',
                                 '025acfac75b10f2d2e5e30634558299a88109bf5029fc98f6d1857a9987657a4',
                                 '04cbc6ea5ca205d53fc2d389b8dcafbd399fdca15e86ca571f23eb47b9d7ecf6',
                                 '05faa53dd245a34bf4c452262531bcb23bd42362770e0efee5f9fce2daf30bce',
                                 '062555d577cd1ca56724cbe87441e727d4d51fd0a4ec793fec5e2d3897225fb6',
                                 '0640a5a30bfaf724bff4ee035ea03fd07225c2fb2d328ca28abf708708991163',
                                 '075cd3128a9f80c9f3ffd9ad947a2d50a1461b9466ff4138d9c46a12ebdd84b7',
                                 '07fd467dc40b7a81cf6e1c1107ad30771e4b2ef8271380dc93f24e3948382b1b',
                                 '0875c0f8a4fe0e5671e6eb674896a39ebead43142ad46b507b5454b8a2ede236',
                                 '0a14117f25dce0e0383301158dfb4cfb6638b887a7deac2accea47f8eff1511b',
                                 '0ab34c147d904448cdd03b51f49785a32815bdc0c59744f656b8d9d7fed6c260',
                                 '0ae8026975ac872c52e0880e503016a5dbe71d3dfceca1496fc281959bba0c49',
                                 '0b296ea2625fa0e9dbd80c86ff31a991ef826934d26376276d3fcf311e59facc',
                                 '0da721ca0767e5d960e12aa855cd606e3139955c7aa92fb2c8fb034c43c136ac',
                                 '0e79f8d612d46a0e8326477f01b9f36f9d4f37822011293350611397a90e0001',
                                 '10c1a3ec8d50a04bed4221c18b7828516f46f064be0155dfae1b3a2be938e82e',
                                 '10c288239dbe668971b7db4e55050949426ec5c0cdbf76286dab4700d588ac34',
                                 '1201718f354646036c49ea02ba6595c722c0c9099d7976de326791b96f235d8f',
                                 '12fbd5edf70052ec0cc64072bfb5d11c294ac76551464308926dc35a4c293eef',
                                 '132e9dd02c56c7cefe5abdecfbbce0a3ec1520284884865949e14d2e45a3b67d',
                                 '14c124497154649df31bde9ad45fc6ba925dbab308d55ad9250effb40b1f21ed',
                                 '153504a8d1ea0e3e17ddc407654886c36ecaff57b41f8d5a820dbbaade9b4939',
                                 '156a343969452e1729b8f41f15f8ddefebeb1ee25ee414f589ec9bd2a2f72222',
                                 '15d2ab9e1a10f36d7cec0523d98efc4e6314c09e1eabcc663dfe309405404111',
                                 '164ad45a085b64e70b68314670f5048713a90ae3ad7568a98760c056b336a701',
                                 '17b1b9f8a5eb252e164d56fdaf3eea85767adffdc8614f87bc237a8bab96a2dd',
                                 '17e850d79d7b2e81f1b6d5f7f3e63a6d3d2a84cb61a2d57bac3743c48b907e17',
                                 '18e1183793c1539e255b89acf036c8bd5fe3a5d092103738634e5211c7d29a8e',
                                 '1adcbc0cfbaf7fc742051e05cc4b1de33d8236eb50d45919893909b6ef7b77d0',
                                 '1c70bb4897f422c6e4266d686f5de83992c760c985dfff3b771facdfa039220f',
                                 '1da2653146ff3c21ec25fb9eb58bc10e187ca6e8a07260858706ba36f68a5e68',
                                 '1e6b805e5556afa6afcc067027cde36fe7fea702ea435628cc923c4b5a28a32d',
                                 '22b3a683404dcbc0143210720573904768e0ec5f3c010c2f444ca9fce85f4e7d',
                                 '23af47e609ad53896ffcd0b6ab1b78b3ed80cf96af11ca540687dc363696a920',
                                 '2960a620f6c44a158becc7574d04b591c847257587de96fd84e6f0571f89ef16',
                                 '2ab5d02bd108d5103abaf56662cb89f4a9ba6597d414793ec8aed56dc0954192',
                                 '2b57c0b4f6a9e6da8e0b8e6ed67cb0b182e5630c13831f5ce17572c557fdaa60',
                                 '2c80e62eba201143e972ebd19113a0b12e26f93efb44e4cc71d6924b23461b32',
                                 '2f4ab3b89874a8d54cd6a572d8df2754da0f5eabac2d62156ccd1e2fd535441c',
                                 '2fa9234e33a6a477f6f71a3f227b9f2252e7617e65b9f13a0cb0afc8eef0f8f3',
                                 '2ff3013133bf8de1bd73082a70269542a19a2fb98308ef657552167ea3cdd6d2',
                                 '30af91e42a2bf175492299efa1d1761706c97f6efde4c6638ae0bbb6afda2795',
                                 '330d0c2e4cb7f1a762e63ff94e9ee3f14718b3918920417849d57a6d886145ff',
                                 '33b681f1e91220b8ef9226fca18e082b83a5d046daa832877de90ed4c3f5b2df',
                                 '3453e0dad3b51a87d7af1af0ee72daba3ad04eed754f978b36a98436c5c1e9a9',
                                 '34f2cbd0293d7bcf97eeca254e46a735c907c04b0cb531a70121c08b40e9e2c3',
                                 '3a6db640dc9cd9a62874f85b0582f7f99b36155ef9574db64b98fa4436223bfc',
                                 '3ba5eb79b18f7ccd635becd594f132e1f89a13ee4879e1622bcb787a5f0e7453',
                                 '3c81ac1df51ce9602380c58fc2e862fdbde84311758b9b4681b1c3cc2ba28838',
                                 '3d6400e71fa42aaffa24e0278e8c9c15ad90e839ef42e746dc7fa53b64ccda61',
                                 '3e084183dda700a81b400c7d75cf0b890fd980b63df0ac8ee1420bfbb3291076',
                                 '3f7588b5016b754c54457dedd7a7cfa2c144724f7c69450367005cc370e6904d',
                                 '3fbfcabfc4df31142d48bc8532c4b53d7bfa2b5bc9685a4c6fc87789e0000dcc',
                                 '3ff71a63412f2148451770c804d06eef8015557bfbb1644010ec7f7e207b9ffd',
                                 '41097905308c8e125f6d23ff289ee890697af1fc492560d3d7a3bbb750617ed3',
                                 '42e1b5cb6a14984272a932aea8adba69ecaaf3db33e6bdad8b841543288197aa',
                                 '4442bb136b7443e9b206ef631ea9a5d0752448bf88b3376fd66d6fa9aca18675',
                                 '44c564ec0ddcca34a888e0f4f6f685fa8b93d9f9e5a2897aa6f550198f6b7ce9',
                                 '49450e5a2be4e7c3263494b3812defa22f6ea3bf4e7c32c5ded16619fa591493',
                                 '4b79cf7c0d58c9d0795d922e73584511d8fd3701fe59d63cd0f95403cd2909d9',
                                 '4c4b885f0c0030eea16fac8c3ca79ca9299503a16d7380b63ec951d4110ecdca',
                                 '4efcb3b6aed645ab9b3218e3000bf475bc09e87901457b69cca49c80a2649094',
                                 '4fa32d0126213d2c8b51ba3467c3dda601f35f7b7737948240a598a46917c5b5',
                                 '5007da18b0c2e415baf1a02eedb7519afe6ab999b448c68a60bfce7ef9599770',
                                 '51544443b6f0a8ffe0f755dd075a82cac2a67d3528ea18ce4015ac73dfaa6be3',
                                 '52348fc1fcf836e30b1a8167b48d5d5cb2ea4aeef34896887938b101a35826dd',
                                 '5331cf461a98df528d2c431a7b208bbe799ee765b309be93377ba2f9de1e515f',
                                 '53ea58bbf2c0405919c41f835395ac5fc645dd1f536b5f87b39abf32f2bd5639',
                                 '55eb900d6d5f84adca0355dae5a1c767c5804dae2c8fc87c69cd96b4e504b6f3',
                                 '5678e3b0971ac1de446f2ad0f46fcda4644173c7f86fb52acde012d9c2cf2766',
                                 '56eab463268240f94a2601605d75b93348e89a3024f9aee230702172eeeb5ac9',
                                 '5725ed7a7193a00c414e33960bfa5570ee3187208e556cc5a1d65e5a8830590d',
                                 '5968fd59c774f360677227fd6c7ab0a78f5bed5cfd309f0f9439871e4e071a80',
                                 '59f66b291371a75a5d42ff07f3d51767ba757db94ab983272a776284cb049fbe',
                                 '5bb429b7b5b250f0709b5512e4bb871321dff2454294ffb13a8c9bcf8eb57be3',
                                 '5c271268057d4d33f569d8facaa4dbd335de5828f9f68d4556f71a970deca03f',
                                 '5d52d525bc5847c269eefeecf7425ad5703df399bad6b92c17378e9954532475',
                                 '5d83188931175a2b93e18cb0a06cdf0c8992414e25d713d149b1d82ab7355964',
                                 '5e543a11a113b989d7ce5f1cb450f63716f4a8bd66fd9dbf1bec31e3b08007fa',
                                 '5e9c0b438eca0dfb552fa4fdff7356202d8729dcfc40597c02b35023480d587c',
                                 '5eb2fc89f10d2886773f7acabc39d45c4fbafc3351d8aabd277afe1f4af3053e',
                                 '5f1653091add8d17e322c058f413fa80813079e266f1a1e389421e17a20bd98b',
                                 '5fcce409bf760ba7c07c7ad8e30710d8d545b78c56790e95a47e9846ba952e4d',
                                 '5fe0895262149a97d2e876d6da5ecfa865084d63a8687446799077a77ad37023',
                                 '60732f0bd0c0bcc9c86585ca37241f25f08177c476a18300a82e6b936c8cd032',
                                 '6092cd804a51081bd7df2c1a1d8e78e2db0868171c17b069e8395aa5bd86d470',
                                 '621495a8d8b455d8a59ec3470647453304caa0681d444972f4a2c05b5e5a34d5',
                                 '63158a3d30409a2c3d3fef705ec0764f0a6486582071ecd3e85be7c671ff7e16',
                                 '6348917b3a1b95542be65d62c94c964fa15301d8bc75cfbf5a03eb53e7bfee1f',
                                 '635ff80766cb66c53ca74d8b51623229f3f28ae4070437008537910f406ede72',
                                 '63997d48e995012e22d5ad7c67e691318e9ccea234e6a9bb57b1ead2b69096d4',
                                 '659ac893678e9c6695006741458cb08ad3bc14669d5b017baa3cfb537d12b852',
                                 '65da2cc7e78c1f365e25b731d392bcc512705518d3ebb341549af239b3eee7da',
                                 '66f1e785eb33839a3ca4d6a9a7cedbbaaf4dc3765ee82f60f5530dce28efdb7a',
                                 '6742f7f3252f3936065a99b6aba207f3e33f5c20c00eb42ada2b1a4003b81226',
                                 '67c572e388285b21990c4db9248c28be8a17d4f6cb1b2cf32428ae1faf39e76c',
                                 '683a3ea553ffa2bc05b0678d780970ecec84ba0b17de8d216a784c62e1b67313',
                                 '68612bc65d8031aa7ff5038a758fdbb9695d4641a8b96058c210f28b7824f10a',
                                 '68c7f742a8d7134168adebc828c15289231b85b9f48bf8f5d5c56e71aa7ce06b',
                                 '6c8c67f8e5ce1a5b035c23f283e928dcb408e10bc9dc6c4e238eed892d9acafd',
                                 '6c9314a3604342fba89ec7d3c479eb6d13b87d7a73df9d0cc5752403720b41c3',
                                 '6e59c69226f3b212dff62231168516863c08fd75dc09ef75c9ccf9c51adb9442',
                                 '71b8e0baa1151f01b697a3294255f67768cab2279692b36f64218ab20e1df84e',
                                 '72927cb8c851d4bdad756dda9e448354d9e0bdf5fcd2113fac561715e238b888',
                                 '73c515fd9ebfe517df241615fdd2e3e10d1e7d485a230c2bf344604cce87cda5',
                                 '73df4b36c9deba1c6eb8117a0f122508f8383ed6d66d9d3bac4a366276b94574',
                                 '7484173e5bb4f15b02b8ae99207f359bee8d09c42754f19de4575959bfbe5d57',
                                 '77f9bb35c8554cabb0853cc1dc095f451a4b0a88ea086b3549e2130500ecb3a2',
                                 '785e72a9405ed089f502a6448406de899d81797e54393c24db9ef5473589f2bb',
                                 '7888041d6958892c68fa7f2db3f4c0c0e60e1ce0c1261dc83b9d2c918c522d40',
                                 '79fdca83608b0d9bcaca4144abe026d59b72825ae3a45d1f21f47c09a5da2966',
                                 '7afe4068112bdcfe9da065897e9a56e539480ac1449ea649262d5c585b53f89b',
                                 '7c0d93b6a6600ad4322392e148532e47356c379017ba4736987dc91ecd531c23',
                                 '7c3b529c0aa28f318635024e76903e7e53b59f8985f2562d81d649f4fc1fbf66',
                                 '7d85809afa741e9a138ece2a371d274ec853091bfe6d5a23bdadfb455304ee52',
                                 '7e6fbf097b7b2f9d5e38a973aeeb2b067cefb840aa132ecef7e06473d89e25b1',
                                 '8039d5ece6cf3b957ded5c9ec59a5ba0fd30ff0346dec068d404ffa9e49c993b',
                                 '82ad5a41cf61559877efcd6575a86a5aa0e0bed7c39930423e308a782c811eca',
                                 '83d5bfd94c8b26e9c6cb7497145200cecfe6b177fc3645690d4ec067421b144c',
                                 '87914a81e28c271057724ce40f63d4192be1126e44bf5f6e9fa1bec4254681da',
                                 '87fab97adda841fdb8614614daeb5dfee452ff5d5601f6816e4bce009a05b132',
                                 '8a0973295ec332adca6cebc6080f6c40619d8fad99676c89dd0680f24debfba4',
                                 '8a25fe8af889d2fdd66e5a3524da72f1a5f353f397a4f6a3b60eb0269f6b413c',
                                 '8b6194125b3726fb81c0a275a2e901a563698a7e65e43f3b83e5cd1abbbc359a',
                                 '8bf9d2f62362fb83b06aa2d25972ed502e805179aba4d71842694c22b4be55cb',
                                 '8fb74fa14bee9d67a0e5a954fd15e3c3fb0bf9b437963a4d7dfb78b424b06f18',
                                 '8fd18e3e196904338501790fe205977bce83f43182e4778c277703532afabfc6',
                                 '92500ef24fc8bc3e83d6b8230ee1ff4854866aeb758b2b7d86c16b6dc1004073',
                                 '92d4871f7b174eea0938a5a1e0e8a2fb3d664f59e28e599cd8795059504b5376',
                                 '935c0f57c9e68552876824fd7df2c6a4b28499883f9f7bbfbb642c4cd26973b0',
                                 '943f633ab9ca431d38e9cf05c98ac007e7da39f92b969950e5854a5c6595f464',
                                 '95955e6c3d4e01c25a6636fd373a88ec10a7a6dc4a23dfdd4c104ef83e734471',
                                 '9600cfa5165847f1f2b6f2917b07520aacdc77687d8e807e6b9eb275677fc32a',
                                 '966048ff2c91470f00ae3fec3d9f3639ccd7d724478704ad8092a4d9e42cf91e',
                                 '96b1d9bf34b44176fc984cc4114ad870c366c7223cf9f28d2f4168f1cc510de2',
                                 '98d9792a445237e19a0c7c96fb719ded0ff428fc232c8424c2b1ab7efd8bd817',
                                 '9aac1f6ac1f04abfc31122811b5a299ee2c798c110641b73f0707c41a89b00d5',
                                 '9bbe325801682fb78677ed07e9e926945e172641cc912b59f8e9e28f1dc9dd77',
                                 '9d1c4b5d89d57bb0a36c42da0308f796ed484bd88adffdb0b4ddbd6fa5977c1e',
                                 '9d2838f7b8bd360488b37d3dc348f12dc462479a7315bb0bdc2edb4a11997340',
                                 '9fde3f3495a74d03c5df3459ed852854f7fd17f6bc1c106068fcf90652101894',
                                 'a07ec0ef0617bf067bc89478819bf654c2131d2a14652b4ae4b680a05eb1ee56',
                                 'a0e3853ce627b9b5ce92dcb25ab418062c9de0cf005146f9f16c16eddf48d266',
                                 'a2306f644085f3b12c70d80ed8c35253c605020cb9439701380250274a38e586',
                                 'a23b2aab0730d4fbbc90a8c53f5329ca282e5cc96ec77c5dfef0c0caaf4bd056',
                                 'a3477ece05aaa0787815e3efb183b13dea7d805261d97236700364e3716ff3e4',
                                 'a38db72971b316f5e31d715057d95a6348fc2ea499210e06fa2a19e17938d708',
                                 'a43aef961fa3cf0e096108a830357b8ddade1272a68b22b059a2432a92f7479d',
                                 'a733b52e477f56669dd8b18ced6c4dd4fa0aa63e764e80b7644a69677280b745',
                                 'a778bf5f9425b5f044e2995779458aa6994608b7c6fe5cc076ddea04d7d49efe',
                                 'a788a3859833a885f10d133b01197c6de151438cd7a61072134dc132d677b04e',
                                 'a78b3628247a9aef9581f193871ca1b27f05e77eb8db2b2624a82bdcf071934a',
                                 'a886dedb34414fd4c27273539066d4cca7eef151f926aecf47663952297ec5d1',
                                 'a91ede2e568ad96b73eef69e28669bc312b3103615759650c2513672e008c080',
                                 'a9f1094ffe6cba7ae790513feec340544234639936a44e127a73565d68710d8a',
                                 'aa158336b6c8a5bebed7a2bb64a629972be9e80c311baa29f1b704efad90a8af',
                                 'aae6564a9f36d1aea93c83e24f19e4377ee15a6b55bcaa2f90eb041a6b574441',
                                 'acee491004e52f01cab1df8f9d872cc08a90995adec61388cd99b5532c56c0a3',
                                 'addfa95d189080d8f61ad242a5b6002896362702406980c1704929334ae8902e',
                                 'ae5c3de1c61c81b02b3e2c7784c008fe4f604843271fd55fb267aaeba69b9ed6',
                                 'aff76b5db3f67d7c83e445d120aa11325044e176173fcfc0daaa7cd1f7e9e560',
                                 'b0be9b6d1ff88f2f3082443a1939e2342ce79187b98450bd26655eff2944ace0',
                                 'b0d96d84962dbee97f3149f9415a5d6a1e66742687ae9927ea9f80e77f229918',
                                 'b1d39a271423056d16f513243f6fbf9adc588abd8976e02d1b75b2490f0f621a',
                                 'b23c36fca54ebaf1bfaac2db53390b28edfe202170fd20c0f770e93d68fd5dbc',
                                 'b31f1223246f032decb412cc92337c1f331744bbeef99c48e4d42d31b94cdfc4',
                                 'b37c884aae3c0992df6b948fd2365b773f3e95f6740917239444c47d7130ac8e',
                                 'b3f9eeafc108c61e580e2921ff666090416819151f7bea0ec5215769e3691324',
                                 'b62b89008a976e97165de226f062294f36e1546dbe21371043b4e48c93866c8b',
                                 'b7e01180bfdef6f793e75f5e6314253689d5a99d908e34bca72ee7627700a5d5',
                                 'b7f911e2f81f52d193dae6ab42ab068b4c4ae2bed100380176887be1a3938863',
                                 'b84f0f5ab50a66ce13ff0d763fbc78441e62cca8b230d2b1b1b4cbfb2ba83e26',
                                 'b8f1d36af16d11a921c14ce1b8f88f9a063fe514a81837edbe0ef279bd25b4e3',
                                 'bda6eb19fb7b76156694ceb611656ece9e99076ef17ff9855da40c62328ed3fe',
                                 'beae340c7bc81049f42fe4f2a8c16cbf69b0217da0e91def553797f335ae8d47',
                                 'beda6a3892bdc36964f72bf2a99613967b548b4a8caf29d379287129d9eb7c34',
                                 'bf1d8bc8c43e47ad2fd56d7a9ffe8d8972fe3f50a5adc66bc36c0b37411a5450',
                                 'c1ce9dce9534559d61cc6d035537506b998105e727ba4333c14c6d2a54a1a182',
                                 'c584f5738820c17480bb499a3da6d2167236f8126837cdb8b0a77f4c5b0a7b5c',
                                 'c5dca94871edd4462202324f7125ddd454c9214ca52a3712cec480d65f5f4932',
                                 'c6b45743d0e647f5445b98ca50891c1165c216771802f13eb92a6934fcd50d09',
                                 'c721d29143720c928bef40476b1790715d65531206256de2d189b1e3fa73ef26',
                                 'c79c0ec5365993cf0bef2499cb47f635072acd5fa1babf96c5f816e517461a22',
                                 'c857bd9566d29a36b7d188bb7c6b5654c49b653033370d15983fde5070b42cfb',
                                 'c8852ae9efeb2d5cb0f561a1347b27057fcd676abc270113734c85636b33314e',
                                 'c94c6cb9d48635188ce8984908cb175658bb8ee919b1cbd0b48f98ebb4abf785',
                                 'ca365f9b990e95da985ab724f6e72f0f38894b7e590250baf726fd453fe02295',
                                 'cbe92a5bec75b89e73e54838b4a23c1f7924f596fd913c3c6007003d23d57f57',
                                 'ccd4d2d08c1684b546bf898a017c73a42a2ed517a8af1ab62663354e4fbb564c',
                                 'cf802e27adf563df38c7771f295a22496c8f451bf7d689b66f27951799ad4f57',
                                 'd09b234e9d60eb7499ddcec298e7b03c8ec1b66da15c0185f9c766bedd63394b',
                                 'd1f647754324125a01602e50e22dfce9320fe5d9a4d9073e9b9c1e24eb04f8a6',
                                 'd27b59565496f7d1d2226793fc22bcab5e77788c02f891581bf9f60f9c128e4d',
                                 'd407494b6952057f50dc6cc827f65cbedeaaddbf1854dd0c55cc69742aa42113',
                                 'd4cdcbc9a50eed5ac00aa2bf0896242b81e28f19e494655c7439ced82eccda44',
                                 'd5806778998f5638b8d4c737f91e677b757ed57cb38c7015849811343c00f10d',
                                 'd74203842739844e0c3107abb1930f52686fa6b7b26d7ad5a2a87d383f8c4d2a',
                                 'd74af292900eec3afd4ba2ca1aa19fdb824b7efb1e6f22251f37372965c2a1e7',
                                 'd7c7af79949603e08a1283b409e49c419b39cad7fc025d0981a2f7e205c82fe6',
                                 'd91db4b33808dcb9a233a124358f16353ab4f4c49695ff51b2a9d0e10a5db46f',
                                 'd9201da948dbfa3c68501eed71dd65de755ae952880a8a17ee0ccf946aec3474',
                                 'd9c40743ef59438f408a609682029975df0fc4e532b1ecb4b813d641b6d79792',
                                 'da5a3f0e651dbba239abe9cc3473362b97d4a5739de9864fb9a3ffbd47c0bf73',
                                 'de0ce38ba92132d1a116f5257537d5c1d78e3898f3f8a48b73f300652e057156',
                                 'de645eae5a9465ed2845f947f9ff8e13579f5ad7d1d00010eead29aa56625817',
                                 'df6cfd1563933d9b1b2a515f1d54fabedc095092d2e63eeb6ddd6a227a7e61ee',
                                 'e03259dc61cf2687dccc38e2b31ef302edaab7ef10808d68962da2cf312dad53',
                                 'e0d2bf336e7d5ef503c96e7951e29d5e3ab4ce2b3e346d8ec31d9b8dbe2be378',
                                 'e1b6796a261a0aabf76a897fa1a91a620384f7c6381604a6aa129c69a268220d',
                                 'e24c73f4dd8a01018d33ea381be46f5a29bc1e9b4327e8ea746529b85093dfe6',
                                 'e2918e61d4bbd8aa325ab1407604c49661d3db4908eb810920c18d53b2e1fb0a',
                                 'e4d775112f99a72802d9c4fc231c314a6e56bcfe9b2c345bbeb86efb54e490bb',
                                 'e4e55547eefaa799c3c81355823ddc9d934cdce07fb0a5bc2940b3f25a187603',
                                 'e5752d337efef0ede8944fe597b1b74f733fdf9bebeb277c31a7195c9a13f92b',
                                 'e58188440807520641f61ef85b3cc615cb013bbf6e7fd9c7a2472395ed3c3bb1',
                                 'e5f21277dcee02a37596f78b455e5ba039d8b6b1ee3f935da54884a810d29e45',
                                 'e6d18849a1f503cbace17d0b2c45670ffedba0608f6aa89785039fb26bf3dea0',
                                 'e6e367c48c0d7c731021282dbe5b18d01eb62dd78fb41fdd9829c4525c1c3ec9',
                                 'e701ad73144831549e51150fd70eeab37893e41376c694f63758f1edb74ea560',
                                 'e823a170dbba4d99067e102bfbcbffce34b339d4e33b03531f58aeb9abf4a313',
                                 'e8a28c59d3c870e2d9f1e8545c7a62e59c14e5db8eecfce99fcbc9cea68b645e',
                                 'ebf27d3d516e92478f5d8830b1ad6b511439a6e3165eb844db5317ebcea47027',
                                 'ef10f5a096aab84c5414a69c70f07efd07a2342c9abd4a7b9c431b9eb71f7698',
                                 'eff1a1d388cab2294f64783fa8a97f2a65daddc62b4e51507dbaf5f95f01e5e9',
                                 'f01e0769c8ae7a7394a6a7e477694e59b6ea733762477070b67da6f7b62d68d8',
                                 'f18c25c36feb686d868be1a62157bb654eda46856d618cb2da06d7ad8c8f2002',
                                 'f259f58ea8c091fae9e42caddebc05a6509a509ab2c9c3755a9c2e6c72c33c20',
                                 'f426a3f54b093708eff8655a0714ba30df8009c2495a53f8a0181d15566fe980',
                                 'f5be178c5c704ca9ec63cb40036fe2fbc771f3d34a7e45fc6176a5d4a6ed7546',
                                 'f7fc26499f5253a9043bfd6b46a76bbf50782fcd4f9d09fecb3fd3fd146eca32',
                                 'f889354bd71743341ffb65a3ddd9da5aeeda776f7fb1eb88b80425dec2f1fd90',
                                 'fc0f4e271acede800bd35ac721204343e0f630c99c746b32552b5463338961fe',
                                 'fd287cba6f5acd529b7ef80296d3410c47c0bddb0369173ba4695def0b7d26ff',
                                 'fdb95fb8e65ee3ea48fa33bed4c11dadfe50659a0fe0d81bcb3a892716ed0c26',
                                 'ff63ffd151a253b21816dd79aa1462eee204c3bf15adef6e5c0ebe93e16cae01'],
 'dkim_config': ['b4715763adf12dac6cd00659871e45e1a7b36d404fd90fe8a3915546ad6b416e'],
 'dkim_records': ['c2f173118e0cdc35bfdca803e8977ad30e69e445982ed1d3aaf7ee12fe4542a2',
                  'e03cc99f636135a39f79f4197b675a291359af0ace70058b9382d508982a6044',
                  'fa625b913b519e515872c690a135dea5b4f810a6c24d98cf400b2c94ce8310aa'],
 'dmarc_records': ['c2f173118e0cdc35bfdca803e8977ad30e69e445982ed1d3aaf7ee12fe4542a2',
                   'e03cc99f636135a39f79f4197b675a291359af0ace70058b9382d508982a6044',
                   'fa625b913b519e515872c690a135dea5b4f810a6c24d98cf400b2c94ce8310aa'],
 'meeting_policies': ['9c7bd6483405412350f21331f8d56f65c475f851dbea154230df9691171058b2'],
 'org_config': ['cf5dc663de9a2855d91ea339aea4f1a37ce0665c683ab873e0ef4bc118db91a1'],
 'privileged_roles': ['004a3256613c0ab5c25f0c4aadf840ac9faa89e8a4b030071a68d43f32b9f417',
                      '1d8230786c6ad12de687035ff2e4a7f33cd75efa09be797999ba7b60f04fee80',
                      '1f34459aac58b5f1653e0b9abddb01d5cb3ab25df10ecf6612d670dc4b5e677e',
                      '2dde676ccd93538cf5a6d8a647295c565ddd3bdbee2a9dd44cea50c830453d25',
                      '30a5f60f1e300c45daf881ef55db01e3ed6346cb4fe67b2cdf8b0459f5500a28',
                      '31bdcad27c60abceb9f7af6c0f3c584bbb078f1c34ae1574581c0f24b5f1c6e0',
                      '35be6e6f1c54fc2c8fe40791cd03f0afce6c43a7eb6283dec1de0d9d9aebc89a',
                      '3a5ba1492424eac8dcbb8b59101e544db754fedb311fdb79990c1543ab8c47cc',
                      '3c57c69e824b86c14b849d148c4aa468c8f01e9d7209447fae18e5aeb98e8593',
                      '3e05d4f8ba462ba59909c004013d6fc1808bea207b8747fbc0ac2bb7d94acdd3',
                      '45351929174fed565f0afd7ea735ce82dfad8297861475cccc5da38fff39bdd8',
                      '495505d4ae1eda653fcadae6442f42f809d4e924e4ea7e114565acdf18bf145b',
                      '514457a887b86d405aa017c7462cf76cbbc55fa2b4ced58a7e79bac097ec42cf',
                      '5b0b15d7a9aa9b0c4a491c99020048b3db71ae5a9ab21ef68f0a3a2011c68862',
                      '6f180b49e613cd9ccd412f015a20b6ffd5023b9ef190cc61b79532f21514702b',
                      '71b2d7dbfffd378d9928a33949652a6b38969fa1b6face042d18c4e3d611d935',
                      '797a9c2a6d24536bf2039a6b94c62fcb1eb19eded0b1da8bf70d9fc21e065e6f',
                      '843fe5439387e681ac11091c627c6f5bf09bf655816e28d4fc36cf02cb469828',
                      '861fdeb5a12348a35884547c90d6996104ddc144cb5449f21b583168736b5d8a',
                      '92e3a6acf44a42e1fb0c9a7f7f197f5ddd7c7ab94dd3054a0bbee73a51e370fe',
                      '95a3468ff7af66d8897cca4b03a07571f966c9d46ac6754a03824f904f2a1e7d',
                      '969de120d186fac63ca9a9d05431ec00692a0d43bd2748809e418afc892e4b81',
                      '97507c7a57130ef057db6348938408e4e2776d39e49b3c325322ab284a65d6dc',
                      'a24913132eac9640311bf8cbc0691e3783c465c2bd181e6db59a7541f6737f58',
                      'a6c44da9968929df9850fff3584e80372961b0300ac86630114ae1961b17a53d',
                      'adfa3e58d530156e3cd67d9ff26595cbd47b020b6fcc303d5ab4f41f448c6662',
                      'af6947851f7bd9170d574e84960c627502ba2cd6a4e27755f4d7ffa59b1dfecc',
                      'b9641bcf1f50206369249627f86a9c1da6dcfddfa0dd68a94719616590f7383a',
                      'bf3cff0fb11155bf3ed8bdd6f4f4cce1b3ac1c2627e464336dd980751a86470c',
                      'c80c7b204139f0230146412246bb544468126fcaf04d24f04ef5752f02fd37c6',
                      'caff3cceba08885fab6c71d773e04e688f583c8bebf8fc58b4bf68834d493cd7',
                      'cdfd50b6807412bbec540159b77e37ac4b4e859f3b80a496383e158849000379',
                      'ce79d4481198ca664d22cacf17d0193922d54dc78ae4af455cccb94ea6355ef9',
                      'da3b406710e6e52b39a4af193cd2c59e4e7f87fc554d478aec7ea1209fbe6fa4',
                      'eaccb61ee4439a1b1b2a6e132ed164d00f52c2318f33eec86ec554c3771b7ac2',
                      'f9c36b729d927b8bf191a3d90229ff6b67a1adbd9db0988209a170469cf728d9'],
 'privileged_users': ['44e39708ed06eb88e2c3f2a8ea0b308ccbace1ea322d3f402f85e8ce81ff538f',
                      'bea85c55b042f7b4464603d0bd58802aa4291b60dc503e791e2c02ae628d81be',
                      'dd66b0cfb44813443ce8bd68853ca8723479008f84e1cfe5e8a499d756d8629e',
                      'f5c3a92a6fc765186485f64fb69e543f27eb5bc4e34ee0713bb25941567a3c35'],
 'scuba_config': ['0020a0f7e9df068b4dd25dad5a11e6fed654d8db609c5d3d85c68b431e95a911',
                  '03077aacf3fff7a08ece465f860e766c51b623c926662c25f97c0b79cef7dda2',
                  '054ac16c0c14025c0f7a37e597ecaaf6660f35c216f2d78c0cfac4024fcf6783',
                  '05cd36160012e63e40f492d24df581fc56bc97a3a327652ed6d4ecd85006159c',
                  '06378d526fd5fd31068d32ebe287b1f9b1b11bf6c7fe8ecb95928f7232247b0e',
                  '06a7ecdaec904b697131fceee251ec69e21b0a9b92fc3c563ef351b962d02305',
                  '083e1c1d676f94fce1e901bacea7b0313c8c2bc85d687bc57d6292eb4a05ba74',
                  '097cdd1ab9d8b04b8f42de9b9a93dcb9216398dd313aa4a154a0d442b585491b',
                  '099063e8ea90bb14e0cb5e7fdc7723aa14e3d0391ad4ce4c04f7da50d7c07912',
                  '0996ed3e82ffa5aadcf6d9109c553e740aa6c6fc3d8ce71fe3467ac8123a7300',
                  '0df888e26e2de5a4fb3ce3857abce90d4094ef77aaea88f40c37a57c86350fea',
                  '0e5239193b16c053dc622587790d4a48a7f5548db1457420657e9c7f6cd05cef',
                  '0eafcfda93bbf092480453c8eae7629de48681ec124c873e317544f88cdf743a',
                  '1191d2644f97db24b80f24895d881075cab8dc8bdda3fbcca659260af653a3d0',
                  '1253364d82e2ea04a0f1b700c82ac123e37ae746a4d9e30283c9168576ef6ca5',
                  '149f8d1ea619afeadec4f173ebb107d10e0b59680fa2674c9a8a5e4a7d4e8a56',
                  '20cf283ca4ab0d9f9954e5810de01e5601dd9a2fc77661690460d6e4928b11ed',
                  '264b2e2a74327adef321274f110c637250e37ea1206becefa9f4761500d2ce88',
                  '26a2653cb76fd3166f7e7cf9d9479688ca2bc8a8743fc636898c3b8cdbad35ea',
                  '281f457e7c36797161480dfeac7f5f0b29ae751860624419184012f846206c3c',
                  '29dc7ff718e0c69dce2833fcd65f5177c7b3fada85017fa7d63c3ea3b49131b1',
                  '2a41fcc4583ac90915ec3eaf42d545c7d8fb1987a7100bd8912dc1e9dbeeaa8b',
                  '2e29fd471bafbf70740cdfbec89ca02e32e37aed0840594e9cc7ee1e3179bb10',
                  '2f525a8bf0e0722988f0fc0e91fe1a4dd9a5569197a556ed983b783933e2c23a',
                  '35b68c2c1a2c96d70740be2095f0547eb722e5dc0134842b1a504a2ce65d8374',
                  '36b14de165080563f8f24d28f8ae2460d24b318a0b176319a2ce4273df3ff628',
                  '37243fbecf29e83b7a03ae0afe90a336e916fb4e22334830c0d929f83ab5e927',
                  '37763563c54bd9cf1c76b8caa07ff5285690fcc0d24b4cd2d9050460a35bf753',
                  '4461d96248473f3d2271509c680a7a8903bc1fc9b19c96d05eff7ea9d2a722cd',
                  '459333d3b1103afdee78d4c770c80531ee8bf2e2d850391ed3ff72a735c47148',
                  '4dc375e273be2312f8bcd329046e5aaec0b8229c34ff59bd893c3348d210875b',
                  '4e3fb8f7e380c788636b1b6448b5a61d8f738914ce237a3bb045a5c12730c7dd',
                  '508a29aeadf7542d6287590c399b1486eff5e635f9e3e2e855c06b102c683a21',
                  '52a8876273bb66098fdd1fcd75121dcb7fbddfa079d27c4b21beac10be55cb51',
                  '54b4e42abce4c76ed59e9694dae89b7abe66ead627c58289a8bf4d10a4dd10db',
                  '5610b8ccb35c862a1a4d17bf337f1078eb4bccad778ddd31d800a0f42a59f98d',
                  '572db71c009b55d6418d3f579a5170369557c538d0138934badc4593038989db',
                  '57aee2af5cc20fcc245849f168e3ceeba3854851c2d3a39f48df86f588f14936',
                  '586f29f17644f28934427676277d15b03e921b482246976f346a6428e1adf38b',
                  '588d13f4ae30a62f75bcc0bb9f6532ea9674d2418d9a67db95f9d76e8cca2197',
                  '5ad39a8a5184291da83ecfc9ad5b6fa013dff1eec4a20ea6648c72c0dbbbc838',
                  '5c01ebb738173c79bb072caa43d0631e9be719c512cbe039770ea7c7c17e455d',
                  '5c6e4a4f4872c0edfd222de04f65fbf4cc5e5b0aebeecfb4db4423ace17c408e',
                  '5c85a9058dadc302489dfc11c8019e1de145356368555caf45bcf527d14f9d4c',
                  '5feb7ba01ae5856ff768cf6aad1fe64591b7adb815b0b41ff68b8ef79ef65140',
                  '6066a22d37b27aae4165b4f8adb3f0714f742e50a19c3971e8eb051403b07c5f',
                  '6186f6f3a53850c1090b26a1bea373cab5aa52f9a9b82b4c77c20ae0a6e4db01',
                  '61ff91c14967a6beb98534e3ea1816e65bf1efec8f451c9d1153e88c9c877937',
                  '63059cf98487832d0edb61e05860ffbe4c2cc1ff4fa64e7c401f1475e344e2c3',
                  '6f668b8cd538faa2ea136d2dd7d7b9c3be03345ea8f0d64487d9d47f527035ef',
                  '749e8a42af9fac934482f2c8d99a5f6e8e9d13949352a8c5db5fbe530f87d491',
                  '75c7c8ecd239c270ba35ce95ad721c70c9df480ea24b1ede991c32d5effc334d',
                  '78c1eade42ac06207c3d5051f3dc5956cfaecaec589755396207b6e7f0d14e26',
                  '7bd97c17056af916598645f92508b604c46e2471464c342635416f5b3b85c4fc',
                  '7c2c942058d5345630dff13cdddccbeb0a198d7c2897e1032e45e2d3f11f8139',
                  '7d2e1d9cb8690b1af608f8032442ae0669694165f21fd9a3c972c95bab6b362a',
                  '8382838f6fffe9291924557c78cd3be9aca842dd0301b31ca7276fc44ca8ae08',
                  '89a3e0699262b74d5ac5e7a31eaad1237a2b083949b0d8168c23449da93a1256',
                  '8fae2b21b5cfb48eb3f72308471cc732175efd259ea0b1e1d923c14aaa70a4b8',
                  '9190da9e46121859942c7c3c60d71bbe5caa8fcf718a568c6c3f0acfe350c61a',
                  '934c6892901bad2d53b0ef7077489b6408d9ac19be57c0c26bf7093e89a6a7ad',
                  '939bde19185c8b3a5113c06e3dfe967bcf1a8c85251a7cbfe05a193d226349ad',
                  '97498b3a960cc9164648ff530042621724118d84a5a3869bd894dd1611d4f842',
                  '9c5f01680993ab3c1d1e2997de7620a3e1fb9ce8d4ec3fe3d9429c2422f93535',
                  'a2036fd8fff51bc2236178c9aa5a41d0630a5773e12772d731c2c49f047f371c',
                  'a33b654f2c1d8112911b0b78edcdbad394e04f000fc99af0d9388fbab77318a7',
                  'a46186770e721a7e40e4b567eae699dbaf63aafed25d8fb40817536cebc8fa43',
                  'a50df5b82515888b91a06355cd5efe4e559e61ba90248e96800891c2739df30f',
                  'acbed0f4178bb80d5f569c86907dd8640e623954e03692181acf274b7fd5ecd5',
                  'ade8c8ad8da89c2dcb2f5a7e2238f1d1e6f5fb8f2b33e06f6c7c20f863980549',
                  'aebf9e781da5e5d7b0004f531af64ccf93c701b21cad86d21abe50c7fca41815',
                  'afc1db08a4fb60e1b2291986267e95e9b1bfede51ba03c2be970f65b23ba5c67',
                  'b42ad93e7b036b4c2e65584b476e65a0bcc8d79aa57778b5bb5e659e08a05199',
                  'b812e9665980ccc85564941ce323d6df387e5e43c5b339faf9446f115cf88b5d',
                  'ba4f179851b4739225ebbdea45f273c282962e0272c033b9ea31cb5457b09d5a',
                  'bbcbc1d57f1eadaf667086405b92540f56a5c3065ea893548b0da9c102c87f73',
                  'c03256eb85cabe100d5cc24d85ddbeb35bd742c00d9293170bd87cdb34991ded',
                  'c3484aef269d3938a80535c15eccc1efdff1768760fa61ca8c6c3f0cca359280',
                  'c8681ddf65723fabf5da95af9b7dccaa02fc8c00a2323088e0adb08d36fa7b0e',
                  'c86fca9403ff4e65ab884bd13f05c15919cac376787cb00e1b090569554512f9',
                  'ca5ae1a7556d1e2bd5e5f825cd4e7529e8934df085fdb3549fbc123ab7c79f3d',
                  'cbce5eb715618b7b35c1a2dd843062c4206359c7eeb96cc7353d1aca1c8e2128',
                  'd181abd2b236f7988195aaf025994d19c2bc3b19e0a5d194ef5e6964a90835e3',
                  'd50b0b86f9b38d9bb864e084d60aaa37039f3e425d5287b6ccdad87e90716db3',
                  'da549ce926ecfcadea482f791b3bff5922a6850872798095cfce04052ae1be85',
                  'df1b6ec32189bb651f40456d38543069a36362416f81558c98f074c5be60f0c7',
                  'e2ec276907afba67dfe387bc8b3b2ecafdb77e5250616d8934ef8fa239efa000',
                  'e396d2e25368e685d73c7545ee76de60c0513b598d3d2292c6c4dde67fac7995',
                  'eaac9b388955768bfb4cc7b43804d0c2d7bc47cbea0102670674bcebb7c43a2d',
                  'f16f271b805c4392951ef24dd9db363747733778d9545bacc8d085e3a3f3b949',
                  'f5c98a1d27c5faad70362c4af323c95d2feb6888ef9f818f249c74d41cda8a6c',
                  'f7041e13fdf127a346af7ae5f2f0df6cdf6c5f2c61a976a051c6ac15a6686274',
                  'f7317082330ced3bc27638a9e4a2e27054c4d5b68031ca43b75829e66720741f',
                  'f8ea75925de096924158468b7340d9de1280e80aaef82cfdf330d4444793188e',
                  'fac77c3a8bb0ce6b44c495850fe37fac0fa87aa018aedbc5cb1f1f8c3d3466e6',
                  'fb94e60bfa85d04c68cbeb3b907e20afbfbdfa2ccb91715b74c373c22be07dae',
                  'ff539a0ec58f3c5263edbf44fd5e36f036c262dcc996c3cb022b93e91f284a30',
                  'ff78cf59e512895e511a50f34cf15a135dc90be55dfcfda516c3662930ea83cc',
                  'ffdb646ddb4eeff6f985ca7629c38126ba9442bdac179fc62ecab54c8546823c'],
 'service_plans': ['6e59c69226f3b212dff62231168516863c08fd75dc09ef75c9ccf9c51adb9442',
                   '7f4e7214c6bec7aca5bf3044b58af79df9eda6943a20dcc8c7e1f06cce6152ad'],
 'spf_records': ['0c84e58beeae24d667350e9a88e652ac29446e40ff04acb2f4c77afb08012411',
                 '0d26945509efd098c92358a3d3e1e87842d524f69968eebf2e7a7ea24d0f1690',
                 '6346eea42ec45a8bcf70e5b313251e6bbfb240862ba43c96d24ed14ad96f384f'],
 'tenant_id': ['05cd36160012e63e40f492d24df581fc56bc97a3a327652ed6d4ecd85006159c',
               '72495b0e1f3c6c961f46d3f249ce968ac758c43b88e50d32aa138681f8a38804'],
 'transport_config': ['af192c8cd9f202145aa1beec820592b5733dc700737b45eb6d7fda6c6f3d2f4e']}


PACK_ENUM_DOMAINS = {'SPO_tenant': {'[].DefaultLinkPermission': ['1', '2'],
                '[].DefaultSharingLinkType': ['1', '2'],
                '[].FileAnonymousLinkType': ['1', '2'],
                '[].FolderAnonymousLinkType': ['1', '2', '3'],
                '[].ODBSharingCapability': ['0', '1', '2', '3'],
                '[].SharingCapability': ['0', '1', '2', '3'],
                '[].SharingDomainRestrictionMode': ['0', '1']},
 'accepted_domains': {},
 'authorization_policies': {'[].AllowInvitesFrom': ['"Bad value"', '"adminsAndGuestInviters"']},
 'conditional_access_policies': {'[].Conditions.AgentIdRiskLevels': ['"high"',
                                                                     '"medium"',
                                                                     '"medium,high"',
                                                                     'null'],
                                 '[].Conditions.Applications.IncludeUserActions': ['"urn:user:registersecurityinfo"'],
                                 '[].Conditions.AuthenticationFlows.TransferMethods': ['"deviceCodeFlow"',
                                                                                       'null'],
                                 '[].Conditions.ClientAppTypes': ['""',
                                                                  '"all"',
                                                                  '"exchangeActiveSync"',
                                                                  '"other"'],
                                 '[].Conditions.SignInRiskLevels': ['""', '"high"', '"medium"'],
                                 '[].Conditions.UserRiskLevels': ['""', '"high"', '"medium"'],
                                 '[].Conditions.Users.ExcludeGuestsOrExternalUsers.ExternalTenants.MembershipKind': ['"all"'],
                                 '[].Conditions.Users.ExcludeGuestsOrExternalUsers.GuestOrExternalUserTypes': ['"b2bCollaborationGuest"',
                                                                                                               '"b2bCollaborationGuest,internalGuest"'],
                                 '[].GrantControls.AuthenticationStrength.AllowedCombinations': ['"SuperStrength"',
                                                                                                 '"deviceBasedPush"',
                                                                                                 '"federatedMultiFactor"',
                                                                                                 '"fido2"',
                                                                                                 '"hardwareOath,federatedSingleFactor"',
                                                                                                 '"microsoftAuthenticatorPush,federatedSingleFactor"',
                                                                                                 '"password"',
                                                                                                 '"password,hardwareOath"',
                                                                                                 '"password,microsoftAuthenticatorPush"',
                                                                                                 '"password,sms"',
                                                                                                 '"password,softwareOath"',
                                                                                                 '"password,voice"',
                                                                                                 '"sms,federatedSingleFactor"',
                                                                                                 '"softwareOath,federatedSingleFactor"',
                                                                                                 '"temporaryAccessPassMultiUse"',
                                                                                                 '"temporaryAccessPassOneTime"',
                                                                                                 '"voice,federatedSingleFactor"',
                                                                                                 '"windowsHelloForBusiness"',
                                                                                                 '"x509CertificateMultiFactor"',
                                                                                                 'null'],
                                 '[].GrantControls.BuiltInControls': ['""',
                                                                      '"block"',
                                                                      '"compliantDevice"',
                                                                      '"domainJoinedDevice"',
                                                                      '"mfa"',
                                                                      'null'],
                                 '[].GrantControls.Operator': ['""', '"OR"', 'null'],
                                 '[].State': ['"disabled"',
                                              '"enabled"',
                                              '"enabledForReportingButNotEnforced"']},
 'dkim_config': {},
 'dkim_records': {},
 'dmarc_records': {},
 'meeting_policies': {'[].AutoAdmittedUsers': ['"Everyone"',
                                               '"EveryoneInCompany"',
                                               '"EveryoneInCompanyExcludingGuests"',
                                               '"EveryoneInSameAndFederatedCompany"',
                                               '"InvitedUsers"',
                                               '"OrganizerOnly"']},
 'org_config': {},
 'privileged_roles': {'[].Rules[].NotificationType': ['""', '"Email"', 'null'],
                      '[].Rules[].RuleSourceType': ['"Directory Role"', '"PIM Group"']},
 'privileged_users': {},
 'scuba_config': {'.M365Environment': ['"commercial"', '"dod"', '"gcc"', '"gcchigh"', 'null']},
 'service_plans': {},
 'spf_records': {},
 'tenant_id': {},
 'transport_config': {}}
