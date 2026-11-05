"""The report-output redaction boundary: one function every shareable writer passes through.

Run directories, evidence stores and ``raw/`` / ``normalized/`` files are private working files (0600 in
0700 directories) and are *not* redacted: the operator needs them whole. Everything that can leave the
operator's machine through a writer, sink or return value listed in the inventory is redacted here, at the
last step before the bytes are written, printed, sent or returned. The decided boundary and its limits are in
``docs/reference/security-privacy.md`` ("Output redaction boundary"); ``auditex/output_writers.py`` holds the
machine-readable inventory that ``tests/test_output_redaction.py`` checks against an AST scan of ``src/``, so a
new file write, print, network send or return path of a known shape cannot appear without being classified.

API::

    redact_output(value, *, profile=PROFILE_SHAREABLE, context=None, markup=False)   # same shape out as in
    context_for_run(run_dir)                       # salt, run paths, protected names and immutable ids
    context_for_runs(run_dirs, paths=())           # the same for an output built from several runs
    redact_payload(value, *, run_dirs=(), paths=())  # redact_output + context + citation summary, for returns
    settle_citations(payload)                      # re-derive a redacted payload's citation list and summary

``value`` may be a ``str``, a mapping, a list, tuple or set, or anything else (returned unchanged). The result
has the same shape: mappings stay mappings, lists keep their order, numbers, booleans, ``None`` and bytes pass
through. A key is rewritten only when the key text itself holds an identifier (an e-mail address or a GUID) or a
credential assignment (``password=value``) and never by name substitution; values under structural keys (ids,
setting names, reason codes, statuses, verdicts, sections) and values shaped like a policy id or a snake_case code
are never name-substituted; if rewriting makes two keys equal the later one gets a ``#n`` suffix and no value is
lost. Number literals in embedded JSON are written back exactly.

What is and is not guaranteed (see the document for the full statement):

* Redaction is deterministic (a pseudonym depends only on the value and the salt) and, for the forms listed
  below, idempotent: ``redact_output(redact_output(x)) == redact_output(x)``. Generated pseudonyms are never
  matched as names, ids or e-mail addresses again.
* It raises ``RedactionDepthError`` (a ``ValueError``) for a value nested more than ``MAX_DEPTH`` levels,
  including a self-referencing one, instead of returning something partly redacted; an unknown profile name
  raises ``KeyError``; and, for a profile that pseudonymises identities, it raises ``ContextIncompleteError`` when
  ``context.incomplete`` is set (``context_for_run`` could not read every record of the run: fail closed, redact
  nothing, return nothing). It does not otherwise raise on odd input.
* It protects the classes below in the representations below. It is a pattern and structure redactor, not a
  proof: free text can carry a name it was never told about (see "Limits" in the document).

What a profile redacts (``PROFILES``):

* secrets: Bearer values, JWTs, ``key=value`` and JSON-keyed credentials (``secret_hygiene.INLINE_SECRET_RE``),
  and the whole value, of any type, under an exact credential key;
* e-mail local parts, masked as ``***@domain`` exactly like the model projection (also when written
  ``%40``, ``\\u0040``, ``&#64;`` or the full-width at sign), except the exact public baseline addresses in
  ``PUBLIC_ADDRESSES``;
* privileged-user display names (M365 role holders, Google admins) and on-premises immutable ids, pseudonymised
  like the projection (``User <16 hex>`` / ``Id <16 hex>``, ``sha256(salt NUL text)``), including inside the
  text of the same output and inside JSON embedded in a string;
* dashed GUIDs (``PROFILE_POLICY[profile].redact_guids``), except ``PUBLIC_GUIDS`` and values labelled
  ``Trace ID:`` / ``Correlation ID:``; the replacement is itself a valid GUID so schemas that demand
  one (OSCAL) still validate;
* the operator's run paths (``RedactionContext.run_paths``), every occurrence.

What each profile redacts beyond its fixed rules is the table ``PROFILE_POLICY`` (GUIDs, domains, group names and
free-text keys; ``ProfilePolicy``); change a field there (or pass a replacement through ``RedactionContext.policy``)
and every writer follows.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Iterable

from .citations import build_citation_summary, dedupe_citations
from .secret_hygiene import BEARER_RE, INLINE_SECRET_RE, JWT_RE, OUTPUT_EMAIL_RE, OUTPUT_GUID_RE

PROFILE_REPORT_PACK = "report_pack"
PROFILE_SHAREABLE = "shareable"
PROFILE_CUSTOMER_PACK = "customer_pack"
PROFILE_EXPLAINER = "explainer"

SECRET_PLACEHOLDER = "***redacted***"
RUN_DIR_PLACEHOLDER = "<run-dir>"
TEXT_PLACEHOLDER = "<redacted-text>"
GROUP_PREFIX = "Group "

# Values nested deeper than this (mappings, lists and JSON embedded in strings together) are refused.
MAX_DEPTH = 100


class RedactionError(ValueError):
    """The value cannot be redacted safely; nothing was returned."""


class RedactionDepthError(RedactionError):
    """The value is nested more than ``MAX_DEPTH`` levels (or refers to itself): fail closed."""


class ContextIncompleteError(RedactionError):
    """The run's identities could not all be discovered (see ``RedactionContext.incomplete``): fail closed.

    The message and the attributes name each unusable file by a *safe label* (its run-relative path with every
    segment that is not a plain section name replaced by ``<redacted-segment-N>``) and a reason class
    (``unreadable``, ``malformed JSON``, ``oversize``, ``non-regular``, ``dangling link``, ``limit``, ``outside run``,
    ``changed during scan``). Never file content, an operating-system message or the absolute run path.

    ``files`` is the sorted list shown, at most ``_MAX_LISTED_FILES`` ``(label, reason class)`` pairs; ``omitted``
    counts the unusable files beyond it.
    """

    def __init__(self, files: Iterable[tuple[str, str]] = (), omitted: int = 0) -> None:
        listed = tuple((str(label), str(reason)) for label, reason in files)
        shown, rest = listed[:_MAX_LISTED_FILES], max(0, int(omitted)) + max(0, len(listed) - _MAX_LISTED_FILES)
        self.files: tuple[tuple[str, str], ...] = shown
        self.omitted: int = rest
        total = len(shown) + rest
        names = "; ".join(f"{label} ({reason})" for label, reason in shown) or "no file could be named"
        more = f"; and {rest} more" if rest else ""
        super().__init__(
            f"identity discovery was incomplete for {total} file(s): {names}{more}. Nothing was redacted or returned. "
            "Repair or remove the listed files and retry"
        )


@dataclass(frozen=True)
class RedactionProfile:
    """Which identifier classes one output class has redacted."""

    name: str
    secrets: bool = True
    emails: bool = True
    identities: bool = True
    guids: bool = False
    run_paths: bool = False


# ``report_pack`` is the run bundle's own ``reports/report-pack.json``, written while the run is still open. It is
# a working artifact: its finding ids, proof-table rows and evidence references embed the keys of the records they
# cite (including e-mail addresses and GUIDs), and the validator resolves them against ``normalized/``. Masking
# an identifier there makes the references unresolvable (``unresolved_report_proof_table_ref``), and the run
# salt (the digest of the final manifest) does not exist yet. So the pack carries secrets-redaction only and
# RETAINS e-mail addresses, GUIDs, names and paths exactly; the identifier classes are applied where the pack's
# content is rendered, exported, sent or handed over, which is where every other profile applies the full set.
# A copy of the pack inside a customer pack is therefore not an "all identifiers redacted" file.
PROFILES: dict[str, RedactionProfile] = {
    PROFILE_REPORT_PACK: RedactionProfile(PROFILE_REPORT_PACK, emails=False, identities=False),
    PROFILE_SHAREABLE: RedactionProfile(PROFILE_SHAREABLE, guids=True, run_paths=True),
    PROFILE_CUSTOMER_PACK: RedactionProfile(PROFILE_CUSTOMER_PACK, guids=True, run_paths=True),
    PROFILE_EXPLAINER: RedactionProfile(PROFILE_EXPLAINER, guids=True, run_paths=True),
}


@dataclass(frozen=True)
class ProfilePolicy:
    """The identifier classes one redaction profile redacts beyond its fixed rules (decided by product, 5 Nov 2026).

    ``True`` redacts the class in that profile. There is no role-name field: built-in role names are public
    Microsoft vocabulary and custom names are tenant text the output cannot tell apart, so role names are never
    redacted (and are protected from being mistaken for a user's name, see ``RedactionContext.vocabulary``).
    """

    # Dashed GUIDs (tenant, object, application and policy ids): pseudonymised per run, so references inside one
    # report stay usable and nothing ties back to the tenant. Only applies to a profile that handles GUIDs at all
    # (``RedactionProfile.guids``; the secrets-only ``report_pack`` keeps its references exact).
    redact_guids: bool = True
    # Domain names. Off everywhere: DNS, mail-flow and accepted-domain findings are unreadable without them, and the
    # e-mail mask keeps the domain by contract. On: every domain seen in an e-mail address in the output (and
    # ``RedactionContext.domains``), with its subdomains, becomes ``domain-<12 hex>.invalid``.
    redact_domains: bool = False
    # Group display names: records whose ``principal_type`` is ``group`` (``Group <16 hex>``). Off everywhere:
    # groups named in findings are what an administrator acts on.
    redact_group_names: bool = False
    # Every string under a ``TENANT_TEXT_KEYS`` key (waiver owner, justification, comments, notes), whatever the
    # container. On for the customer pack and the explainer, off in the local report and the report pack.
    redact_free_text_keys: bool = False


_SHAREABLE_POLICY = ProfilePolicy()
# The setting per profile. ``report_pack`` is the secrets-only working artifact (it keeps GUIDs, names and free text
# so its references resolve); ``shareable`` is the operator's own report and MCP payloads; the customer
# pack, notifications (third-party services) and the explainer leave the operator's control. A flip is one edit here.
PROFILE_POLICY: Mapping[str, ProfilePolicy] = MappingProxyType(
    {
        PROFILE_REPORT_PACK: ProfilePolicy(redact_guids=False),
        PROFILE_SHAREABLE: _SHAREABLE_POLICY,
        PROFILE_CUSTOMER_PACK: ProfilePolicy(redact_free_text_keys=True),
        PROFILE_EXPLAINER: ProfilePolicy(redact_free_text_keys=True),
    }
)


def policy_for(profile: RedactionProfile) -> ProfilePolicy:
    """The policy of ``profile`` (a profile that is not in the table gets the shareable one)."""
    return PROFILE_POLICY.get(profile.name, _SHAREABLE_POLICY)


TENANT_TEXT_KEYS = frozenset({"owner", "justification", "comment", "comments", "notes"})

# Exact public addresses from the public baselines and their examples; compared case-insensitively.
PUBLIC_ADDRESSES = frozenset(
    {
        "reports@dmarc.cyber.dhs.gov",
        "cyberliaison@cisa.dhs.gov",
        "reports@example.com",
        "username@somedomain.com",
    }
)

# Microsoft role template ids, first-party application ids and the all-zero GUID that the product ships as
# constants (a test checks that every GUID literal under ``src/`` is listed here, so adding one is a
# decision, not an accident). They identify Microsoft's catalogue, not a tenant.
PUBLIC_GUIDS = frozenset(
    {
        "00000000-0000-0000-0000-000000000000",
    "00000000-0000-0000-0000-000000000002", "00000000-0000-0000-0000-000000000003",
    "00000000-0000-0000-0000-000000000004", "00000002-0000-0ff1-ce00-000000000000",
    "00000003-0000-0000-c000-000000000000", "00000003-0000-0ff1-ce00-000000000000",
    "00000007-0000-0000-c000-000000000000", "00000009-0000-0000-c000-000000000000",
    "01c0a623-fc9b-48e9-b794-0756f8e8f067", "06b708a9-e830-4db3-a914-8e69da51d44f",
    "10dae51f-b6af-4016-8d66-8c2a99b929b3", "158c047a-c907-4556-b7ef-446551a6b5f7",
    "194ae4cb-b126-40b2-bd5b-6091b380977d", "19dbc75e-c2e2-444c-a770-ec69d8559fc7",
    "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9", "29232cdf-9323-42fd-ade2-1d097af3e4de",
    "2af84b1e-32c8-42b7-82bc-daa82404023b", "3a2c62db-5318-420d-8d74-23affee5d9d5",
    "475226c6-020e-4fb2-8a90-7a972cbfc1d4", "4ba39ca4-527c-499a-b93d-d9b492c50246",
    "50483e42-d915-4231-9639-7fdb7fd190e5", "62a82d76-70ea-41e2-9197-370581804d09",
    "62e90394-69f5-4237-9190-012177145e10", "729827e3-9c14-49f7-bb1b-9608f156bbb8",
    "72f988bf-86f1-41af-91ab-2d7cd011db47", "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
    "7df0a125-d3be-4c96-aa54-591f83ff541c", "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2",
    "9360feb5-f418-4baa-8175-e2a00bac4301", "966707d0-3269-4727-9be2-8c3a10f19b9d",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8",
    "a0b1b346-4d3e-4e8b-98f8-753987be4970", "a82116e5-55eb-4c41-a434-62fe8a61c773",
    "b0f54661-2d74-4c50-afa3-1ec803f12efe", "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
    "b633e1c5-b582-4048-a93e-9f11b44c7e96", "c4e39bd9-1100-46d3-8c65-fb160da0071f",
    "c5393580-f805-4401-95e8-94b7a6ef2fc2", "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8",
    "e2a3a72e-5f79-4c64-b1b1-878b674786c9", "e8611ab8-c189-46e8-94e1-60213ab1f814",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c", "f2ef992c-3afb-46b9-b7cf-a126ee74c451",
    "f8cdef31-a31e-4b4a-93e4-5f571e91255a", "fe930be7-5e62-47db-91af-98c3a49a38b1",
        # Microsoft catalogue ids added with the risky delegated-permission list (Graph, Flow, Dataverse and other
        # Microsoft first-party delegated scope ids) and the Teams admin API resource id: public Microsoft values.
        "01944dba-21df-426f-bb8c-796488be96ad", "024d486e-b451-40bb-833d-3e66d98c5c73",
        "02a5a114-36a6-46ff-a102-954d89d9ab02", "06da0dbc-49e2-44d2-8312-53f166ab848a",
        "077fde41-7e0b-4c5b-bcd1-e9d743a30c80", "0b575251-2c95-46df-bc75-c8c43e6b7116",
        "0b5d694c-a244-4bde-86e6-eb5cd07730fe", "0cea5a30-f6f8-42b5-87a0-84cc26822e02",
        "0e263e50-5827-48a4-b97c-d940288653c7", "0eb56b90-a7b5-43b5-9402-8137a8083e90",
        "10465720-29dd-4523-a11a-6a75c743c9d9", "116b7235-7cc6-461e-b163-8e55691d839e",
        "140e747e-90d3-4de0-8618-85a0cc7a1129", "17f07f5d-fb80-4278-ba37-70ae04d476a3",
        "181aac24-028a-486e-a649-b3742c74ec71", "185758ba-798d-4b72-9e54-429a413a2510",
        "195adc35-e27b-454b-a7ed-1ecdffa1c09f", "199f155b-cccd-4be4-bbe6-ca9a867b24b4",
        "1a50df37-8278-4139-9af3-3b60d57dd007", "1b8ff426-c49e-4985-a589-956c1a33c510",
        "1ca167d5-1655-44a1-8adf-1414072e1ef9", "1d894596-c906-42b1-8422-9360440c1c0c",
        "1ec239c2-d7c9-4623-a91a-a9775856bb36", "204e0828-b5ca-4ad8-b9f3-f32a958e7cc4",
        "205e70e5-aba6-4c52-a976-6d2d46c48043", "2448370f-f988-42cd-909c-6528efd67c1a",
        "2497278c-d82d-46a2-b1ce-39d4cdde5570", "258f6531-6087-4cc4-bb90-092c5fb3ed3f",
        "266d2589-20b5-4f91-9a03-89247d1be8da", "27235839-268c-4d68-a668-351401ff623a",
        "27608d7c-2c66-4cad-a657-951d575f5a60", "27789c5b-aca8-4cb6-94b8-bcc8964dd8ad",
        "27c61d54-eb42-4315-8793-6e5715a19746", "2b61aa8a-6d36-4b2f-ac7b-f29867937c53",
        "2b9c4092-424d-4249-948d-b43879977640", "2e25a044-2580-450d-8859-42eeb6e996c0",
        "2e83d72d-8895-4b66-9eea-abb43449ab8b", "30b2d850-00c3-4802-b7ae-ece9af9de5c6",
        "32253599-e142-4cf0-810d-4827eedd1cfa", "322b68b2-0804-416e-86a5-d772c567b6e6",
        "38826093-1258-4dea-98f0-00003be2b8d0", "39d65650-9d3e-4223-80db-a335590d027e",
        "3b5f3d61-589b-4a3c-a359-5dd4b5ee5bd5", "3be8fe94-2189-4d8b-89c6-dd35c5cea6ef",
        "3d728bf5-2e5b-4ea2-8c8a-dcf9711e1208", "405a51b5-8d8d-430b-9842-8be4b0e9f324",
        "41ce6ca6-6826-4807-84f1-1c82854f7ee5", "445002fb-a6f2-4dc1-a81e-4254a111cd29",
        "44882612-f346-430a-b938-4f00ee1c77a7", "44d6b5f2-d42b-4fa7-b999-1c5fcab98e4d",
        "4585ecca-5b47-432f-ac70-e1391e4951ed", "465a38f9-76ea-45b9-9f34-9e8b0d4b0b42",
        "471f2a7f-2a42-4d45-a2bf-594d0838070d", "48ac35b8-9aa8-4d74-927d-1f4a14a0b239",
        "48fec646-b2ba-4019-8681-8eb31435aded", "4ae1bf56-f562-4747-b7bc-2fa0874ed46f",
        "4bae2ed4-473e-4841-a493-9829cfd51d48", "4e0d77b0-96ba-4398-af14-3baa780278f4",
        "4e46008b-f24c-477d-8fff-7bb4ec7aafe0", "4eabc3d1-b762-40ff-9da5-0e18fdf11230",
        "501d06f8-07b8-4f18-b5c6-c191a4af7a82", "518528c3-6969-4554-b49e-73f7f0227e7e",
        "52dc2051-4958-4636-8f2a-281d39c6981c", "56680e0d-d2a3-4ae1-80d8-3c4f2100e3d0",
        "570282fd-fa5c-430d-a7fd-fc8dc98a9dca", "572fea84-0151-49b2-9301-11cb16974376",
        "5af8c3f5-baca-439a-97b0-ea58a435e269", "5b625b3d-65b6-4fb0-85d9-8a5aa26bdf36",
        "5b9be81f-2977-4d27-8faf-bb43af8fc705", "5c28f0bf-8a70-41f1-8ab2-9032436ddb65",
        "5df07973-7d5d-46ed-9847-1271055cbd51", "5eb43c10-865a-4259-960a-83946678f8dd",
        "5f8c59db-677d-491f-a6b8-5f174b11ec1d", "6222dbab-a24c-4210-9d91-2f47cf565614",
        "640ddd16-e5b7-4d71-9690-3f4022699ee7", "652390e4-393a-48de-9484-05f9b1212954",
        "652d7d02-6ff0-4cf7-9516-cf77d33a3ae4", "6768d3af-4562-48ff-82d2-c5e19eb21b9c",
        "6aedf524-7e1c-45a7-bd76-ded8cab8d0fc", "7504609f-c495-4c64-8542-686125a5a36f",
        "75767999-c7a8-481e-a6b4-19458e0b30a5", "765f423e-b55d-412e-97e3-13a800c3a537",
        "76e2ebd5-0dfb-4a5b-93c7-ed89e0362834", "76faac2a-0f20-42f1-928a-50de5b9dbe52",
        "78ce3f0f-a1ce-49c2-8cde-64b5c0896db4", "7a27a256-301d-4359-b77b-c2b759d2e362",
        "7ab1d787-bae7-4d5d-8db6-37ea32df9186", "7b8a2d34-6b3f-4542-a343-54651608ad81",
        "7b9103a5-4610-446b-9670-80643382c1fa", "7e823077-d88e-468f-a337-e18f1f0e6c7c",
        "7f33e027-4039-419b-938e-2f8ca153e68e", "7f36b48e-542f-4d3b-9bcb-8406f0ab9fdb",
        "818c620a-27a9-40bd-a6a5-d96f7d610b4b", "82305458-296d-4edd-8b0b-74dd74c34526",
        "82866913-39a9-4be7-8091-f4fa781088ae", "8458e264-4eb9-4922-abe9-768d58f13c7f",
        "84bccea3-f856-4a8a-967b-dbe0a3d53a64", "863451e7-0667-486c-a5d6-d135439485f0",
        "87f447af-9fa4-4c32-9dfa-4a57a73d18ce", "89d944f2-2011-44ad-830c-aa9bf5ef2319",
        "89fe6a52-be36-487e-b7d8-d061c450a026", "8b01a991-5a5a-47f8-91a2-84d6bfd72c02",
        "91e7d36d-022a-490f-a748-f8e011357b42", "948eb538-f19d-4ec5-9ccc-f059e1ea4c72",
        "96d46335-d92d-41b8-bc9f-273a692381ea", "9769c687-087d-48ac-9cb3-c37dde652038",
        "9aaa3660-6678-4cb8-b4b5-be92b6f4fbf0", "9be106e1-f4e3-4df5-bdff-e4bc531cbe43",
        "9d8982ae-4365-4f57-95e9-d6032a4c0b87", "9f89e109-94b9-4c9b-b4fc-98cdaa54f574",
        "9ff18859-b8d5-4a89-9912-448b84dfb097", "9ff7295e-131b-4d94-90e1-69fde507ac11",
        "a0244d16-171c-4496-8ffb-7b9b6954d339", "a154be20-db9c-4678-8ab7-66f6cc099a59",
        "a367ab51-6b49-43bf-a716-a1fb06d2a174", "a4b8392a-d8d1-4954-a029-8e668a39a170",
        "a65f2972-a4f8-4f5e-afd7-69ccb046d5dc", "ab4f2b77-0b06-4fc1-a9de-02113fc2ab7c",
        "ad13ac2e-ad46-4dc0-b7da-249c94395a6d", "ad902697-1014-4ef5-81ef-2b4301988e8c",
        "b09ec548-3f99-4d0a-859c-c9b7ff53b7a9", "b11fa0e7-fdb7-4dc9-b1f1-59facd463480",
        "b152eca8-ea73-4a48-8c98-1a6742673d99", "b271f05e-8329-4b97-baa4-91cf15b99cf1",
        "b2f1b2fa-f35c-407c-979c-a858a808ba85", "b3f70a70-8a4b-4f95-9573-d71c496a53f4",
        "b3fa7c4c-aab5-4f0c-8311-a36528f007b6", "b43e1ada-25ee-416f-bd5c-512976ddc74b",
        "b7887744-6746-4312-813d-72daeaee7e2d", "b98bfd41-87c6-45cc-b104-e2de4f0dafb9",
        "ba6d575a-1344-4516-b777-1404f5593057", "bac3b9c2-b516-4ef4-bd3b-c2ef73d8d804",
        "bbd1ca91-75e0-4814-ad94-9c5dbbae3415", "bdfbf15f-ee85-4955-8675-146e8e5296b5",
        "c0bdd4d3-3be2-4b90-8f94-aba44d5552eb", "c1499fe0-52b1-4b22-bed2-7a244e0e879f",
        "c34088fb-0649-4714-af0b-bcbfec155897", "c5366453-9fb0-48a5-a156-24f0c49a4b84",
        "c67b52c5-7c69-48b6-9d48-7b3af3ded914", "cd1cb034-c558-413b-b2ad-17bb007192da",
        "cdcdac3a-fd45-410d-83ef-554db620e5c7", "d01b97e9-cbc0-49fe-810a-750afd5527a3",
        "d05743e4-fb24-4dff-8a33-0f6c73c964bd", "d2bc95fc-440e-4b0e-bafd-97182de7aef5",
        "d2e42f6b-2baf-4ff4-83ef-51e66321516e", "d36ad51d-15a2-458d-9b3a-16dbe4c51c30",
        "d56682ec-c09e-4743-aaf4-1a3aac4caa21", "d594897b-76e7-4b2b-984b-b4adff35e109",
        "d660a04c-7b62-4b4c-bea3-89226df00142", "d7b7f2d9-0f45-4ea1-9d42-e50810c06991",
        "d8914f8f-9f64-4bd1-b4d3-f5a701ed8457", "d8d0355c-460d-46fd-bc17-af170848113d",
        "da710fc9-1e83-407b-8c5c-09d225031769", "dab085de-3e14-432f-a47f-84b6457059c4",
        "dbe6434c-63f0-42bb-be8e-122ec1bad4d2", "ddb3ca45-a192-477d-acb2-46bf9dc586de",
        "ddd37690-e119-40c5-a821-3746ea6125c4", "df85f4d6-205c-4ac5-a5ea-6bf408dba283",
        "e0a7cdbb-08b0-4697-8264-0069786e9674", "e383f46e-2787-4529-855e-0e479a3ffac0",
        "e45c5562-459d-4d1b-8148-83eb1b6dcf83", "e4aa47b9-9a69-4109-82ed-36ec70d85ff1",
        "e4c9e354-4dc5-45b8-9e7c-e1393b0b1a20", "e677843f-76d8-44d3-bcdb-ec40dea919e7",
        "e7e732bd-932b-45c4-8ce5-40d60a7daad9", "e843bc88-e493-446d-a73c-0ded7ff1913f",
        "e9cbd5de-0031-493e-8fb1-60712d03cc8b", "eb665d05-7f76-4d1b-b176-1cfc814e668d",
        "ebf0f66e-9fb1-49e4-a278-222f76911cf4", "ef4b5d93-3104-4664-9053-a5c49ab44218",
        "f266d9c0-ccb9-4fb8-a228-01ac0d8d6627", "f3076109-ca66-412a-be10-d4ee1be95d47",
        "f501c180-9344-439a-bca0-6cbf209fd270", "f534bf13-55d4-45a9-8f3c-c92fe64d6131",
        "f7cd536d-e34c-4fb9-bc7f-2a2c30d7de9f", "f9759906-80a4-4f4a-b010-24b832bc6a30",
        "fb698133-92fa-453e-a9ed-688e10f2e5ac", "ff74d97f-43af-4b68-9f2a-b77ee6968c5d",
        "ff91d191-45a0-43fd-b837-bd682c4a0b0f", "ffa91d43-2ad8-45cc-b592-09caddeb24bb",
    }
)

# Values of these keys (compared as ``_norm``, so ``client_secret``, ``Client-Secret`` and ``clientSecret`` are
# one key) are credentials whatever their shape: a non-empty value of any type is replaced whole.
_SECRET_KEYS = frozenset(
    {
        "client_secret", "secret_text", "app_secret", "password", "access_token", "refresh_token",
        "id_token", "api_token", "api_key", "key_material", "dsc_export", "private_key",
    }
)

# Keys whose values are controlled vocabulary or structure (ids of findings and policies, setting names, reason codes,
# statuses, verdicts, sections, kinds, cells, roles): a user's name is never substituted into them, whatever the
# user is called. Compared as ``_norm``. Identifiers (GUIDs, e-mail addresses, immutable ids) in them are still masked.
_CONTROLLED_KEYS = frozenset(
    {
        "id", "ids", "findingid", "findingids", "policyid", "policyids", "ruleid", "ruleids", "checkid", "controlid",
        "setting", "settings", "settingname", "settingnames", "reason", "reasons", "reasoncode", "reasoncodes", "code",
        "errorcode", "errorclass", "status", "severity", "verdict", "section", "sections", "kind", "cell", "cellid",
        "collector", "priority", "type", "format", "principaltype", "state", "outcome", "result", "category", "level",
        "role", "rolename", "rolenames", "roledisplayname", "roledefinitionname",
    }
)
_ROLE_KEYS = frozenset({"role", "rolename", "rolenames", "roledisplayname", "roledefinitionname", "roles"})
# Words that read as report vocabulary: a privileged user who happens to be called one of them keeps the word in
# free text (their structured ``display_name`` is still pseudonymised).
_STATIC_VOCABULARY = frozenset(
    {
        "open", "closed", "pass", "fail", "warning", "critical", "high", "medium", "info", "error", "true", "false",
        "none", "null", "unknown", "enabled", "disabled", "status", "severity", "verdict", "owner", "accepted",
        "resolved", "blocked", "partial", "complete", "manual", "ok", "warn", "skipped", "low", "unavailable",
    }
)
# By shape: policy ids (``MS.EXO.4.1v1``), snake_case and UPPER_SNAKE codes (``not_collected``) are structure
# wherever they appear; a user called one of them keeps it readable in free text (the structured name field is
# still pseudonymised).
_STRUCTURAL_SHAPES = (
    re.compile(r"^[A-Za-z]{2,}(?:\.[A-Za-z0-9]+)+\.\d+v\d+$"),
    re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$"),
    re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$"),
)


def _structural(text: str) -> bool:
    return any(shape.match(text) for shape in _STRUCTURAL_SHAPES)


# Finding ids are ``<namespace>:<snake_case_words>[:<guid-or-digest>]`` (``identity:global_admin_stale_password:<guid>``).
# A credential word inside such an id (``..._password:<guid>``) is part of the name, not an assignment, so the inline
# secret pattern must not read it as ``password: <value>``. The exemption is deliberately narrow and exact:
#
# * the namespace is one of ``_ID_NAMESPACES`` (the namespaces the finding producers under ``src/`` emit; a test scans
#   the producers and fails when one is missing), never a credential word;
# * the words carry at least one underscore, lower case only;
# * the optional suffix is a dashed GUID, a lower-case hex digest of 16 to 64 digits or a decimal number;
# * the token is not preceded by a word, ``:``, ``.`` or ``-`` and is not followed by a word character, ``:`` or ``=``,
#   so ``identity:db_password:hunter2``, ``identity:db_password=x``, ``config:db_password:x`` and
#   ``identity:global_admin_stale_password:<guid>:hunter`` are all still read as credentials and redacted.
#
# Everything is one regular expression run in one left-to-right pass (the id alternative is tried first at every
# position, the inline secret pattern second): linear in the text, no recursion, no second scan.
_ID_NAMESPACES = (
    "admin_set_unknown", "app", "app_consent", "app_credentials", "attack_path", "category", "conditional_access",
    "conditional_access_policy", "conditional_access_relationship", "consent_policy", "coverage_gap",
    "cross_tenant_access", "detection_coverage", "dns_posture", "exchange", "exchange_policy", "exchange_remote_domain",
    "exchange_transport", "exposure", "external_identity", "google_admin_resilience", "google_policies", "identity",
    "identity_governance", "intune", "intune_depth", "mailbox_forwarding", "onedrive_posture", "reports_usage",
    "response", "secure_score", "security_directory_audit", "security_signin", "service_health", "sharepoint",
    "sharepoint_permission", "sharepoint_site_posture", "sharepoint_tenant", "teams_policy",
)
_CREDENTIAL_NAMESPACES = frozenset(
    {"access", "refresh", "id", "client", "secret", "password", "authorization", "api", "token", "key", "bearer"}
)
_ID_GUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
_ID_TOKEN = (
    r"(?-i:(?<![\w:.-])(?:" + "|".join(sorted(_ID_NAMESPACES, key=len, reverse=True)) + r")"
    r":[a-z][a-z0-9]*(?:_[a-z0-9]+)+"
    rf"(?::(?:{_ID_GUID}|[0-9a-f]{{16,64}}|[0-9]{{1,20}}))?(?![\w:=]))"
)
_INLINE_OR_ID_RE = re.compile(rf"(?P<idtoken>{_ID_TOKEN})|{INLINE_SECRET_RE.pattern}", INLINE_SECRET_RE.flags)


def _redact_inline_secrets(value: str) -> str:
    """``INLINE_SECRET_RE`` over ``value``, except that a credential word inside a finding id is left alone."""

    def inline(match: re.Match[str]) -> str:
        if match["idtoken"] is not None:
            return match[0]
        raw = match["value"]
        quote = raw[0] if len(raw) >= 2 and raw[0] in "\"'" and raw[-1] == raw[0] else ""
        return f"{match['prefix']}{quote}{SECRET_PLACEHOLDER}{quote}"

    return _INLINE_OR_ID_RE.sub(inline, value)


# Credentials carried by a URL: the password of ``scheme://user:password@host`` and the value of a credential-looking
# query or fragment parameter (OAuth tokens and codes, shared-access-signature fields, API keys). The URL syntax stays.
_URL_USERINFO_RE = re.compile(r"(?P<head>\b[A-Za-z][A-Za-z0-9+.-]{1,15}://[^\s/@:?#\"'<>]*:)(?P<password>[^\s/@?#\"'<>]+)(?=@)")
_URL_PARAMETERS = (
    "access_token", "refresh_token", "id_token", "token", "sig", "signature", "code", "password", "passwd", "pwd",
    "secret", "client_secret", "key", "api_key", "apikey", "sv", "se", "sp", "sr", "spr", "st", "skoid", "sktid",
    "sas", "sastoken", "auth", "authorization", "assertion", "jwt", "bearer",
)
_URL_PARAMETER_RE = re.compile(
    r"(?P<lead>[?&;#])(?P<name>" + "|".join(_URL_PARAMETERS) + r")(?P<eq>=)(?P<value>[^&;\s#\"'<>]*)", re.IGNORECASE
)


def _redact_url_credentials(value: str) -> str:
    """URL userinfo passwords and credential parameters of ``value`` replaced by ``SECRET_PLACEHOLDER``."""
    if "=" not in value and "://" not in value:
        return value
    value = _URL_USERINFO_RE.sub(lambda m: m["head"] + SECRET_PLACEHOLDER, value)
    return _URL_PARAMETER_RE.sub(lambda m: m["lead"] + m["name"] + m["eq"] + SECRET_PLACEHOLDER, value)


_IMMUTABLE_PREFIX = "Id "
_USER_PREFIX = "User "
_HEX16 = r"[0-9a-f]{16}"
_PSEUDONYM_RE = re.compile(rf"^(?:User|Id|Group) {_HEX16}$")
_PSEUDONYM_KEEP = rf"(?P<keep>(?<!\w)(?:User|Id|Group) {_HEX16}(?!\w))"
_GUID_PSEUDONYM_PREFIX = "00000000-0000-4000-8000-"
_DOMAIN_PSEUDONYM_RE = re.compile(r"^domain-[0-9a-f]{12}\.invalid$")
_GUID_RE = OUTPUT_GUID_RE
# The e-mail forms the plain pattern cannot see: the at sign spelled ``%40``, ``@``, ``&#64;`` or full-width.
# Same start rules and bounds as ``OUTPUT_EMAIL_RE``; the local part may carry percent- and ``\u`` escapes.
_ENCODED_EMAIL_RE = re.compile(
    r"(?:(?<![\w.!#$%*=^`{}~\\-])|(?<=\\[nrtbf])|(?<=%2[07]))"
    r"(?P<local>(?:\\u[0-9a-fA-F]{4}|%[0-9a-fA-F]{2}|[\w.!#$&'*+=?^`{|}~-]){1,64}?)"
    r"(?P<sep>%40|\\u0040|&#64;|＠)"
    r"(?P<domain>[\w](?:[\w.-]{0,251}[\w])?)",
    re.IGNORECASE,
)
_IDENTITY_KEYS = ("onpremisesimmutableid", "immutableid")
_ADMIN_FLAGS = ("isadmin", "isdelegatedadmin", "issuperadmin", "isprivileged")
_NOT_USER_TYPES = frozenset({"group", "serviceprincipal", "application", "app", "device"})


def _norm(key: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


_SECRET_NORMS = frozenset(_norm(key) for key in _SECRET_KEYS)


@dataclass(frozen=True)
class RedactionContext:
    """Per-output inputs: everything that is not in the value itself.

    ``salt`` is the run salt (see ``run_salt``); with an empty salt the pseudonyms are still deterministic but
    carry no run separation. ``run_paths`` are the spellings of the operator's run directory to remove.
    ``protected_names`` and ``protected_ids`` are privileged-user display names and immutable ids the caller
    already knows (``context_for_run`` reads them from the run's ``normalized/`` records, so they hold whichever
    sections the output selects; any found inside the value are added automatically). ``vocabulary`` is
    controlled vocabulary (role names) that a user's name must never rewrite. ``domains`` extends the domain
    set when the domain policy is on. ``policy`` replaces the profile's own ``PROFILE_POLICY`` entry (``None``: use it).
    """

    salt: str = ""
    run_paths: tuple[str, ...] = ()
    protected_names: frozenset[str] = frozenset()
    domains: frozenset[str] = frozenset()
    policy: ProfilePolicy | None = None
    protected_ids: frozenset[str] = frozenset()
    vocabulary: frozenset[str] = frozenset()
    incomplete: bool = False
    # What made the context incomplete, as safe ``(label, reason class)`` pairs (see ``ContextIncompleteError``) and
    # the same as ``"<label>: <reason class>"`` strings; ``incomplete_omitted`` counts problems beyond the kept ones.
    incomplete_reasons: tuple[str, ...] = ()
    incomplete_files: tuple[tuple[str, str], ...] = ()
    incomplete_omitted: int = 0


def pseudonym(salt: str, text: str) -> str:
    """The projection's pseudonym: the first 16 hex digits of ``sha256(salt NUL text)``."""
    return hashlib.sha256((salt + "\0" + text).encode("utf-8", "surrogatepass")).hexdigest()[:16]


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def run_salt(run_dir: str | Path) -> str:
    """The salt ``scuba_projection.project_run`` uses: SHA-256 of the canonical ``run-manifest.json``.

    A missing or unusable manifest gives the digest of ``{}``, as the projection does. Never persisted.
    """
    try:
        manifest = json.loads((Path(run_dir) / "run-manifest.json").read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            raise ValueError
        return hashlib.sha256(_canonical(manifest).encode()).hexdigest()
    except (OSError, ValueError, TypeError, RecursionError, UnicodeError):
        return hashlib.sha256(_canonical({}).encode()).hexdigest()


def run_path_roots(run_dir: str | Path) -> tuple[str, ...]:
    """Every spelling of the run directory a payload may carry, longest first."""
    run_path = Path(run_dir)
    roots = {str(run_path), os.path.abspath(run_path), os.path.realpath(run_path)}
    return tuple(sorted((r.rstrip(os.sep) for r in roots if r and r != os.sep), key=len, reverse=True))


_ROOT_PATTERNS: dict[tuple[str, ...], re.Pattern[str]] = {}


def _root_pattern(roots: tuple[str, ...]) -> re.Pattern[str]:
    pattern = _ROOT_PATTERNS.get(roots)
    if pattern is None:
        # A root is a whole path prefix: not the tail of a longer word or path, and not the start of a longer name
        # (``/tmp/run2``, ``/tmp/run.bak``); a sentence's closing full stop still ends it.
        pattern = re.compile(r"(?<![\w.~-])(?:" + "|".join(re.escape(r) for r in roots) + r")(?![\w-]|\.\w)")
        if len(_ROOT_PATTERNS) > 64:
            _ROOT_PATTERNS.clear()
        _ROOT_PATTERNS[roots] = pattern
    return pattern


def scrub_run_paths(text: str, roots: Iterable[str]) -> str:
    """Paths below the run become run-relative (when the text starts with one), the run itself ``<run-dir>``;
    every other occurrence of the run path becomes ``<run-dir>``. The result holds no root and is stable."""
    unique = tuple(sorted({r for r in roots if r}, key=lambda r: (-len(r), r)))
    if not unique or not text:
        return text
    for root in unique:
        if text == root:
            return RUN_DIR_PLACEHOLDER
        if text.startswith(root + os.sep):
            text = text[len(root) + 1:]
            break
    return _root_pattern(unique).sub(RUN_DIR_PLACEHOLDER, text)


# -- identities found in the data ---------------------------------------------------------------------------------


def _is_privileged_user(record: Mapping[Any, Any]) -> bool:
    keys = {_norm(k): v for k, v in record.items()}
    if str(keys.get("principaltype", "")).lower() in _NOT_USER_TYPES:
        return False
    if "onpremisesimmutableid" in keys or "immutableid" in keys:
        return True
    if any(keys.get(flag) is True for flag in _ADMIN_FLAGS):
        return True  # Google Workspace super and delegated administrators, and records flagged privileged
    if str(keys.get("principaltype", "")).lower() == "user" and ("roles" in keys or "rolenames" in keys or "counted" in keys):
        return True
    return keys.get("isuser") is True and ("roles" in keys or "rolenames" in keys)


def _is_group(record: Mapping[Any, Any]) -> bool:
    return str({_norm(k): v for k, v in record.items()}.get("principaltype", "")).lower() == "group"


@dataclass
class _Found:
    names: set[str] = field(default_factory=set)
    ids: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    vocabulary: set[str] = field(default_factory=set)
    keys: set[str] = field(default_factory=set)
    limit_hits: int = 0  # JSON-looking strings above ``_MAX_EMBEDDED_JSON_CHARS`` that were not parsed

    def merge(self, other: "_Found") -> None:
        self.names |= other.names
        self.ids |= other.ids
        self.domains |= other.domains
        self.vocabulary |= other.vocabulary
        self.keys |= other.keys
        self.limit_hits += other.limit_hits


class _Num:
    """A JSON number kept as the literal it was written as: never re-parsed, so it cannot round, overflow to
    ``Infinity`` or lose its sign."""

    __slots__ = ("raw",)

    def __init__(self, raw: str) -> None:
        self.raw = raw

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"_Num({self.raw!r})"


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


# JSON embedded in a string is parsed (to find identities in it and to redact it as structure) up to this many
# characters. A longer string that looks like JSON is not parsed and is never passed on as if it had been: discovery
# and redaction both treat it as an incomplete context and fail closed (``_EmbeddedLimitError``).
_MAX_EMBEDDED_JSON_CHARS = 16 * 1024 * 1024
_JSON_START_RE = re.compile(r"\s*[\[{]")


def _maybe_json(text: str) -> Any:
    """The parsed value of a string that is a JSON object or array, else ``None``. Numbers are ``_Num``; the
    non-standard ``NaN`` and ``Infinity`` make the text not JSON. Raises ``_EmbeddedLimitError`` for a string longer
    than ``_MAX_EMBEDDED_JSON_CHARS`` that starts like JSON."""
    if len(text) > _MAX_EMBEDDED_JSON_CHARS and _JSON_START_RE.match(text):
        raise _EmbeddedLimitError
    stripped = text.strip()
    if len(stripped) < 2 or stripped[0] not in "{[" or stripped[-1] not in "}]":
        return None
    try:
        parsed = json.loads(stripped, parse_float=_Num, parse_int=_Num, parse_constant=_reject_constant)
    except RecursionError as exc:
        raise RedactionDepthError("embedded JSON is nested too deeply to redact") from exc
    except ValueError:
        return None
    return parsed if isinstance(parsed, (dict, list)) else None


def _collect(value: Any, found: _Found, *, names: bool, domains: bool) -> None:
    """Privileged-user display names, immutable ids, role vocabulary and key names found anywhere in ``value``
    (JSON embedded in a string included), so the same strings are replaced inside free text of the same output."""
    stack = [value]
    # Visited containers are kept alive here, not only their ids: a parsed embedded record that is freed would
    # hand its id to the next one parsed, which would then be skipped as "seen" and its identities lost.
    seen: dict[int, Any] = {}
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            if domains:
                for match in OUTPUT_EMAIL_RE.finditer(item):
                    found.domains.add(match["domain"].lower())
                for match in _ENCODED_EMAIL_RE.finditer(item):
                    found.domains.add(match["domain"].lower())
            if names and item[:1] in ("{", "[", " ", "\n", "\t"):
                try:
                    parsed = _maybe_json(item)
                except _EmbeddedLimitError:
                    found.limit_hits += 1
                    continue
                if parsed is not None:
                    stack.append(parsed)
        elif isinstance(item, Mapping):
            if id(item) in seen:
                continue
            seen[id(item)] = item
            if names:
                privileged = _is_privileged_user(item)
                for key, member in item.items():
                    norm = _norm(key)
                    if isinstance(key, str) and len(key) <= 64 and "@" not in key:
                        found.keys.add(key.lower())
                    if privileged and norm == "displayname" and isinstance(member, str) and member and not _PSEUDONYM_RE.match(member):
                        found.names.add(member)
                    if norm in _IDENTITY_KEYS and isinstance(member, str) and member and not _PSEUDONYM_RE.match(member):
                        found.ids.add(member)
                    if norm in _ROLE_KEYS:
                        if isinstance(member, str) and member:
                            found.vocabulary.add(member.lower())
                        elif isinstance(member, (list, tuple)):
                            found.vocabulary.update(m.lower() for m in member if isinstance(m, str) and m)
            stack.extend(item.values())
            stack.extend(k for k in item if isinstance(k, str) and domains)
        elif isinstance(item, (list, tuple, set, frozenset)):
            if id(item) in seen:
                continue
            seen[id(item)] = item
            stack.extend(item)


# -- contexts ---------------------------------------------------------------------------------------------------------

# Discovery limits. Hitting one is never silent: the context is flagged ``incomplete`` (see ``RedactionContext``).
_MAX_SCAN_FILES = 5_000            # ``normalized/**/*.json`` files per run
_MAX_FILE_BYTES = 32 * 1024 * 1024  # one file; a larger one is not read
_MAX_SCAN_BYTES = 128 * 1024 * 1024  # all files of one run together
_MAX_SCAN_DEPTH = 32               # directory levels below ``normalized/``
_MAX_REASONS = 20                  # problems a context keeps (the rest is only counted)
_MAX_LISTED_FILES = 10             # problems a refusal names (the rest is only counted)

# Why a file could not be used. A label and one of these classes are all a refusal ever says about a file.
REASON_UNREADABLE = "unreadable"
REASON_MALFORMED = "malformed JSON"
REASON_OVERSIZE = "oversize"
REASON_NON_REGULAR = "non-regular"
REASON_DANGLING = "dangling link"
REASON_LIMIT = "limit"
REASON_OUTSIDE = "outside run"
REASON_CHANGED = "changed during scan"

_SAFE_SEGMENT_RE = re.compile(r"^[a-z][a-z0-9_]{0,47}(?:\.json)?$")
_CREDENTIAL_WORD_RE = re.compile(r"password|passwd|secret|token|apikey|api_key|authorization|bearer|credential", re.IGNORECASE)
_LONG_DIGITS_RE = re.compile(r"[0-9]{6,}")


def _safe_label(parts: Iterable[str]) -> str:
    """A run-relative path that is safe to show: a segment is kept only when it is a short lower-case snake_case
    section name (``normalized``, ``identity_users.json``) with no credential word and no long digit run; every
    other segment (a name, an address, a GUID, a credential or anything else a file can be called) becomes
    ``<redacted-segment-N>``, N being its 1-based position in the path. The run directory is never part of it."""
    shown = []
    for index, part in enumerate(parts, start=1):
        keep = bool(_SAFE_SEGMENT_RE.match(part)) and not _CREDENTIAL_WORD_RE.search(part) and not _LONG_DIGITS_RE.search(part)
        shown.append(part if keep else f"<redacted-segment-{index}>")
    return "/".join(shown) or "<run>"


class _EmbeddedLimitError(Exception):
    """A JSON-looking string is longer than ``_MAX_EMBEDDED_JSON_CHARS`` (internal; becomes a ``limit`` reason)."""


class _Unsafe(Exception):
    """A file or directory cannot be used; ``reason`` is one of the ``REASON_*`` classes."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


_DIR_MODE = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
_FILE_MODE = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)


def _inside(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def _open_dir_at(parent_fd: int, name: str, expected: os.stat_result | None = None) -> int:
    """A directory descriptor for ``name`` below ``parent_fd``, opened without following a link and checked on the
    descriptor (type, and identity when ``expected`` is the earlier ``lstat``)."""
    try:
        descriptor = os.open(name, _DIR_MODE, dir_fd=parent_fd)
    except FileNotFoundError as exc:
        raise _Unsafe(REASON_CHANGED) from exc
    except PermissionError as exc:
        raise _Unsafe(REASON_UNREADABLE) from exc
    except OSError as exc:  # a symlink or a non-directory in the way: the tree changed under us
        raise _Unsafe(REASON_CHANGED) from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode) or (expected is not None and (info.st_dev, info.st_ino) != (expected.st_dev, expected.st_ino)):
            raise _Unsafe(REASON_CHANGED)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _read_file_at(parent_fd: int, name: str, expected: os.stat_result) -> bytes:
    """The bytes of regular file ``name`` below ``parent_fd``: never following a link, never blocking, identity and
    type re-checked on the descriptor, at most ``_MAX_FILE_BYTES``."""
    try:
        descriptor = os.open(name, _FILE_MODE, dir_fd=parent_fd)
    except FileNotFoundError as exc:
        raise _Unsafe(REASON_CHANGED) from exc
    except PermissionError as exc:
        raise _Unsafe(REASON_UNREADABLE) from exc
    except OSError as exc:
        raise _Unsafe(REASON_CHANGED) from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise _Unsafe(REASON_NON_REGULAR)
        if (info.st_dev, info.st_ino) != (expected.st_dev, expected.st_ino):
            raise _Unsafe(REASON_CHANGED)
        if info.st_size > _MAX_FILE_BYTES:
            raise _Unsafe(REASON_OVERSIZE)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1 << 20, _MAX_FILE_BYTES + 1 - total))
            if not chunk:
                return b"".join(chunks)
            total += len(chunk)
            if total > _MAX_FILE_BYTES:
                raise _Unsafe(REASON_OVERSIZE)
            chunks.append(chunk)
    except OSError as exc:
        raise _Unsafe(REASON_UNREADABLE) from exc
    finally:
        os.close(descriptor)


def _open_chain(root_fd: int, parts: tuple[str, ...]) -> tuple[int, str]:
    """``(directory descriptor, final name)`` for the file ``parts`` below ``root_fd``, every directory opened
    without following links (an ancestor swapped for a symlink is refused). The caller closes the descriptor."""
    current = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            nxt = _open_dir_at(current, part)
            os.close(current)
            current = nxt
        return current, parts[-1]
    except BaseException:
        os.close(current)
        raise


def _link_reader(run_real: str, dir_fd: int, parts: tuple[str, ...], name: str) -> tuple[Callable[[], bytes], int] | None:
    """A symlink below ``normalized/``: a ``.json`` link to a regular file inside the run is read through its
    resolved path (every ancestor opened without following links); a link to a directory is not followed.

    Returns ``(reader, size)``, ``None`` for a link that is not a ``.json`` file, or raises ``_Unsafe``.
    """
    is_json = name.lower().endswith(".json")
    try:
        target_info = os.stat(name, dir_fd=dir_fd)
    except FileNotFoundError:
        if is_json:
            raise _Unsafe(REASON_DANGLING) from None
        return None
    except OSError:
        if is_json:
            raise _Unsafe(REASON_UNREADABLE) from None
        return None
    if stat.S_ISDIR(target_info.st_mode):
        raise _Unsafe(REASON_NON_REGULAR)  # a symlinked directory is not followed
    if not is_json:
        return None
    target = os.path.realpath(os.path.join(run_real, *parts, name))
    if not _inside(target, run_real) or target == run_real:
        raise _Unsafe(REASON_OUTSIDE)
    if not stat.S_ISREG(target_info.st_mode):
        raise _Unsafe(REASON_NON_REGULAR)
    relative = tuple(Path(target).relative_to(run_real).parts)

    def reader() -> bytes:
        root_fd = os.open(run_real, _DIR_MODE)
        try:
            parent_fd, leaf = _open_chain(root_fd, relative)
        finally:
            os.close(root_fd)
        try:
            return _read_file_at(parent_fd, leaf, target_info)
        finally:
            os.close(parent_fd)

    return reader, target_info.st_size


class _Scan:
    def __init__(self, run_real: str) -> None:
        self.run_real = run_real
        self.found = _Found()
        self.problems: list[tuple[tuple[str, ...], str]] = []
        self.files = 0
        self.budget = _MAX_SCAN_BYTES

    def problem(self, parts: tuple[str, ...], reason: str) -> None:
        self.problems.append((parts, reason))

    def collect(self, parts: tuple[str, ...], data: bytes) -> None:
        try:
            payload = json.loads(data.decode("utf-8"))
            local = _Found()
            _collect(payload, local, names=True, domains=False)
        except (ValueError, RecursionError):  # malformed JSON, bad encoding, too deeply nested
            self.problem(parts, REASON_MALFORMED)
            return
        self.found.merge(local)
        if local.limit_hits:
            self.problem(parts, REASON_LIMIT)

    def take(self, parts: tuple[str, ...], reader: Callable[[], bytes], size: int) -> None:
        if self.files >= _MAX_SCAN_FILES:
            self.problem(parts, REASON_LIMIT)
            return
        self.files += 1
        if size > _MAX_FILE_BYTES:
            self.problem(parts, REASON_OVERSIZE)
            return
        if size > self.budget:
            self.problem(parts, REASON_LIMIT)
            return
        self.budget -= size
        try:
            data = reader()
        except _Unsafe as exc:
            self.problem(parts, exc.reason)
            return
        self.collect(parts, data)

    def symlink(self, dir_fd: int, parts: tuple[str, ...], name: str) -> None:
        """A symlink below ``normalized/`` (see ``_link_reader``)."""
        here = (*parts, name)
        try:
            resolved = _link_reader(self.run_real, dir_fd, parts, name)
        except _Unsafe as exc:
            self.problem(here, exc.reason)
            return
        if resolved is not None:
            self.take(here, *resolved)

    def _enter(self, frames: list["_Frame"], descriptor: int, parts: tuple[str, ...], depth: int) -> None:
        """Push the directory ``descriptor`` (owned from here on) unless it is too deep or cannot be listed."""
        try:
            if depth > _MAX_SCAN_DEPTH:
                self.problem(parts, REASON_LIMIT)
            else:
                frames.append(_Frame(descriptor, parts, sorted(os.listdir(descriptor))))
                return
        except OSError:
            self.problem(parts, REASON_UNREADABLE)
        os.close(descriptor)

    def walk(self, root_fd: int, root_parts: tuple[str, ...]) -> None:
        """Every ``*.json`` below the descriptor (which is closed here), depth first, names sorted; nothing but a
        regular file is opened, and at most ``_MAX_SCAN_DEPTH`` + 1 descriptors are open at once."""
        frames: list[_Frame] = []
        try:
            self._enter(frames, root_fd, root_parts, 0)
            while frames:
                frame = frames[-1]
                if frame.position >= len(frame.names):
                    os.close(frame.descriptor)
                    frames.pop()
                    continue
                name = frame.names[frame.position]
                frame.position += 1
                here = (*frame.parts, name)
                try:
                    info = os.stat(name, dir_fd=frame.descriptor, follow_symlinks=False)
                except OSError:
                    self.problem(here, REASON_CHANGED)
                    continue
                mode = info.st_mode
                if stat.S_ISDIR(mode):
                    try:
                        child = _open_dir_at(frame.descriptor, name, info)
                    except _Unsafe as exc:
                        self.problem(here, exc.reason)
                    else:
                        self._enter(frames, child, here, len(frames))
                elif stat.S_ISLNK(mode):
                    self.symlink(frame.descriptor, frame.parts, name)
                elif not name.lower().endswith(".json"):
                    continue
                elif not stat.S_ISREG(mode):
                    self.problem(here, REASON_NON_REGULAR)  # FIFO, socket, device: never opened
                else:
                    self.take(here, lambda d=frame.descriptor, n=name, i=info: _read_file_at(d, n, i), info.st_size)
        finally:
            for frame in frames:
                os.close(frame.descriptor)


class _Frame:
    __slots__ = ("descriptor", "parts", "names", "position")

    def __init__(self, descriptor: int, parts: tuple[str, ...], names: list[str]) -> None:
        self.descriptor = descriptor
        self.parts = parts
        self.names = names
        self.position = 0


def read_run_json(run_dir: str | Path, relative: str, fallback: Any = None) -> Any:
    """The parsed JSON of one file below a run directory, read with the guarded reader, else ``fallback``.

    Used for every ``normalized/`` record a report reads: the file is opened below a descriptor of the run directory,
    no component may be a symlink (a link to a regular file inside the run is the one exception), the descriptor is
    checked to be a regular file of at most ``_MAX_FILE_BYTES``, and nothing ever blocks (FIFO, device, socket).
    """
    parts = tuple(part for part in relative.replace("\\", "/").split("/") if part not in ("", "."))
    if not parts or ".." in parts:
        return fallback
    run_real = os.path.realpath(run_dir)
    try:
        run_fd = os.open(run_real, _DIR_MODE)
    except OSError:
        return fallback
    try:
        parent_fd, leaf = _open_chain(run_fd, parts)
        try:
            entry = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            if stat.S_ISLNK(entry.st_mode):
                resolved = _link_reader(run_real, parent_fd, parts[:-1], leaf)
                if resolved is None:
                    return fallback
                data = resolved[0]()
            elif stat.S_ISREG(entry.st_mode):
                data = _read_file_at(parent_fd, leaf, entry)
            else:
                return fallback
        finally:
            os.close(parent_fd)
        return json.loads(data.decode("utf-8"))
    except (OSError, _Unsafe, ValueError, RecursionError):
        return fallback
    finally:
        os.close(run_fd)


def read_normalized_sections(run_dir: str | Path) -> dict[str, Any]:
    """The top-level ``normalized/<section>.json`` records of a run, parsed, for a report.

    The same guarded reader as identity discovery: only a bounded regular file (or a link to one inside the run) is
    opened, never a FIFO, device, socket, escaping or dangling link, never without ``O_NONBLOCK`` and never through a
    symlinked directory. A file that cannot be used is left out here; ``context_for_run`` names it and the
    redaction profiles that pseudonymise identities then refuse, so nothing is published without it. Empty
    sections are not returned. Never raises for a missing or unreadable ``normalized/``.
    """
    sections: dict[str, Any] = {}
    run_real = os.path.realpath(run_dir)
    try:
        run_fd = os.open(run_real, _DIR_MODE)
    except OSError:
        return sections
    try:
        try:
            info = os.stat("normalized", dir_fd=run_fd, follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode):
                return sections
            root_fd = _open_dir_at(run_fd, "normalized", info)
        except (OSError, _Unsafe):
            return sections
        try:
            budget = _MAX_SCAN_BYTES
            for name in sorted(os.listdir(root_fd)):
                if not name.lower().endswith(".json"):
                    continue
                try:
                    entry = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
                    if stat.S_ISLNK(entry.st_mode):
                        resolved = _link_reader(run_real, root_fd, ("normalized",), name)
                        if resolved is None:
                            continue
                        reader, size = resolved
                    elif stat.S_ISREG(entry.st_mode):
                        size = entry.st_size
                        reader = lambda d=root_fd, n=name, i=entry: _read_file_at(d, n, i)  # noqa: E731
                    else:
                        continue
                    if size > budget:
                        continue
                    budget -= size
                    payload = json.loads(reader().decode("utf-8"))
                except (OSError, _Unsafe, ValueError, RecursionError):
                    continue
                if payload not in ({}, [], None):
                    sections[name[: -len(".json")]] = payload
        finally:
            os.close(root_fd)
    finally:
        os.close(run_fd)
    return sections


def _scan_run_identities(run_path: Path) -> tuple[frozenset[str], frozenset[str], frozenset[str], list[tuple[str, str]]]:
    """Privileged-user names, immutable ids, role vocabulary and the files discovery could not use.

    Every ``normalized/**/*.json`` is read (bounded), not just the sections a report selects, so an output that
    shows only findings still knows who the administrators are. Discovery never gives up silently: a file that
    cannot be read, or a limit that is hit, is a problem (a safe label and a reason class), the identities found
    elsewhere are kept, and the caller gets the problems (``RedactionContext.incomplete``).

    Every directory is opened below a descriptor of the run directory without following links, every file is
    checked on its descriptor (regular, same identity as listed, size) and nothing is cached: a file replaced,
    swapped, made unreadable or edited between two calls is seen by the next one.
    """
    run_real = os.path.realpath(run_path)
    try:
        run_fd = os.open(run_real, _DIR_MODE)
    except FileNotFoundError:
        return frozenset(), frozenset(), frozenset(), []
    except OSError:
        return frozenset(), frozenset(), frozenset(), [("<run>", REASON_UNREADABLE)]
    scan = _Scan(run_real)
    try:
        try:
            info = os.stat("normalized", dir_fd=run_fd, follow_symlinks=False)
        except FileNotFoundError:
            info = None  # no normalized directory: nothing to discover
        except OSError:
            scan.problem(("normalized",), REASON_UNREADABLE)
            info = None
        if info is not None:
            if stat.S_ISLNK(info.st_mode):
                try:
                    os.stat("normalized", dir_fd=run_fd)
                    scan.problem(("normalized",), REASON_NON_REGULAR)  # a symlinked root is a symlinked ancestor
                except FileNotFoundError:
                    scan.problem(("normalized",), REASON_DANGLING)
                except OSError:
                    scan.problem(("normalized",), REASON_UNREADABLE)
            elif not stat.S_ISDIR(info.st_mode):
                scan.problem(("normalized",), REASON_NON_REGULAR)
            else:
                try:
                    root_fd = _open_dir_at(run_fd, "normalized", info)
                except _Unsafe as exc:
                    scan.problem(("normalized",), exc.reason)
                else:
                    scan.walk(root_fd, ("normalized",))  # closes the descriptor
    finally:
        os.close(run_fd)
    labelled = []
    for index, (parts, reason) in enumerate(sorted(set(scan.problems)), start=1):
        label = _safe_label(parts)
        labelled.append((f"{label}#{index}" if "<redacted-segment-" in label else label, reason))
    found = scan.found
    return frozenset(found.names), frozenset(found.ids), frozenset(found.vocabulary), labelled


def _problem_fields(problems: list[tuple[str, str]], prefix: str = "") -> tuple[tuple[tuple[str, str], ...], int]:
    kept = tuple((f"{prefix}{label}", reason) for label, reason in problems[:_MAX_REASONS])
    return kept, max(0, len(problems) - _MAX_REASONS)


def _reason_strings(files: tuple[tuple[str, str], ...], omitted: int) -> tuple[str, ...]:
    return (*(f"{label}: {reason}" for label, reason in files), *((f"and {omitted} more",) if omitted else ()))


def context_for_run(run_dir: str | Path, **overrides: Any) -> RedactionContext:
    """The context for outputs derived from one run: its salt, its path spellings, its administrators' names and
    immutable ids (from every ``normalized/`` record, whichever sections the output selects) and role vocabulary."""
    run_path = Path(run_dir)
    names, ids, vocabulary, problems = _scan_run_identities(run_path)
    files, omitted = _problem_fields(problems)
    values: dict[str, Any] = {
        "incomplete": bool(problems),
        "incomplete_reasons": _reason_strings(files, omitted),
        "incomplete_files": files,
        "incomplete_omitted": omitted,
        "salt": run_salt(run_path),
        "run_paths": run_path_roots(run_path),
        "protected_names": names,
        "protected_ids": ids,
        "vocabulary": vocabulary,
    }
    values.update(overrides)
    return RedactionContext(**values)


def context_for_runs(run_dirs: Iterable[str | Path], paths: Iterable[str | Path] = ()) -> RedactionContext:
    """One context for an output built from several runs (a diff, a comparison) or from other local paths.

    The first run supplies the salt (a comparison has one); names, ids, vocabulary and path spellings of every
    run are protected, and ``paths`` are further directories whose spellings are scrubbed (a customer pack).
    """
    roots: set[str] = set()
    names: set[str] = set()
    ids: set[str] = set()
    vocabulary: set[str] = set()
    files: list[tuple[str, str]] = []
    omitted = 0
    incomplete = False
    salt = ""
    for index, run_dir in enumerate(run_dirs):
        context = context_for_run(run_dir)
        incomplete = incomplete or context.incomplete
        files.extend((f"run {index + 1}: {label}", reason) for label, reason in context.incomplete_files)
        omitted += context.incomplete_omitted
        salt = salt if index else context.salt
        roots.update(context.run_paths)
        names.update(context.protected_names)
        ids.update(context.protected_ids)
        vocabulary.update(context.vocabulary)
    for path in paths:
        roots.update(run_path_roots(path))
    kept = tuple(files[:_MAX_REASONS])
    omitted += max(0, len(files) - _MAX_REASONS)
    return RedactionContext(
        salt=salt,
        run_paths=tuple(sorted(roots, key=lambda r: (-len(r), r))),
        protected_names=frozenset(names),
        protected_ids=frozenset(ids),
        vocabulary=frozenset(vocabulary),
        incomplete=incomplete,
        incomplete_reasons=_reason_strings(kept, omitted),
        incomplete_files=kept,
        incomplete_omitted=omitted,
    )


# -- redaction --------------------------------------------------------------------------------------------------------

_MS_APP_ID_RE = re.compile(r"^0000000[0-9a-f]-0000-(?:0000-c000|0ff1-ce00)-000000000000$")
_JSON_SHAPES: tuple[tuple[int | None, tuple[str, str]], ...] = (
    (None, (", ", ": ")), (None, (",", ":")), (2, (",", ": ")), (4, (",", ": ")), (1, (",", ": ")),
)


def _is_microsoft_app_id(guid: str) -> bool:
    """Microsoft's first-party resource application ids (``00000003-0000-0000-c000-000000000000`` and kin)."""
    return bool(_MS_APP_ID_RE.match(guid))


def _public_domains() -> frozenset[str]:
    return frozenset(a.split("@", 1)[1] for a in PUBLIC_ADDRESSES)


def _non_empty(value: Any) -> bool:
    if value is None or isinstance(value, bool):
        return False
    if isinstance(value, (str, bytes, list, tuple, set, frozenset, Mapping)):
        return len(value) > 0
    return True


def _dump(value: Any, ensure_ascii: bool, indent: int | None, separators: tuple[str, str], level: int = 0) -> str:
    """``json.dumps`` for parsed embedded JSON, writing ``_Num`` literals back exactly as they were written."""
    item_sep, key_sep = separators
    if isinstance(value, _Num):
        return value.raw
    if isinstance(value, (Mapping, list, tuple)):
        mapping = isinstance(value, Mapping)
        if not value:
            return "{}" if mapping else "[]"
        opener, closer = ("{", "}") if mapping else ("[", "]")
        if indent is None:
            glue, lead, tail = item_sep, "", ""
        else:
            pad = "\n" + " " * (indent * (level + 1))
            glue, lead, tail = item_sep + pad, pad, "\n" + " " * (indent * level)
        if mapping:
            parts = [
                json.dumps(str(key), ensure_ascii=ensure_ascii) + key_sep + _dump(member, ensure_ascii, indent, separators, level + 1)
                for key, member in value.items()
            ]
        else:
            parts = [_dump(member, ensure_ascii, indent, separators, level + 1) for member in value]
        return opener + lead + glue.join(parts) + tail + closer
    return json.dumps(value, ensure_ascii=ensure_ascii, allow_nan=False)


def _dump_like(original: str, parsed: Any, redacted: Any) -> str:
    """``redacted`` serialised the way ``original`` was, when one of the usual layouts reproduces it exactly."""
    for ensure_ascii in (True, False):
        for indent, separators in _JSON_SHAPES:
            try:
                if _dump(parsed, ensure_ascii, indent, separators) == original:
                    return _dump(redacted, ensure_ascii, indent, separators)
            except (ValueError, TypeError):
                continue
    return _dump(redacted, original.isascii(), None, (", ", ": "))


class _Redactor:
    def __init__(self, profile: RedactionProfile, context: RedactionContext, value: Any, markup: bool) -> None:
        self.profile = profile
        self.markup = markup
        self.salt = context.salt
        self.policy = context.policy or policy_for(profile)
        self.roots = context.run_paths if profile.run_paths else ()
        self.depth = 0
        self.blank = 0  # > 0 while walking the value of a free-text key whose strings are replaced
        if profile.identities and context.incomplete:
            # Fail closed: the names and ids of this run were not all discovered, so free text may carry ones this
            # redactor was never told about. The shareable profiles refuse rather than return a partial result.
            raise ContextIncompleteError(
                context.incomplete_files or (("<context>", "incomplete"),), context.incomplete_omitted
            )
        found = _Found()
        names = set(context.protected_names) if profile.identities else set()
        ids = set(context.protected_ids) if profile.identities else set()
        domains = {d.lower() for d in context.domains}
        want_domains = profile.emails and self.policy.redact_domains
        if profile.identities or want_domains:
            _collect(value, found, names=profile.identities, domains=want_domains)
        if profile.identities and found.limit_hits:
            raise ContextIncompleteError((("<output value>", REASON_LIMIT),))
        names |= found.names
        ids |= found.ids
        domains |= found.domains
        # A name that is also report vocabulary (a role, a status word, a key of the structure) stays readable in
        # free text; the user's own structured ``display_name`` is still pseudonymised.
        vocabulary = {v.lower() for v in context.vocabulary} | found.vocabulary | _STATIC_VOCABULARY | found.keys
        vocabulary_norms = {_norm(v) for v in vocabulary}
        self.names = sorted(
            (
                n for n in names
                if len(n) >= 4 and not _PSEUDONYM_RE.match(n) and n.lower() not in vocabulary and _norm(n) not in vocabulary_norms and not _structural(n)
            ),
            key=len, reverse=True,
        )
        # The alternation puts a generated pseudonym first, so ``User 0123...`` is never re-read as the name ``User``.
        self.name_re = (
            re.compile(_PSEUDONYM_KEEP + r"|(?<!\w)(?P<hit>" + "|".join(re.escape(n) for n in self.names) + r")(?!\w)")
            if self.names else None
        )
        # Immutable ids are protected by value, whatever their shape and case (``planted_immutable_id`` is as much an id
        # as a base64 one); the pseudonym is that of the id as discovered, so every spelling gets the same one.
        self.id_canonical = {i.lower(): i for i in sorted(ids, reverse=True) if len(i) >= 6 and not _PSEUDONYM_RE.match(i)}
        self.ids = sorted(self.id_canonical.values(), key=len, reverse=True)
        self.id_re = (
            re.compile(
                _PSEUDONYM_KEEP + r"|(?<![\w+/=-])(?P<hit>" + "|".join(re.escape(i) for i in self.ids) + r")(?![\w+/=-])",
                re.IGNORECASE,
            )
            if self.ids else None
        )
        self.domains = sorted(
            (d for d in domains if d and d not in _public_domains() and not _DOMAIN_PSEUDONYM_RE.match(d)),
            key=len, reverse=True,
        ) if want_domains else []
        # The domain itself (with the boundary rules); its subdomain labels are taken leftwards by ``_mask_domains``,
        # so the search is one linear pass whatever dotted text surrounds it.
        self.domain_re = (
            re.compile(
                r"(?:(?<![\w-])|(?<=%40)|(?<=\\u0040))(?P<d>" + "|".join(re.escape(d) for d in self.domains) + r")(?![\w-])",
                re.IGNORECASE,
            )
            if self.domains else None
        )

    # -- text ---------------------------------------------------------------------------------------------
    def text(self, value: str, *, names: bool = True, key: bool = False) -> str:
        """``value`` as text. ``key`` is a mapping key: identifiers and credential assignments only, no name or id
        substitution, no embedded JSON. ``names=False`` is a controlled-vocabulary value (finding id, setting name,
        reason code, status): no user name is substituted into it; identifiers in it are still masked."""
        if not value:
            return value
        profile = self.profile
        if self.blank and not key:
            return TEXT_PLACEHOLDER  # a string below a free-text key (the policy of this profile)
        if not key:
            embedded = self._embedded_json(value)
            if embedded is not None:
                return embedded
        if self.roots:
            value = scrub_run_paths(value, self.roots)
        if profile.secrets:
            value = self._secrets(value, minimal=self.markup)
        if profile.emails:
            value = OUTPUT_EMAIL_RE.sub(self._mask_email, value)
            value = _ENCODED_EMAIL_RE.sub(self._mask_encoded_email, value)
        if profile.guids and self.policy.redact_guids:
            value = _GUID_RE.sub(self._mask_guid, value)
        if not key:
            if names and self.name_re is not None:
                value = self.name_re.sub(self._name, value)
            if self.id_re is not None:
                value = self.id_re.sub(self._identifier, value)
        if self.domain_re is not None:
            value = self._mask_domains(value)
        return value

    def _mask_domains(self, value: str) -> str:
        """Each known domain, with the subdomain labels written before it, becomes ``domain-<12 hex>.invalid``.
        One left-to-right search for the domain; the labels are then taken leftwards, never past the previous match."""
        assert self.domain_re is not None
        out: list[str] = []
        done = 0
        for match in self.domain_re.finditer(value):
            start = match.start()
            while start > done and value[start - 1] == ".":
                label = start - 1
                while label > done and (value[label - 1].isalnum() or value[label - 1] in "_-"):
                    label -= 1
                if label == start - 1:
                    break
                start = label
            out.append(value[done:start])
            out.append(f"domain-{pseudonym(self.salt, match['d'].lower())[:12]}.invalid")
            done = match.end()
        out.append(value[done:])
        return "".join(out)

    @staticmethod
    def _secrets(value: str, *, minimal: bool) -> str:
        # ``minimal``: rendered JSON, HTML, CSV and Markdown. ``key=value`` secrets were redacted in the structure
        # before rendering; the inline pattern cannot tell where a value ends in markup. Mapping keys use the full
        # pattern (a key such as ``password=value`` carries its credential in the key text).
        value = JWT_RE.sub("***redacted-jwt***", BEARER_RE.sub("Bearer ***redacted***", value))
        value = _redact_url_credentials(value)
        if minimal:
            return value

        return _redact_inline_secrets(value)

    def _embedded_json(self, value: str) -> str | None:
        """A string that is a JSON object or array is parsed, redacted as structure and written back the way it was
        laid out, so escapes and quotes stay valid; anything else is ``None`` (redact it as text)."""
        try:
            parsed = _maybe_json(value)
        except _EmbeddedLimitError:
            if self.profile.identities:
                raise ContextIncompleteError((("<output value>", REASON_LIMIT),)) from None
            return None
        if parsed is None:
            return None
        stripped = value.strip()
        lead, trail = value[: len(value) - len(value.lstrip())], value[len(value.rstrip()):]
        redacted = self.walk(parsed)
        return lead + _dump_like(stripped, parsed, redacted) + trail

    @staticmethod
    def _mask_email(match: re.Match[str]) -> str:
        local, domain = match["local"], match["domain"]
        if f"{local}@{domain}".lower() in PUBLIC_ADDRESSES or domain.replace(".", "").isdigit():
            return match[0]
        return f"{match['field'] or ''}{match['quote']}***@{domain}"

    @staticmethod
    def _mask_encoded_email(match: re.Match[str]) -> str:
        from urllib.parse import unquote

        local, domain = match["local"], match["domain"]
        if f"{unquote(local)}@{domain}".lower() in PUBLIC_ADDRESSES or domain.replace(".", "").isdigit():
            return match[0]
        return f"***{match['sep']}{domain}"

    def _mask_guid(self, match: re.Match[str]) -> str:
        if match["label"]:
            return match[0]
        guid = match[0].lower()
        if guid in PUBLIC_GUIDS or guid.startswith(_GUID_PSEUDONYM_PREFIX) or _is_microsoft_app_id(guid):
            return match[0]
        return _GUID_PSEUDONYM_PREFIX + pseudonym(self.salt, guid)[:12]

    def _name(self, match: re.Match[str]) -> str:
        return match["keep"] or _USER_PREFIX + pseudonym(self.salt, match["hit"])

    def _identifier(self, match: re.Match[str]) -> str:
        return match["keep"] or _IMMUTABLE_PREFIX + pseudonym(self.salt, self.id_canonical.get(match["hit"].lower(), match["hit"]))

    # -- structure ----------------------------------------------------------------------------------------
    def walk(self, value: Any, controlled: bool = False) -> Any:
        if isinstance(value, str):
            return self.text(value, names=not controlled)
        if not isinstance(value, (Mapping, list, tuple, set, frozenset)):
            return value
        self.depth += 1
        try:
            if self.depth > MAX_DEPTH:
                raise RedactionDepthError(f"value is nested more than {MAX_DEPTH} levels")
            if isinstance(value, Mapping):
                return self.mapping(value)
            if isinstance(value, list):
                return [self.walk(item, controlled) for item in value]
            if isinstance(value, tuple):
                return tuple(self.walk(item, controlled) for item in value)
            return type(value)(self.walk(item, controlled) for item in value)
        finally:
            self.depth -= 1

    def mapping(self, record: Mapping[Any, Any]) -> dict[Any, Any]:
        profile = self.profile
        user = profile.identities and _is_privileged_user(record)
        group = profile.identities and self.policy.redact_group_names and _is_group(record)
        free_text = self.policy.redact_free_text_keys
        rows: list[tuple[Any, Any, Any]] = []
        for key, item in record.items():
            norm = _norm(key)
            if profile.secrets and norm in _SECRET_NORMS and _non_empty(item):
                item = SECRET_PLACEHOLDER
            elif isinstance(item, str):
                if not item:
                    pass
                elif self.blank:
                    item = TEXT_PLACEHOLDER
                elif profile.identities and norm in _IDENTITY_KEYS:
                    item = item if _PSEUDONYM_RE.match(item) else _IMMUTABLE_PREFIX + pseudonym(self.salt, item)
                elif user and norm == "displayname":
                    item = item if _PSEUDONYM_RE.match(item) else _USER_PREFIX + pseudonym(self.salt, item)
                elif group and norm == "displayname":
                    item = item if _PSEUDONYM_RE.match(item) else GROUP_PREFIX + pseudonym(self.salt, item)
                elif free_text and str(key).lower() in TENANT_TEXT_KEYS:
                    item = TEXT_PLACEHOLDER
                else:
                    item = self.text(item, names=norm not in _CONTROLLED_KEYS)
            elif free_text and str(key).lower() in TENANT_TEXT_KEYS:
                # Every string below a free-text key is replaced, but the value still goes through the ordinary walk:
                # its mapping keys are masked and a credential key still replaces its whole value.
                self.blank += 1
                try:
                    item = self.walk(item, norm in _CONTROLLED_KEYS)
                finally:
                    self.blank -= 1
            else:
                item = self.walk(item, norm in _CONTROLLED_KEYS)
            new_key = self.text(key, key=True) if isinstance(key, str) and key else key
            rows.append((key, new_key, item))
        # Output keys are reserved whether they changed or not, so a rewritten key can never displace one that was
        # already there; a collision takes ``#n`` from a counter kept per rewritten name (linear overall).
        used = {new for old, new, _ in rows if new == old}
        counters: dict[Any, int] = {}
        out: dict[Any, Any] = {}
        for old, new, item in rows:
            if new != old:
                if new in used:
                    suffix = counters.get(new, 2)
                    while f"{new}#{suffix}" in used:
                        suffix += 1
                    counters[new] = suffix + 1
                    new = f"{new}#{suffix}"
                used.add(new)
            out[new] = item
        return out


def redact_output(
    value: Any,
    *,
    profile: str | RedactionProfile = PROFILE_SHAREABLE,
    context: RedactionContext | None = None,
    markup: bool = False,
) -> Any:
    """``value`` with the identifiers ``profile`` protects removed; same shape, deterministic, idempotent.

    ``markup=True`` is for text that is already rendered (HTML, CSV, Markdown, serialised JSON): it skips the
    inline ``key=value`` secret pattern, which cannot tell where a value ends in markup. Redact the structure
    before rendering; use ``markup=True`` only for the final pass over the rendered text.

    ``profile`` is a name from ``PROFILES`` or a ``RedactionProfile``. An unknown name raises ``KeyError``
    (a typo must not silently publish). A value nested deeper than ``MAX_DEPTH`` raises ``RedactionDepthError``.
    ``context`` carries the run salt, run paths and known names; omit it for text with no run (pseudonyms are
    then unsalted).
    """
    chosen = profile if isinstance(profile, RedactionProfile) else PROFILES[profile]
    try:
        return _Redactor(chosen, context or RedactionContext(), value, markup).walk(value)
    except RecursionError as exc:
        raise RedactionDepthError("value is nested too deeply to redact") from exc


def redact_for_run(
    value: Any, run_dir: str | Path, *, profile: str | RedactionProfile = PROFILE_SHAREABLE, markup: bool = False
) -> Any:
    """``redact_output`` with the context of ``run_dir`` (its salt, path spellings, names and immutable ids)."""
    return redact_output(value, profile=profile, context=context_for_run(run_dir), markup=markup)


def _settle(value: Any, depth: int) -> Any:
    if depth > MAX_DEPTH + 1:
        return value
    if isinstance(value, list):
        return [_settle(member, depth + 1) for member in value]
    if not isinstance(value, Mapping):
        return value
    result = {key: _settle(member, depth + 1) for key, member in value.items()}
    rows = result.get("citations")
    if isinstance(rows, list) and all(isinstance(row, Mapping) for row in rows):
        settled = dedupe_citations(rows)
        result["citations"] = settled
        if "citation_summary" in result:
            result["citation_summary"] = build_citation_summary(settled)
        if "citation_count" in result:
            result["citation_count"] = len(settled)
    # A summary copied beside the pack it describes (``report_pack_citation_summary``) follows the pack's own.
    pack = result.get("report_pack")
    if (
        "report_pack_citation_summary" in result
        and isinstance(pack, Mapping)
        and isinstance(pack.get("citation_summary"), Mapping)
    ):
        result["report_pack_citation_summary"] = dict(pack["citation_summary"])
    return result


def settle_citations(payload: Any) -> Any:
    """A redacted payload with every citation list de-duplicated and every summary re-derived.

    Masking can make two citations identical, and a summary computed before masking would then disagree with the
    list it sits beside (``verify-pack`` checks that). This applies to the payload and to every nested container
    that holds a ``citations`` list (a ``report_pack``, a notification section), to the ``citation_summary`` and
    ``citation_count`` beside such a list, and to a ``report_pack_citation_summary`` copied from the nested pack's
    summary. Values without citations are returned unchanged.
    """
    if not isinstance(payload, (Mapping, list)):
        return payload
    return _settle(payload, 0)


def redact_payload(
    value: Any,
    *,
    run_dirs: Iterable[str | Path] = (),
    paths: Iterable[str | Path] = (),
    profile: str | RedactionProfile = PROFILE_SHAREABLE,
    markup: bool = False,
    transform: Callable[[Any], Any] | None = None,
) -> Any:
    """The complete payload a tool or command returns, redacted with the context of the runs it was built from
    and with its citation summary re-derived. For return values that can leave the machine (MCP tools, notifications)."""
    context = context_for_runs(run_dirs, paths)
    redacted = redact_output(value, profile=profile, context=context, markup=markup)
    return settle_citations(transform(redacted) if transform else redacted)
