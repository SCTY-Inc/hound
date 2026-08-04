"""Slice 3D: authorized single-entry, single-record, and maintenance reads."""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .access import PrincipalScope, authorize_event_header
from .journal import Journal
from .snapshot import build_journal_query_snapshot
from .store import RecordStore


class ReadContractError(ValueError):
    """A Slice 3D read payload does not satisfy its exact contract."""


LEGACY_OBJECT_SCHEMA = "raw"
_LEGACY_OBJECT_PREFIX = "legacy:"
_ENTRY_FIELDS = frozenset({"entry_id"})
_RECORD_REQUIRED = frozenset({"record_id"})
_RECORD_FIELDS = frozenset({"record_id", "include_content"})
# Only these outcomes commit a dereferenceable staged object.  Every other
# outcome carries a dedupe commitment to bytes that were never stored, so its
# ``content_sha256`` must never be dereferenced.
_STAGED_OUTCOMES = frozenset({"completed", "partial"})


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or not value or len(value) > 255:
        raise ReadContractError(f"{label} must be a bounded nonempty string")
    try:
        value.encode("utf-8")
    except UnicodeError as error:
        raise ReadContractError(f"{label} is not valid Unicode") from error
    return value


@dataclass(frozen=True, slots=True)
class EntryRequest:
    entry_id: str


@dataclass(frozen=True, slots=True)
class RecordRequest:
    record_id: str
    include_content: bool


@dataclass(frozen=True, slots=True)
class RecordBinding:
    """The one authorized event that makes exactly one stored object readable."""

    record_id: str
    schema: str
    staged_sha256: str | None


def parse_maintenance_request(payload: Any) -> None:
    """A verify or rebuild-index payload is exactly the empty object."""

    if type(payload) is not dict or payload:
        raise ReadContractError("maintenance read payload has missing or unknown fields")


def parse_entry_request(payload: Any) -> EntryRequest:
    if type(payload) is not dict or set(payload) != _ENTRY_FIELDS:
        raise ReadContractError("entry read payload has missing or unknown fields")
    return EntryRequest(_identifier(payload["entry_id"], "entry_id"))


def parse_record_request(payload: Any) -> RecordRequest:
    if type(payload) is not dict or not _RECORD_REQUIRED <= set(payload) <= _RECORD_FIELDS:
        raise ReadContractError("record read payload has missing or unknown fields")
    include_content = payload.get("include_content", False)
    if type(include_content) is not bool:
        raise ReadContractError("include_content must be a boolean")
    return RecordRequest(_identifier(payload["record_id"], "record_id"), include_content)


def verified_events(journal: Journal) -> tuple[Mapping[str, Any], ...]:
    """Read one freshly verified journal snapshot; never repair, never retain."""

    return build_journal_query_snapshot(Journal.verified_snapshot(journal)).events


def select_entry(
    events: tuple[Mapping[str, Any], ...],
    scope: PrincipalScope,
    entry_id: str,
) -> Mapping[str, Any] | None:
    """Select one canonical event only from the scope's authorized events."""

    for event in events:
        if authorize_event_header(scope, event) and event["entry_id"] == entry_id:
            return event
    return None


def _staged_blob(event: Mapping[str, Any]) -> str | None:
    """Name the blob this event actually staged, or nothing.

    A dedupe commitment is not evidence that an object exists.  An interrupted
    ``ingest.file`` commits its source digest without ever staging those bytes,
    so the outcome alone decides whether the digest is dereferenceable.  A
    completed import is excluded here too: its bytes are the separately
    readable legacy object, not a staged blob.
    """

    if event["classification"]["outcome"] not in _STAGED_OUTCOMES:
        return None
    if event["dedupe"]["object_key"].startswith(_LEGACY_OBJECT_PREFIX):
        return None
    return event["dedupe"]["content_sha256"]


def select_record(
    events: tuple[Mapping[str, Any], ...],
    scope: PrincipalScope,
    record_id: str,
) -> RecordBinding | None:
    """Bind a stored object to the first authorized event that publishes it.

    An artifact record is named directly by its event.  A completed import
    additionally publishes the preserved raw legacy object, which exists only
    under that event's exact ``legacy:<record id>`` dedupe object key; that
    import stages no blob, because those bytes are the legacy object itself.
    """

    legacy_object_key = _LEGACY_OBJECT_PREFIX + record_id
    for event in events:
        if not authorize_event_header(scope, event):
            continue
        object_key = event["dedupe"]["object_key"]
        if event["artifact"]["record_id"] == record_id:
            return RecordBinding(record_id, event["artifact"]["schema"], _staged_blob(event))
        if object_key == legacy_object_key:
            return RecordBinding(record_id, LEGACY_OBJECT_SCHEMA, None)
    return None


def read_record(records: RecordStore, binding: RecordBinding, *, include_content: bool) -> dict[str, Any]:
    """Return the exact stored bytes plus the distinct staged blob when asked.

    Bytes are never rewritten, re-encoded, or truncated.  Content appears only
    when the event stages a blob that is not the record object itself, so no
    object ever repeats its own bytes under a second name.
    """

    body = records.read(binding.record_id)
    result = {
        "schema": binding.schema,
        "record_id": binding.record_id,
        "body_base64": base64.b64encode(body).decode("ascii"),
        "byte_length": len(body),
    }
    staged = binding.staged_sha256
    if include_content and staged is not None and staged != hashlib.sha256(body).hexdigest():
        content = records.blobs.get(staged)
        result["content_base64"] = base64.b64encode(content).decode("ascii")
        result["content_sha256"] = staged
        result["content_byte_length"] = len(content)
    return result


__all__ = [
    "EntryRequest",
    "LEGACY_OBJECT_SCHEMA",
    "ReadContractError",
    "RecordBinding",
    "RecordRequest",
    "parse_entry_request",
    "parse_maintenance_request",
    "parse_record_request",
    "read_record",
    "select_entry",
    "select_record",
    "verified_events",
]
