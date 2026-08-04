"""Strict, shared validation for durable Slice 3C2 adapter outcomes."""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping

from hound_research.evidence import EvidenceError, validate_public_url

from .contracts import canonical_bytes, canonical_hash, validate_journal_envelope


class AdapterOutcomeError(ValueError):
    """An adapter record or its journal binding is not exact durable truth."""


SEARCH_RECORD_SCHEMA = "houndd.search-record.v1"
URL_RECORD_SCHEMA = "houndd.url-record.v1"
TRANSCRIPT_RECORD_SCHEMA = "houndd.transcript-record.v1"
QUARANTINE_SCHEMA = "houndd.quarantine-record.v1"
MAX_CONTENT_BYTES = 16 * 1024 * 1024
MAX_TRANSCRIPT_SEGMENTS = 2_048
MAX_LANGUAGE_CHARS = 64
MAX_MODEL_CHARS = 128
MAX_QUERY_CHARS = 1_024
# Providers use URLs as native lead IDs (Exa's providerId is the result URL),
# so this bound must hold URL-scale identifiers, not short opaque tokens.
MAX_LEAD_ID_CHARS = 2_048
MAX_LEAD_TITLE_CHARS = 4_000
_SHA256 = frozenset("0123456789abcdef")
_NO_LINEAGE = {"relation": "none", "record_id": "none", "lead_id": "none"}
_BINDINGS = {
    "ingest.search": ("search", SEARCH_RECORD_SCHEMA, "exa"),
    "ingest.url": ("extract", URL_RECORD_SCHEMA, "firecrawl"),
    "transcribe": ("transcription", TRANSCRIPT_RECORD_SCHEMA, "openai"),
}
_EVIDENCE = {
    "completed": "clear",
    "partial": "partial",
    "failed": "failure",
    "degraded": "degraded",
    "refused": "refused",
    "interrupted": "interrupted",
}
_REASONS = {
    "completed": "none",
    "partial": "none",
    "failed": "provider_failed",
    "degraded": "adapter_absent",
    "refused": "provider_abstained",
    "interrupted": "interrupted",
}
_STAGED = frozenset({"completed", "partial"})
_JOURNAL_FIELDS = {
    "schema_version",
    "entry_id",
    "sequence",
    "appended_at",
    "producer",
    "artifact",
    "classification",
    "access",
    "policy_id",
    "dedupe",
    "lineage",
    "source",
    "usage",
}


@dataclass(frozen=True, slots=True)
class AdapterOutcome:
    operation: str
    kind: str
    schema: str
    provider: str
    outcome: str
    evidence_status: str
    staged: bool
    canonical_url: str
    dedupe: dict[str, str]


def _fail(message: str) -> None:
    raise AdapterOutcomeError(message)


def _object(value: object, fields: set[str], label: str, *, optional: set[str] = set()) -> dict[str, Any]:
    keys = set(value) if type(value) is dict else None
    if keys is None or not fields <= keys or keys - fields - optional:
        _fail(f"{label} has an invalid shape")
    return value


def _text(value: object, label: str, *, maximum: int = 4_000, controls: bool = True) -> str:
    if type(value) is not str or not value or len(value) > maximum:
        _fail(f"{label} is invalid")
    if controls and any(ord(character) < 32 or ord(character) == 127 for character in value):
        _fail(f"{label} is invalid")
    return value


def _fixed_text(value: object, expected: str, label: str) -> str:
    value = _text(value, label, maximum=len(expected))
    if value != expected:
        _fail(f"{label} is invalid")
    return value


def _sha(value: object, label: str) -> str:
    value = _text(value, label, maximum=64)
    if len(value) != 64 or any(character not in _SHA256 for character in value):
        _fail(f"{label} is not a SHA-256 digest")
    return value


def _timestamp(value: object, label: str) -> str:
    value = _text(value, label, maximum=128)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise AdapterOutcomeError(f"{label} is not an ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _fail(f"{label} has no timezone")
    return value


def _uint(value: object, label: str, *, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        _fail(f"{label} is out of bounds")
    return value


def _url(value: object, label: str) -> str:
    try:
        return validate_public_url(_text(value, label), label)
    except EvidenceError as error:
        raise AdapterOutcomeError(f"{label} is not a public HTTP URL") from error


def _lineage(value: object, operation: str) -> dict[str, str]:
    lineage = _object(value, {"relation", "record_id", "lead_id"}, "adapter lineage")
    relation = _text(lineage["relation"], "adapter lineage relation")
    record_id = _text(lineage["record_id"], "adapter lineage record_id")
    lead_id = _text(lineage["lead_id"], "adapter lineage lead_id")
    if operation == "ingest.search":
        if lineage != _NO_LINEAGE:
            _fail("search lineage is invalid")
        return {"relation": relation, "record_id": record_id, "lead_id": lead_id}
    if lineage == _NO_LINEAGE:
        return {"relation": relation, "record_id": record_id, "lead_id": lead_id}
    if operation == "transcribe":
        # A transcription's only lineage is the capture it was authorized
        # against; the no-lineage form above belongs to its quarantine record.
        if relation != "media" or lead_id != "none":
            _fail("transcript lineage relation is invalid")
        _sha(record_id, "transcript lineage record_id")
        return lineage
    if relation != "search":
        _fail("URL lineage relation is invalid")
    _sha(record_id, "URL lineage record_id")
    _text(lead_id, "URL lineage lead_id", maximum=MAX_LEAD_ID_CHARS)
    return lineage


def _leads(value: object, limit: int) -> list[dict[str, str]]:
    if type(value) is not list or len(value) > limit:
        _fail("search leads are invalid")
    leads: list[dict[str, str]] = []
    for lead in value:
        lead = _object(lead, {"url", "title", "native_id"}, "search lead")
        leads.append(
            {
                "url": _url(lead["url"], "search lead URL"),
                "title": _text(lead["title"], "search lead title", maximum=MAX_LEAD_TITLE_CHARS),
                "native_id": _text(lead["native_id"], "search lead native_id", maximum=MAX_LEAD_ID_CHARS),
            }
        )
    return leads


def _usage(value: object, outcome: AdapterOutcome, *, content_length: int) -> dict[str, int | float]:
    usage = _object(value, {"requests", "bytes", "cost"}, "adapter usage")
    requests = usage["requests"]
    byte_count = usage["bytes"]
    cost = usage["cost"]
    if type(requests) is not int or requests not in {0, 1}:
        _fail("adapter usage request count is invalid")
    if outcome.outcome in {"completed", "partial", "failed"} and requests != 1:
        _fail("adapter outcome does not bind one exchange")
    if outcome.outcome in {"degraded", "interrupted"} and requests != 0:
        _fail("non-invoked adapter outcome claims an exchange")
    if type(byte_count) is not int or byte_count != (content_length if outcome.staged else 0):
        _fail("adapter usage bytes do not bind content")
    if type(cost) not in {int, float} or type(cost) is bool or not math.isfinite(cost) or cost < 0:
        _fail("adapter usage cost is invalid")
    return usage


def _journal(
    value: object,
    outcome: AdapterOutcome,
    *,
    record_id: str,
    content_length: int,
) -> dict[str, Any]:
    """Check the complete event with exact built-in objects before binding it."""

    event = _object(value, _JOURNAL_FIELDS, "adapter journal event")
    if event["schema_version"] != "houndd.journal.v1":
        _fail("adapter journal schema is invalid")
    _sha(event["entry_id"], "adapter journal entry_id")
    _uint(event["sequence"], "adapter journal sequence", maximum=2**63 - 1)
    _timestamp(event["appended_at"], "adapter journal appended_at")

    producer = _object(event["producer"], {"owner_id", "capability", "run_id"}, "adapter journal producer")
    for field in ("owner_id", "capability", "run_id"):
        _text(producer[field], f"adapter journal producer {field}")

    artifact = _object(
        event["artifact"],
        {"kind", "schema", "record_id", "hash", "authorized_uri"},
        "adapter journal artifact",
    )
    for field in ("kind", "schema", "record_id", "authorized_uri"):
        _text(artifact[field], f"adapter journal artifact {field}")
    _sha(artifact["hash"], "adapter journal artifact hash")

    classification = _object(
        event["classification"],
        {"outcome", "evidence_status"},
        "adapter journal classification",
    )
    _text(classification["outcome"], "adapter journal outcome")
    _text(classification["evidence_status"], "adapter journal evidence status")
    if type(event["access"]) is not str or event["access"] not in {"public", "workspace", "restricted"}:
        _fail("adapter journal access is invalid")
    _text(event["policy_id"], "adapter journal policy_id")

    dedupe = _object(event["dedupe"], {"object_key", "content_sha256"}, "adapter journal dedupe")
    _text(dedupe["object_key"], "adapter journal object_key")
    _sha(dedupe["content_sha256"], "adapter journal content_sha256")
    _lineage(event["lineage"], outcome.operation)

    source = _object(event["source"], {"provider", "native_id", "canonical_url"}, "adapter journal source")
    for field in ("provider", "native_id", "canonical_url"):
        _text(source[field], f"adapter journal source {field}")
    _usage(event["usage"], outcome, content_length=content_length)

    if artifact != {
        "kind": outcome.kind,
        "schema": outcome.schema,
        "record_id": record_id,
        "hash": record_id,
        "authorized_uri": f"houndd://record/{record_id}",
    }:
        _fail("adapter journal artifact does not bind its record")
    return event


def validate_search_options(value: object) -> dict[str, Any]:
    """Check one search options object against the provider's own vocabulary.

    The daemon does not own the option grammar; the exa adapter does.  Routing
    every caller-supplied and record-bound options object through the adapter's
    normalizer keeps one vocabulary at the wire, at the record, and at the
    provider request itself.  The import is deferred so this module stays free
    of adapter transport machinery.
    """

    from hound_research.web import MAX_SEARCH_OPTIONS_BYTES
    from hound_web_adapters._http import AdapterError
    from hound_web_adapters.exa import normalize_search_options

    if type(value) is not dict:
        _fail("search options are invalid")
    try:
        normalize_search_options(value)
    except AdapterError as error:
        raise AdapterOutcomeError(f"search options are invalid: {error}") from error
    if len(canonical_bytes(value)) > MAX_SEARCH_OPTIONS_BYTES:
        _fail("search options are too large")
    return value


_TRANSCRIBED = frozenset({"completed", "partial"})
_TRANSCRIPT_FIELDS = {
    "schema_version",
    "attempt_id",
    "request_hash",
    "operation",
    "outcome",
    "evidence_status",
    "reason",
    "provider",
    "retrieved_at",
    "model",
    "model_version",
    "language",
    "capture",
    "text_sha256",
    "text_byte_length",
    "segments",
    "lineage",
}
_EMPTY_CONTENT = {"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "byte_length": 0}


def _segments(value: object, transcribed: bool) -> list[dict[str, Any]]:
    """Check ordered, non-overlapping segment provenance and nothing else.

    A segment retains its position, its timings, and the hash of its text.  The
    text itself is never part of a transcription record.
    """

    if type(value) is not list or len(value) > MAX_TRANSCRIPT_SEGMENTS:
        _fail("transcript segments are invalid")
    if bool(value) != transcribed:
        _fail("transcript segments do not bind the outcome")
    segments: list[dict[str, Any]] = []
    previous_end = 0
    for index, segment in enumerate(value):
        segment = _object(segment, {"index", "start_ms", "end_ms", "text_sha256"}, "transcript segment")
        start = segment["start_ms"]
        end = segment["end_ms"]
        if (
            segment["index"] != index
            or type(start) is not int
            or type(end) is not int
            or type(segment["index"]) is not int
            or start < previous_end
            or end < start
        ):
            _fail("transcript segment timings are invalid")
        _sha(segment["text_sha256"], "transcript segment text_sha256")
        previous_end = end
        segments.append(dict(segment))
    return segments


def _transcript_outcome(
    record: dict[str, Any],
    *,
    record_id: str | None,
    outcome: str,
    evidence: str,
    lineage: dict[str, str],
    expected_payload: Mapping[str, Any] | None,
    content_identity: Mapping[str, Any] | None,
) -> AdapterOutcome:
    """Validate one ``houndd.transcript-record.v1`` body as durable truth.

    The record is hashes and policy-safe provenance only: no transcript text,
    no provider response, and no staged content object anywhere.  A
    non-transcribed outcome carries no model, language, or text identity at
    all, so a failed or degraded attempt can never read as thin evidence.
    """

    _object(record, _TRANSCRIPT_FIELDS, "transcript outcome")
    if (
        _fixed_text(record["schema_version"], TRANSCRIPT_RECORD_SCHEMA, "transcript schema") != TRANSCRIPT_RECORD_SCHEMA
        or _fixed_text(record["provider"], "openai", "transcript provider") != "openai"
        or _fixed_text(record["reason"], _REASONS[outcome], "transcript reason") != _REASONS[outcome]
    ):
        _fail("transcript provider, schema, or reason is invalid")
    _timestamp(record["retrieved_at"], "transcript retrieved_at")
    transcribed = outcome in _TRANSCRIBED

    capture = _object(record["capture"], {"record_id", "source_sha256", "byte_length", "media_type"}, "transcript capture")
    capture_id = _sha(capture["record_id"], "transcript capture record_id")
    _sha(capture["source_sha256"], "transcript capture source_sha256")
    _uint(capture["byte_length"], "transcript capture byte_length", maximum=MAX_CONTENT_BYTES)
    if _fixed_text(capture["media_type"], "application/octet-stream", "transcript capture media_type") != "application/octet-stream":
        _fail("transcript capture media type is unsupported")
    if lineage != {"relation": "media", "record_id": capture_id, "lead_id": "none"}:
        _fail("transcript lineage does not name its capture")
    if expected_payload is not None and capture_id != expected_payload.get("capture_id"):
        _fail("transcript record does not bind its request")

    model = _text(record["model"], "transcript model", maximum=MAX_MODEL_CHARS)
    model_version = _text(record["model_version"], "transcript model_version", maximum=MAX_MODEL_CHARS)
    language = _text(record["language"], "transcript language", maximum=MAX_LANGUAGE_CHARS)
    if not transcribed and (model, model_version, language) != ("none", "none", "none"):
        _fail("non-transcribed outcome claims model provenance")
    if transcribed and "none" in {model, model_version}:
        _fail("transcribed outcome has no model provenance")

    text_length = record["text_byte_length"]
    if transcribed:
        _sha(record["text_sha256"], "transcript text_sha256")
        if _uint(text_length, "transcript text_byte_length", maximum=MAX_CONTENT_BYTES) == 0:
            _fail("transcribed outcome has no text")
    elif record["text_sha256"] != "none" or type(text_length) is not int or text_length != 0:
        _fail("non-transcribed outcome claims text")
    _segments(record["segments"], transcribed)
    # Nothing is staged for any transcript outcome: the record is the object.
    if content_identity is not None and dict(content_identity) != _EMPTY_CONTENT:
        _fail("transcript plan claims a staged object")
    if record_id is not None and canonical_hash(record) != record_id:
        _fail("transcript record hash is invalid")
    return AdapterOutcome(
        "transcribe",
        "transcription",
        TRANSCRIPT_RECORD_SCHEMA,
        "openai",
        outcome,
        evidence,
        False,
        "none",
        {"object_key": f"transcript:{record_id}", "content_sha256": record_id or ""},
    )


def validate_adapter_record(
    record: object,
    *,
    record_id: str | None = None,
    expected_operation: str | None = None,
    expected_attempt_id: str | None = None,
    expected_request_hash: str | None = None,
    expected_payload: Mapping[str, Any] | None = None,
    expected_lineage: Mapping[str, str] | None = None,
    expected_access: str | None = None,
    content_identity: Mapping[str, Any] | None = None,
) -> AdapterOutcome:
    """Validate one adapter outcome record before it reaches durable truth."""

    if type(record) is not dict:
        _fail("adapter outcome record is invalid")
    operation = record.get("operation")
    if type(operation) is not str or operation not in _BINDINGS:
        _fail("adapter operation is invalid")
    if expected_operation is not None and operation != expected_operation:
        _fail("adapter operation does not match its binding")
    kind, operation_schema, provider = _BINDINGS[operation]
    outcome = record.get("outcome")
    if type(outcome) is not str or outcome not in _EVIDENCE:
        _fail("adapter outcome is invalid")
    evidence = _EVIDENCE[outcome]
    if _fixed_text(record.get("evidence_status"), evidence, "adapter evidence status") != evidence:
        _fail("adapter evidence status is invalid")
    attempt_id = _sha(record.get("attempt_id"), "adapter attempt_id")
    request_hash = _sha(record.get("request_hash"), "adapter request_hash")
    if expected_attempt_id is not None and attempt_id != expected_attempt_id:
        _fail("adapter attempt ID does not bind its plan")
    if expected_request_hash is not None and request_hash != expected_request_hash:
        _fail("adapter request hash does not bind its plan")
    lineage = _lineage(record.get("lineage"), operation)
    if expected_lineage is not None and lineage != dict(expected_lineage):
        _fail("adapter lineage does not bind its plan")

    schema_version = record.get("schema_version")
    if type(schema_version) is not str:
        _fail("adapter schema is invalid")
    if schema_version == QUARANTINE_SCHEMA:
        fields = {
            "schema_version",
            "attempt_id",
            "request_hash",
            "operation",
            "outcome",
            "evidence_status",
            "quarantine",
            "lineage",
        }
        _object(record, fields, "quarantine adapter outcome")
        quarantine = _object(record["quarantine"], {"content_sha256", "byte_length", "reason", "access"}, "quarantine")
        digest = _sha(quarantine["content_sha256"], "quarantine content_sha256")
        length = _uint(quarantine["byte_length"], "quarantine byte_length", maximum=MAX_CONTENT_BYTES)
        if (
            outcome != "refused"
            or lineage != _NO_LINEAGE
            or _fixed_text(quarantine["reason"], "phi_suspected", "quarantine reason")
            != "phi_suspected"
        ):
            _fail("quarantine adapter outcome is invalid")
        if type(quarantine["access"]) is not str or quarantine["access"] not in {"public", "workspace", "restricted"}:
            _fail("quarantine access is invalid")
        if expected_access is not None and quarantine["access"] != expected_access:
            _fail("quarantine access does not bind its plan")
        if content_identity is not None and (
            digest != content_identity.get("sha256") or length != content_identity.get("byte_length")
        ):
            _fail("quarantine does not bind its content")
        if record_id is not None and canonical_hash(record) != record_id:
            _fail("quarantine record hash is invalid")
        return AdapterOutcome(operation, kind, QUARANTINE_SCHEMA, provider, outcome, evidence, False, "none", {"object_key": f"quarantine:{record_id}", "content_sha256": record_id or ""})

    if operation == "transcribe":
        return _transcript_outcome(
            record,
            record_id=record_id,
            outcome=outcome,
            evidence=evidence,
            lineage=lineage,
            expected_payload=expected_payload,
            content_identity=content_identity,
        )

    fields = {
        "schema_version",
        "attempt_id",
        "request_hash",
        "operation",
        "outcome",
        "evidence_status",
        "reason",
        "provider",
        "retrieved_at",
        "content_sha256",
        "byte_length",
        "lineage",
    }
    fields |= {"query", "limit", "leads"} if operation == "ingest.search" else {"url"}
    # ``options`` is additive: every record committed before it existed omits
    # the field and must stay exactly as valid as the day it was written.
    _object(record, fields, "adapter outcome", optional={"options"} if operation == "ingest.search" else set())
    if (
        _fixed_text(record["schema_version"], operation_schema, "adapter schema")
        != operation_schema
        or _fixed_text(record["provider"], provider, "adapter provider") != provider
    ):
        _fail("adapter provider or schema is invalid")
    if _fixed_text(record["reason"], _REASONS[outcome], "adapter reason") != _REASONS[outcome]:
        _fail("adapter reason is invalid")
    _timestamp(record["retrieved_at"], "adapter retrieved_at")
    staged = outcome in _STAGED
    digest = record["content_sha256"]
    length = record["byte_length"]
    if staged:
        digest = _sha(digest, "adapter content_sha256")
        length = _uint(length, "adapter byte_length", maximum=MAX_CONTENT_BYTES)
        if length == 0:
            _fail("staged adapter content is empty")
    elif type(digest) is not str or digest != "none" or type(length) is not int or length != 0:
        _fail("unstaged adapter outcome claims content")
    if content_identity is not None:
        expected_digest = content_identity.get("sha256")
        expected_length = content_identity.get("byte_length")
        if staged:
            if digest != expected_digest or length != expected_length:
                _fail("adapter content does not bind its plan")
        elif content_identity != {
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "byte_length": 0,
        }:
            _fail("unstaged adapter plan has content")
    if operation == "ingest.search":
        query = _text(record["query"], "search query", maximum=MAX_QUERY_CHARS)
        limit = record["limit"]
        if type(limit) is not int or not 1 <= limit <= 50:
            _fail("search limit is invalid")
        leads = _leads(record["leads"], limit)
        if not staged and leads:
            _fail("unstaged search outcome claims leads")
        if "options" in record:
            validate_search_options(record["options"])
        if expected_payload is not None and (
            query != expected_payload.get("query")
            or limit != expected_payload.get("limit")
            or record.get("options") != expected_payload.get("options")
        ):
            _fail("search record does not bind its request")
        canonical_url = "none"
    else:
        url = _url(record["url"], "extract URL")
        if expected_payload is not None and url != expected_payload.get("url"):
            _fail("extract record does not bind its request")
        canonical_url = url
    if record_id is not None and canonical_hash(record) != record_id:
        _fail("adapter record hash is invalid")
    dedupe = (
        {"object_key": f"{kind}:{digest}", "content_sha256": digest}
        if staged
        else {"object_key": f"{kind}-outcome:{record_id}", "content_sha256": record_id or ""}
    )
    return AdapterOutcome(operation, kind, operation_schema, provider, outcome, evidence, staged, canonical_url, dedupe)


def validate_adapter_outcome(
    record: object,
    event: object,
    *,
    record_id: str,
    **expected: Any,
) -> AdapterOutcome:
    """Validate an exact adapter record/event pair and every cross-binding."""

    record_id = _sha(record_id, "adapter record_id")
    outcome = validate_adapter_record(record, record_id=record_id, **expected)
    content_length = (
        record["byte_length"]
        if outcome.staged
        else record["quarantine"]["byte_length"]
        if outcome.schema == QUARANTINE_SCHEMA
        else 0
    )
    checked_event = _journal(
        event,
        outcome,
        record_id=record_id,
        content_length=content_length,
    )
    try:
        canonical_event = validate_journal_envelope(checked_event)
    except ValueError as error:
        raise AdapterOutcomeError("adapter journal event is invalid") from error
    if canonical_event != checked_event:
        _fail("adapter journal event changed during validation")
    lineage = record["lineage"]
    artifact = {
        "kind": outcome.kind,
        "schema": outcome.schema,
        "record_id": record_id,
        "hash": record_id,
        "authorized_uri": f"houndd://record/{record_id}",
    }
    source = {
        "provider": outcome.provider,
        "native_id": record_id,
        "canonical_url": outcome.canonical_url,
    }
    if (
        event.get("artifact") != artifact
        or event.get("source") != source
        or event.get("classification") != {"outcome": outcome.outcome, "evidence_status": outcome.evidence_status}
        or event.get("lineage") != lineage
        or event.get("dedupe") != outcome.dedupe
    ):
        _fail("adapter record and journal event disagree")
    if outcome.schema == QUARANTINE_SCHEMA and event["usage"]["requests"] != 1:
        _fail("quarantine does not bind one provider exchange")
    return outcome


__all__ = [
    "AdapterOutcome",
    "AdapterOutcomeError",
    "MAX_CONTENT_BYTES",
    "MAX_TRANSCRIPT_SEGMENTS",
    "QUARANTINE_SCHEMA",
    "SEARCH_RECORD_SCHEMA",
    "TRANSCRIPT_RECORD_SCHEMA",
    "URL_RECORD_SCHEMA",
    "validate_adapter_outcome",
    "validate_adapter_record",
    "validate_search_options",
]
