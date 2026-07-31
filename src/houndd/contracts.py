"""HSP-04: strict canonical request, response, and journal contracts."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from datetime import datetime
from typing import Any


class ContractError(ValueError):
    """A houndd value does not satisfy the canonical contract."""


ACCESS_TIERS = {"public", "workspace", "restricted"}
_REQUEST_REQUIRED = {
    "schema_version",
    "request_id",
    "idempotency_key",
    "producer",
    "requested_access",
    "policy_id",
    "operation",
}
_RESPONSE_REQUIRED = {
    "schema_version",
    "request_id",
    "ok",
    "outcome",
    "record_ids",
    "entry_ids",
    "usage",
}
_JOURNAL_REQUIRED = {
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
_JOURNAL_OPTIONAL = set()
_FORBIDDEN_CANONICAL_KEYS = {
    "summary",
    "priority",
    "status",
    "next_action",
    "approval",
    "crm",
    "crm_claim",
    "wiki",
    "wiki_claim",
    "domain_tags",
    "tags",
}


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ContractError(f"{label} must be an object")
    return dict(value)


def _strict(value: Mapping[str, Any], required: set[str], optional: set[str], label: str) -> None:
    if not all(isinstance(key, str) for key in value):
        raise ContractError(f"{label} keys must be strings")
    missing = required - value.keys()
    unknown = set(value) - required - optional
    if missing or unknown:
        detail = []
        if missing:
            detail.append(f"missing {sorted(missing)!r}")
        if unknown:
            detail.append(f"unknown {sorted(unknown)!r}")
        raise ContractError(f"{label} has {' and '.join(detail)}")


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ContractError(f"{label} must be a non-empty string")
    return value


def _hash(value: Any, label: str) -> str:
    value = _text(value, label)
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ContractError(f"{label} must be a lowercase SHA-256 hex digest")
    return value


def _timestamp(value: Any, label: str) -> str:
    value = _text(value, label)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ContractError(f"{label} must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None:
        raise ContractError(f"{label} must include a timezone")
    return value


def _nonnegative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ContractError(f"{label} must be a non-negative integer")
    return value


def _finite_json(value: Any, path: str = "value") -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ContractError(f"{path} contains a non-finite number")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ContractError(f"{path} keys must be strings")
            _finite_json(item, f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _finite_json(item, f"{path}[]")
        return
    raise ContractError(f"{path} is not JSON-compatible")


def canonical_json(value: Any) -> str:
    """Return stable, path-independent, compact canonical JSON."""

    _finite_json(value)
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        encoded.encode("utf-8")
    except (TypeError, UnicodeError, ValueError, OverflowError, RecursionError) as error:
        raise ContractError(f"value cannot be canonicalized: {error}") from error
    return encoded


def canonical_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _validate_producer(value: Any, label: str = "producer") -> dict[str, Any]:
    producer = _object(value, label)
    _strict(producer, {"owner_id", "capability", "run_id"}, set(), label)
    for key in producer:
        _text(producer[key], f"{label}.{key}")
    return producer


def validate_request(value: Any) -> dict[str, Any]:
    """Validate the exact VISION request envelope."""

    request = _object(value, "request")
    _strict(request, _REQUEST_REQUIRED, set(), "request")
    _text(request["schema_version"], "request.schema_version")
    _text(request["request_id"], "request.request_id")
    _text(request["idempotency_key"], "request.idempotency_key")
    _validate_producer(request["producer"], "request.producer")
    if request["requested_access"] not in ACCESS_TIERS:
        raise ContractError("request.requested_access is not a supported access tier")
    _text(request["policy_id"], "request.policy_id")
    operation = _object(request["operation"], "request.operation")
    _strict(operation, {"name", "payload"}, set(), "request.operation")
    _text(operation["name"], "request.operation.name")
    if not isinstance(operation["payload"], Mapping):
        raise ContractError("request.operation.payload must be an object")
    _finite_json(request)
    return request


def canonical_request_hash(value: Any) -> str:
    """Hash request semantics, excluding transport/request retry identifiers."""

    request = validate_request(value)
    semantic = {key: item for key, item in request.items() if key not in {"request_id", "idempotency_key"}}
    return canonical_hash(semantic)


def make_response(
    request_id: str,
    *,
    ok: bool,
    outcome: str,
    record_ids: list[str] | tuple[str, ...] = (),
    entry_ids: list[str] | tuple[str, ...] = (),
    usage: Mapping[str, Any] | None = None,
    cursor: str | None = None,
    error: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the exact response envelope, omitting only optional fields."""

    if not isinstance(ok, bool):
        raise ContractError("response.ok must be boolean")
    response: dict[str, Any] = {
        "schema_version": "houndd.response.v1",
        "request_id": _text(request_id, "response.request_id"),
        "ok": ok,
        "outcome": _text(outcome, "response.outcome"),
        "record_ids": list(record_ids),
        "entry_ids": list(entry_ids),
        "usage": {
            key: usage[key]
            for key in ("requests", "bytes", "cost")
            if usage is not None and key in usage and usage[key] is not None
        },
    }
    if cursor is not None:
        response["cursor"] = _text(cursor, "response.cursor")
    if error is not None:
        response["error"] = dict(error)
    return validate_response(response)


def validate_response(value: Any) -> dict[str, Any]:
    """Validate the exact VISION response envelope."""

    response = _object(value, "response")
    _strict(response, _RESPONSE_REQUIRED, {"cursor", "error"}, "response")
    _text(response["schema_version"], "response.schema_version")
    _text(response["request_id"], "response.request_id")
    if not isinstance(response["ok"], bool):
        raise ContractError("response.ok must be boolean")
    _text(response["outcome"], "response.outcome")
    for field in ("record_ids", "entry_ids"):
        if not isinstance(response[field], list) or any(not isinstance(item, str) for item in response[field]):
            raise ContractError(f"response.{field} must be an array of strings")
    usage = _object(response["usage"], "response.usage")
    _strict(usage, set(), {"requests", "bytes", "cost"}, "response.usage")
    for key, item in usage.items():
        if isinstance(item, bool) or not isinstance(item, (int, float)) or not math.isfinite(item) or item < 0:
            raise ContractError(f"response.usage.{key} must be a non-negative finite number")
    if "cursor" in response:
        _text(response["cursor"], "response.cursor")
    if "error" in response:
        error = _object(response["error"], "response.error")
        _strict(error, {"code", "retryable", "message"}, set(), "response.error")
        _text(error["code"], "response.error.code")
        if not isinstance(error["retryable"], bool):
            raise ContractError("response.error.retryable must be boolean")
        _text(error["message"], "response.error.message")
    _finite_json(response)
    return response


def _reject_forbidden(value: Any, path: str) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if key in _FORBIDDEN_CANONICAL_KEYS:
                raise ContractError(f"{path}.{key} is not canonical journal truth")
            _reject_forbidden(item, f"{path}.{key}")
    elif isinstance(value, list):
        for item in value:
            _reject_forbidden(item, f"{path}[]")


def _validate_usage(value: Any) -> dict[str, Any]:
    usage = _object(value, "journal.usage")
    _strict(usage, set(), {"requests", "bytes", "cost"}, "journal.usage")
    for key, item in usage.items():
        if isinstance(item, bool) or not isinstance(item, (int, float)) or not math.isfinite(item) or item < 0:
            raise ContractError(f"journal.usage.{key} must be a non-negative finite number")
    return usage


def make_journal_envelope(
    *,
    sequence: int,
    appended_at: str,
    producer: Mapping[str, Any],
    artifact: Mapping[str, Any],
    classification: Mapping[str, Any],
    access: str,
    policy_id: str,
    dedupe: Mapping[str, Any],
    lineage: Mapping[str, Any],
    source: Mapping[str, Any],
    usage: Mapping[str, Any],
    schema_version: str = "houndd.journal.v1",
) -> dict[str, Any]:
    """Create one VISION journal envelope with an identity-derived entry ID."""

    body: dict[str, Any] = {
        "schema_version": _text(schema_version, "journal.schema_version"),
        "entry_id": "",
        "sequence": _nonnegative_int(sequence, "journal.sequence"),
        "appended_at": _timestamp(appended_at, "journal.appended_at"),
        "producer": dict(producer),
        "artifact": dict(artifact),
        "classification": dict(classification),
        "access": access,
        "policy_id": _text(policy_id, "journal.policy_id"),
        "dedupe": dict(dedupe),
    }
    body["lineage"] = dict(lineage)
    body["source"] = dict(source)
    body["usage"] = {
        key: usage[key]
        for key in ("requests", "bytes", "cost")
        if key in usage and usage[key] is not None
    }
    body["entry_id"] = canonical_hash({key: item for key, item in body.items() if key != "entry_id"})
    return validate_journal_envelope(body)


def validate_journal_envelope(value: Any) -> dict[str, Any]:
    """Validate the immutable journal envelope and its omission rules."""

    envelope = _object(value, "journal")
    _strict(envelope, _JOURNAL_REQUIRED, _JOURNAL_OPTIONAL, "journal")
    if envelope["schema_version"] != "houndd.journal.v1":
        raise ContractError("journal.schema_version must be 'houndd.journal.v1'")
    _hash(envelope["entry_id"], "journal.entry_id")
    _nonnegative_int(envelope["sequence"], "journal.sequence")
    _timestamp(envelope["appended_at"], "journal.appended_at")
    _validate_producer(envelope["producer"], "journal.producer")
    artifact = _object(envelope["artifact"], "journal.artifact")
    _strict(artifact, {"kind", "schema", "record_id", "hash", "authorized_uri"}, set(), "journal.artifact")
    for key in ("kind", "schema", "record_id", "authorized_uri"):
        _text(artifact[key], f"journal.artifact.{key}")
    _hash(artifact["hash"], "journal.artifact.hash")
    classification = _object(envelope["classification"], "journal.classification")
    _strict(classification, {"outcome", "evidence_status"}, set(), "journal.classification")
    _text(classification["outcome"], "journal.classification.outcome")
    _text(classification["evidence_status"], "journal.classification.evidence_status")
    if envelope["access"] not in ACCESS_TIERS:
        raise ContractError("journal.access is not a supported access tier")
    _text(envelope["policy_id"], "journal.policy_id")
    dedupe = _object(envelope["dedupe"], "journal.dedupe")
    _strict(dedupe, {"object_key", "content_sha256"}, set(), "journal.dedupe")
    _text(dedupe["object_key"], "journal.dedupe.object_key")
    _hash(dedupe["content_sha256"], "journal.dedupe.content_sha256")
    if "lineage" in envelope:
        lineage = _object(envelope["lineage"], "journal.lineage")
        _strict(lineage, {"relation", "record_id", "lead_id"}, set(), "journal.lineage")
        _text(lineage["relation"], "journal.lineage.relation")
        _text(lineage["record_id"], "journal.lineage.record_id")
        _text(lineage["lead_id"], "journal.lineage.lead_id")
    if "source" in envelope:
        source = _object(envelope["source"], "journal.source")
        _strict(source, {"provider", "native_id", "canonical_url"}, set(), "journal.source")
        for key in source:
            _text(source[key], f"journal.source.{key}")
    if "usage" in envelope:
        _validate_usage(envelope["usage"])
    _reject_forbidden(envelope, "journal")
    expected_id = canonical_hash({key: item for key, item in envelope.items() if key != "entry_id"})
    if envelope["entry_id"] != expected_id:
        raise ContractError("journal.entry_id does not match its canonical envelope")
    _finite_json(envelope)
    return envelope


def validate_forbidden_fields(value: Any) -> None:
    """Raise when canonical journal truth contains a VISION-forbidden field."""

    _reject_forbidden(value, "value")


__all__ = [
    "ACCESS_TIERS",
    "ContractError",
    "canonical_bytes",
    "canonical_hash",
    "canonical_json",
    "canonical_request_hash",
    "make_journal_envelope",
    "make_response",
    "validate_forbidden_fields",
    "validate_journal_envelope",
    "validate_request",
    "validate_response",
]
