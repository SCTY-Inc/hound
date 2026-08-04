"""Minimal socket-only client for the Slice 3B journal read boundary.

This module intentionally imports neither the transitional research commands
nor provider-facing helpers.  It is safe to import in an isolated wheel smoke
test that permits only local Unix-domain socket transport.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from collections.abc import Callable
from pathlib import Path
import socket
from typing import Any

from houndd.contracts import canonical_bytes
from houndd.service import MAX_FRAME_BYTES, RESPONSE_SCHEMA, WIRE_VERSION


class JournalClientError(RuntimeError):
    """An unavailable or invalid local journal transport response."""


def _read_exact(connection: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            raise JournalClientError("houndd response was truncated")
        data.extend(chunk)
    return bytes(data)


def _invalid() -> JournalClientError:
    return JournalClientError("houndd response violates the read contract")


def _text(value: object) -> bool:
    return type(value) is str and bool(value) and len(value) <= 512


def _error(value: object, *, retryable: bool) -> bool:
    return (
        type(value) is dict
        and set(value) == {"code", "retryable", "message"}
        and _text(value["code"])
        and type(value["retryable"]) is bool
        and value["retryable"] is retryable
        and _text(value["message"])
    )


def _ledger_row(value: object) -> bool:
    fields = {"entry_id", "appended_at", "producer", "operation", "source", "classification", "artifact", "lineage", "access"}
    if type(value) is not dict or set(value) != fields or not _text(value.get("entry_id")) or not _text(value.get("appended_at")) or not _text(value.get("access")):
        return False
    nested = (
        ("producer", {"owner_id", "capability", "run_id"}),
        ("operation", {"capability", "artifact_kind"}),
        ("source", {"provider"}),
        ("classification", {"outcome", "evidence_status"}),
        ("artifact", {"record_id"}),
        ("lineage", {"relation", "record_id", "lead_id"}),
    )
    return all(type(value[name]) is dict and set(value[name]) == keys and all(_text(item) for item in value[name].values()) for name, keys in nested)


_REQUIRED_BODY_FIELDS = frozenset({"schema_version", "request_id", "ok", "outcome", "record_ids", "entry_ids", "usage"})
_OPTIONAL_BODY_FIELDS = frozenset({"result", "cursor", "projection", "error"})


def _envelope(raw: bytes, *, request_id: str) -> tuple[dict[str, Any], dict[str, Any], int]:
    """Decode one response frame and check every field the reads share."""

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite number")))
    except (UnicodeError, ValueError) as error:
        raise _invalid() from error
    if type(value) is not dict or canonical_bytes(value) != raw:
        raise _invalid()
    if set(value) != {"wire_version", "status", "body"} or value["wire_version"] != WIRE_VERSION or type(value["status"]) is not int or value["status"] not in {200, 400, 404, 503}:
        raise _invalid()
    body = value["body"]
    if type(body) is not dict or set(body) - _REQUIRED_BODY_FIELDS - _OPTIONAL_BODY_FIELDS or _REQUIRED_BODY_FIELDS - set(body):
        raise _invalid()
    if body["schema_version"] != RESPONSE_SCHEMA or body["request_id"] != request_id or type(body["ok"]) is not bool or not _text(body["outcome"]):
        raise _invalid()
    if type(body["record_ids"]) is not list or type(body["entry_ids"]) is not list or any(not _text(item) for item in body["record_ids"] + body["entry_ids"]):
        raise _invalid()
    usage = body["usage"]
    if type(usage) is not dict or set(usage) != {"requests", "bytes", "cost"} or any(type(usage[key]) is not int or usage[key] < 0 for key in usage):
        raise _invalid()
    return value, body, value["status"]


def _non_success(body: dict[str, Any], status: int) -> None:
    """Check the three non-success shapes every read response shares."""

    if status == 400:
        if body["ok"] is not False or body["outcome"] != "invalid" or "result" in body or "cursor" in body or "projection" in body or not _error(body.get("error"), retryable=False):
            raise _invalid()
    elif status == 404:
        if body["ok"] is not False or body["outcome"] != "not_found" or body["entry_ids"] or body["record_ids"] or _OPTIONAL_BODY_FIELDS & set(body):
            raise _invalid()
    else:
        if body["ok"] is not False or body["outcome"] != "unavailable" or "result" in body or "cursor" in body or "projection" in body or not _error(body.get("error"), retryable=True):
            raise _invalid()


def strict_response(raw: bytes, *, request_id: str, view: str | None = None) -> dict[str, Any]:
    """Decode and semantically validate one complete Slice 3B response."""

    value, body, status = _envelope(raw, request_id=request_id)
    if status != 200:
        _non_success(body, status)
        return value
    if body["ok"] is not True or body["outcome"] != "completed" or "error" in body or type(body.get("result")) is not list:
        raise _invalid()
    if "cursor" in body and not _text(body["cursor"]):
        raise _invalid()
    result = body["result"]
    if view is None and "projection" in body:
        raise _invalid()
    if view == "intake-ledger.v1":
        projection = body.get("projection")
        if type(projection) is not dict or projection.get("schema_version") != "houndd.intake-ledger.v1" or projection.get("integrity") != "verified" or not _text(projection.get("high_watermark")) or set(projection) != {"schema_version", "integrity", "high_watermark"}:
            raise _invalid()
        if any(not _ledger_row(event) for event in result):
            raise _invalid()
    elif view is not None:
        raise _invalid()
    elif any(type(event) is not dict or not _text(event.get("entry_id")) or type(event.get("artifact")) is not dict or not _text(event["artifact"].get("record_id")) for event in result):
        raise _invalid()
    if body["entry_ids"] != [event["entry_id"] for event in result] or body["record_ids"] != [event["artifact"]["record_id"] for event in result]:
        raise _invalid()
    return value


def _connect(socket_path: Path, request: dict[str, Any], timeout: float, validate: Callable[[bytes], dict[str, Any]]) -> dict[str, Any]:
    """Send one canonical request, half-close, then require one response."""

    if not socket_path.is_absolute():
        raise JournalClientError("journal socket must be absolute")
    raw = canonical_bytes(request)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout)
            connection.connect(os.fspath(socket_path))
            connection.sendall(len(raw).to_bytes(4, "big") + raw)
            connection.shutdown(socket.SHUT_WR)
            length = int.from_bytes(_read_exact(connection, 4), "big")
            if not 0 < length <= MAX_FRAME_BYTES:
                raise _invalid()
            response = validate(_read_exact(connection, length))
            if connection.recv(1):
                raise _invalid()
            return response
    except JournalClientError:
        raise
    except OSError as error:
        raise JournalClientError("houndd is unavailable") from error


def _request_id(request: dict[str, Any]) -> str:
    request_id = request.get("body", {}).get("request_id") if type(request.get("body")) is dict else None
    if not _text(request_id):
        raise JournalClientError("journal request ID is invalid")
    return request_id


# Reads are near-instant, but the daemon serves one connection at a time and a
# commit holds it through a full provider round trip — a read arriving behind
# one must out-wait it, not spuriously report the daemon unavailable.
READ_EXCHANGE_TIMEOUT_SECONDS = 60


def exchange(socket_path: Path, request: dict[str, Any], *, timeout: float = READ_EXCHANGE_TIMEOUT_SECONDS) -> dict[str, Any]:
    """Exchange one journal query or single-entry read."""

    request_id = _request_id(request)
    payload = request.get("body", {}).get("operation", {}).get("payload") if type(request.get("body")) is dict and type(request["body"].get("operation")) is dict else None
    view = payload.get("view") if type(payload) is dict else None
    if view is not None and view != "intake-ledger.v1":
        raise JournalClientError("journal view is invalid")
    order = payload.get("order") if type(payload) is dict else None
    if order is not None and order not in {"ascending", "descending"}:
        raise JournalClientError("journal order is invalid")
    return _connect(socket_path, request, timeout, lambda raw: strict_response(raw, request_id=request_id, view=view))


_RECORD_RESULT_REQUIRED = frozenset({"schema", "record_id", "body_base64", "byte_length"})
_RECORD_RESULT_OPTIONAL = frozenset({"content_base64", "content_sha256", "content_byte_length"})
_SHA256_HEX_DIGITS = frozenset("0123456789abcdef")


def _non_negative_int(value: object) -> bool:
    return type(value) is int and value >= 0


def _base64_bytes(value: object) -> bytes | None:
    """Decode a base64 payload field (unbounded length, unlike short `_text` ids)."""

    if type(value) is not str or not value:
        return None
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        return None


def _record_result(value: object) -> bool:
    if type(value) is not dict:
        return False
    keys = set(value)
    if keys - (_RECORD_RESULT_REQUIRED | _RECORD_RESULT_OPTIONAL) or _RECORD_RESULT_REQUIRED - keys:
        return False
    has_optional = bool(keys & _RECORD_RESULT_OPTIONAL)
    if has_optional and _RECORD_RESULT_OPTIONAL - keys:
        return False
    if not _text(value["schema"]) or not _text(value["record_id"]) or not _non_negative_int(value["byte_length"]):
        return False
    body = _base64_bytes(value["body_base64"])
    if body is None or len(body) != value["byte_length"]:
        return False
    if has_optional:
        if not _non_negative_int(value["content_byte_length"]):
            return False
        content = _base64_bytes(value["content_base64"])
        if content is None or len(content) != value["content_byte_length"]:
            return False
        digest = value["content_sha256"]
        if type(digest) is not str or len(digest) != 64 or set(digest) - _SHA256_HEX_DIGITS:
            return False
        if hashlib.sha256(content).hexdigest() != digest:
            return False
    return True


def record_strict_response(raw: bytes, *, request_id: str) -> dict[str, Any]:
    """Decode and semantically validate one complete record.get response."""

    value, body, status = _envelope(raw, request_id=request_id)
    if status != 200:
        _non_success(body, status)
        return value
    if body["ok"] is not True or body["outcome"] != "completed" or "error" in body or "cursor" in body or "projection" in body:
        raise _invalid()
    result = body.get("result")
    if type(result) is not list or len(result) != 1 or not _record_result(result[0]):
        raise _invalid()
    return value


def record_exchange(socket_path: Path, request: dict[str, Any], *, timeout: float = READ_EXCHANGE_TIMEOUT_SECONDS) -> dict[str, Any]:
    """Exchange one record.get read."""

    request_id = _request_id(request)
    return _connect(socket_path, request, timeout, lambda raw: record_strict_response(raw, request_id=request_id))


def report_strict_response(raw: bytes, *, request_id: str, schema: str) -> dict[str, Any]:
    """Decode and semantically validate one maintenance-report response.

    A verify or rebuild-index report is exactly its schema and one boolean.
    Aligned IDs stay empty because the report is neither a journal event nor a
    record, and the report never carries per-object failure detail.
    """

    value, body, status = _envelope(raw, request_id=request_id)
    if status != 200:
        _non_success(body, status)
        return value
    if body["ok"] is not True or body["outcome"] != "completed" or "error" in body or "cursor" in body or "projection" in body:
        raise _invalid()
    if body["entry_ids"] or body["record_ids"]:
        raise _invalid()
    result = body.get("result")
    if type(result) is not list or len(result) != 1:
        raise _invalid()
    report = result[0]
    if type(report) is not dict or set(report) != {"schema_version", "valid"} or report["schema_version"] != schema or type(report["valid"]) is not bool:
        raise _invalid()
    return value


def report_exchange(socket_path: Path, request: dict[str, Any], *, schema: str, timeout: float = READ_EXCHANGE_TIMEOUT_SECONDS) -> dict[str, Any]:
    """Exchange one journal.verify or journal.rebuild-index read."""

    request_id = _request_id(request)
    return _connect(socket_path, request, timeout, lambda raw: report_strict_response(raw, request_id=request_id, schema=schema))


__all__ = ["JournalClientError", "exchange", "record_exchange", "record_strict_response", "report_exchange", "report_strict_response", "strict_response"]
