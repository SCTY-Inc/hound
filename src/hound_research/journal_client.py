"""Minimal socket-only client for the Slice 3B journal read boundary.

This module intentionally imports neither the transitional research commands
nor provider-facing helpers.  It is safe to import in an isolated wheel smoke
test that permits only local Unix-domain socket transport.
"""

from __future__ import annotations

import json
import os
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


def strict_response(raw: bytes, *, request_id: str) -> dict[str, Any]:
    """Decode and semantically validate one complete Slice 3B response."""

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
    required = {"schema_version", "request_id", "ok", "outcome", "record_ids", "entry_ids", "usage"}
    optional = {"result", "cursor", "error"}
    if type(body) is not dict or set(body) - required - optional or required - set(body):
        raise _invalid()
    if body["schema_version"] != RESPONSE_SCHEMA or body["request_id"] != request_id or type(body["ok"]) is not bool or not _text(body["outcome"]):
        raise _invalid()
    if type(body["record_ids"]) is not list or type(body["entry_ids"]) is not list or any(not _text(item) for item in body["record_ids"] + body["entry_ids"]):
        raise _invalid()
    usage = body["usage"]
    if type(usage) is not dict or set(usage) != {"requests", "bytes", "cost"} or any(type(usage[key]) is not int or usage[key] < 0 for key in usage):
        raise _invalid()
    status = value["status"]
    if status == 200:
        if body["ok"] is not True or body["outcome"] != "completed" or "error" in body or type(body.get("result")) is not list:
            raise _invalid()
        if "cursor" in body and not _text(body["cursor"]):
            raise _invalid()
        result = body["result"]
        if any(type(event) is not dict or not _text(event.get("entry_id")) or type(event.get("artifact")) is not dict or not _text(event["artifact"].get("record_id")) for event in result):
            raise _invalid()
        if body["entry_ids"] != [event["entry_id"] for event in result] or body["record_ids"] != [event["artifact"]["record_id"] for event in result]:
            raise _invalid()
    elif status == 400:
        if body["ok"] is not False or body["outcome"] != "invalid" or "result" in body or "cursor" in body or not _error(body.get("error"), retryable=False):
            raise _invalid()
    elif status == 404:
        if body["ok"] is not False or body["outcome"] != "not_found" or body["entry_ids"] or body["record_ids"] or optional & set(body):
            raise _invalid()
    else:
        if body["ok"] is not False or body["outcome"] != "unavailable" or "result" in body or "cursor" in body or not _error(body.get("error"), retryable=True):
            raise _invalid()
    return value


def exchange(socket_path: Path, request: dict[str, Any], *, timeout: float = 5) -> dict[str, Any]:
    """Send one canonical request, half-close, then require one response."""

    if not socket_path.is_absolute():
        raise JournalClientError("journal socket must be absolute")
    request_id = request.get("body", {}).get("request_id") if type(request.get("body")) is dict else None
    if not _text(request_id):
        raise JournalClientError("journal request ID is invalid")
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
            response = strict_response(_read_exact(connection, length), request_id=request_id)
            if connection.recv(1):
                raise _invalid()
            return response
    except JournalClientError:
        raise
    except OSError as error:
        raise JournalClientError("houndd is unavailable") from error


__all__ = ["JournalClientError", "exchange", "strict_response"]
