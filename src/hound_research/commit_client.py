"""Strict socket-only client for the two public Slice 3C1 commit commands."""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
from typing import Any

from houndd.commit import COMMIT_RESPONSE_SCHEMA, validate_commit_response
from houndd.contracts import canonical_bytes
from houndd.service import MAX_FRAME_BYTES, WIRE_VERSION


class CommitClientError(RuntimeError):
    """The local commit daemon returned malformed or unavailable transport."""


def _read_exact(connection: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            raise CommitClientError("houndd response was truncated")
        data.extend(chunk)
    return bytes(data)


def strict_response(raw: bytes, *, request_id: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        frame = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite")))
    except (UnicodeError, ValueError) as error:
        raise CommitClientError("houndd response violates the commit contract") from error
    if type(frame) is not dict or canonical_bytes(frame) != raw or set(frame) != {"wire_version", "status", "body"}:
        raise CommitClientError("houndd response violates the commit contract")
    if frame["wire_version"] != WIRE_VERSION or type(frame["status"]) is not int or frame["status"] not in {200, 400, 404, 503}:
        raise CommitClientError("houndd response violates the commit contract")
    try:
        body = validate_commit_response(frame["body"])
    except ValueError as error:
        raise CommitClientError("houndd response violates the commit contract") from error
    if body["schema_version"] != COMMIT_RESPONSE_SCHEMA or body["request_id"] != request_id:
        raise CommitClientError("houndd response violates the commit contract")
    status = frame["status"]
    if status == 200:
        # A durable operation is transport-successful even when its recorded
        # outcome is non-completed.  Those results are the evidence the caller
        # needs to receive (and map to exit 4), not malformed responses.
        if not body["record_ids"] or len(body["entry_ids"]) != 1:
            raise CommitClientError("houndd response violates the commit contract")
        if body["outcome"] == "completed":
            if body["ok"] is not True or "error" in body:
                raise CommitClientError("houndd response violates the commit contract")
        elif body["outcome"] in {"failed", "partial", "degraded", "refused", "interrupted"}:
            if body["ok"] is not False:
                raise CommitClientError("houndd response violates the commit contract")
        else:
            raise CommitClientError("houndd response violates the commit contract")
    elif status == 400:
        if body["ok"] is not False or body["outcome"] != "invalid" or body["record_ids"] or body["entry_ids"] or "error" not in body:
            raise CommitClientError("houndd response violates the commit contract")
    elif status == 404:
        if body["ok"] is not False or body["outcome"] != "invalid" or body["record_ids"] or body["entry_ids"] or "error" in body:
            raise CommitClientError("houndd response violates the commit contract")
    elif body["ok"] is not False or body["outcome"] != "unavailable" or body["record_ids"] or body["entry_ids"] or "error" not in body:
        raise CommitClientError("houndd response violates the commit contract")
    return frame


def exit_code(response: dict[str, Any]) -> int:
    """Map the durable transport status/outcome to the frozen CLI semantics."""

    status = response["status"]
    if status == 200:
        return 0 if response["body"]["outcome"] == "completed" else 4
    return {400: 2, 404: 3, 503: 5}[status]


def exchange(socket_path: Path, request: dict[str, Any], *, timeout: float = 5) -> dict[str, Any]:
    if not socket_path.is_absolute():
        raise CommitClientError("commit socket must be absolute")
    body = request.get("body") if type(request) is dict else None
    request_id = body.get("request_id") if type(body) is dict else None
    if type(request_id) is not str or not request_id:
        raise CommitClientError("commit request ID is invalid")
    raw = canonical_bytes(request)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout)
            connection.connect(os.fspath(socket_path))
            connection.sendall(len(raw).to_bytes(4, "big") + raw)
            connection.shutdown(socket.SHUT_WR)
            size = int.from_bytes(_read_exact(connection, 4), "big")
            if not 0 < size <= MAX_FRAME_BYTES:
                raise CommitClientError("houndd response violates the commit contract")
            response = strict_response(_read_exact(connection, size), request_id=request_id)
            if connection.recv(1):
                raise CommitClientError("houndd response violates the commit contract")
            return response
    except CommitClientError:
        raise
    except OSError as error:
        raise CommitClientError("houndd is unavailable") from error


__all__ = ["CommitClientError", "exchange", "exit_code", "strict_response"]
