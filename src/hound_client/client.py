"""Standard-library client for the houndd AF_UNIX commit/read boundary.

A lane repo that only needs to submit one durable commit, dereference one
record, or probe readiness talks to houndd through this module instead of
re-implementing the wire. It imports nothing from ``houndd``, so a consumer
can depend on the transport without depending on the daemon's internals.

The client is deliberately thin: it proves a response is canonical, answers
this request, and fits the frame bound, then hands the body back. Callers that
must validate the full response contract (the frozen CLI exit-code mapping,
for one) keep their own strict clients.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
from pathlib import Path
from typing import Any

WIRE_VERSION = "houndd.uds.v1"
MAX_FRAME_BYTES = 1_048_576
COMMIT_REQUEST_SCHEMA = "houndd.commit-request.v1"
READ_REQUEST_SCHEMA = "houndd.read-request.v1"

# A commit is synchronous: the daemon calls the search or extraction provider
# inside the request, so this bounds a provider round trip rather than an IPC
# hop. Reads only touch local state.
COMMIT_TIMEOUT_SECONDS = 180
READ_TIMEOUT_SECONDS = 15


class HounddClientError(RuntimeError):
    """Raised when the local houndd daemon cannot complete a request."""


def canonical_bytes(value: object) -> bytes:
    """Encode one JSON-safe value exactly as houndd canonicalizes it."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def default_socket_path() -> Path:
    """Locate the per-user daemon socket. Callers layer their own override."""

    runtime = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    return Path(runtime) / "hound" / "houndd.sock"


def _read_exact(connection: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            raise HounddClientError("houndd response was truncated")
        data.extend(chunk)
    return bytes(data)


def _failure(body: dict[str, Any]) -> str:
    error = body.get("error")
    if isinstance(error, dict) and isinstance(error.get("message"), str):
        return error["message"]
    outcome = body.get("outcome")
    return outcome if isinstance(outcome, str) else "unknown"


def _decode(value: object, *, label: str) -> bytes:
    if not isinstance(value, str):
        raise HounddClientError(f"houndd {label} is missing")
    try:
        return base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as error:
        raise HounddClientError(f"houndd {label} is not valid base64") from error


class HounddClient:
    """One producer identity talking to one houndd socket."""

    def __init__(
        self,
        socket_path: Path | None = None,
        *,
        owner_id: str,
        policy_id: str,
        requested_access: str = "public",
        commit_timeout: int = COMMIT_TIMEOUT_SECONDS,
        read_timeout: int = READ_TIMEOUT_SECONDS,
    ) -> None:
        self.socket_path = Path(socket_path) if socket_path is not None else default_socket_path()
        self.owner_id = owner_id
        self.policy_id = policy_id
        self.requested_access = requested_access
        self.commit_timeout = commit_timeout
        self.read_timeout = read_timeout

    def ready(self, *, run_id: str = "ready-check", request_id: str = "ready-probe") -> None:
        """Probe daemon readiness. Returns nothing; a fault is the only signal."""

        request = {
            "wire_version": WIRE_VERSION,
            "method": "GET",
            "path": "/v1/ready",
            "body": self._body(
                schema_version=READ_REQUEST_SCHEMA,
                request_id=request_id,
                capability="service.ready",
                run_id=run_id,
                payload={},
            ),
        }
        response = self._exchange(request, timeout=self.read_timeout)
        body = response["body"]
        if response.get("status") != 200 or body.get("ok") is not True:
            raise HounddClientError(f"houndd is not ready: {_failure(body)}")

    def commit(
        self,
        *,
        path: str,
        capability: str,
        payload: dict[str, Any],
        idempotency_key: str,
        request_id: str,
        run_id: str,
    ) -> str:
        """Run one durable operation and return the record it produced."""

        body = self._body(
            schema_version=COMMIT_REQUEST_SCHEMA,
            request_id=request_id,
            capability=capability,
            run_id=run_id,
            payload=payload,
        )
        body["idempotency_key"] = idempotency_key
        request = {"wire_version": WIRE_VERSION, "method": "POST", "path": path, "body": body}
        response = self._exchange(request, timeout=self.commit_timeout)
        result = response["body"]
        # A durable non-completed outcome is transport-successful, but the
        # operation still did not happen. Degrade; never invent a record.
        if response.get("status") != 200 or result.get("outcome") != "completed":
            raise HounddClientError(f"{capability} did not complete: {_failure(result)}")
        record_ids = result.get("record_ids")
        if (
            not isinstance(record_ids, list)
            or not record_ids
            or not isinstance(record_ids[0], str)
        ):
            raise HounddClientError(f"{capability} returned no record ID")
        return record_ids[0]

    def record_get(
        self,
        record_id: str,
        *,
        run_id: str,
        include_content: bool = False,
        request_id: str | None = None,
    ) -> tuple[dict[str, Any], bytes]:
        """Dereference one immutable record and optionally its stored content.

        ``request_id`` defaults to ``record-get-<first 32 chars of record_id>``,
        which is deterministic in the record so a replay carries the same ID.
        """

        payload: dict[str, Any] = {"record_id": record_id}
        if include_content:
            payload["include_content"] = True
        request = {
            "wire_version": WIRE_VERSION,
            "method": "GET",
            "path": "/v1/record",
            "body": self._body(
                schema_version=READ_REQUEST_SCHEMA,
                request_id=request_id or f"record-get-{record_id[:32]}",
                capability="record.get",
                run_id=run_id,
                payload=payload,
            ),
        }
        response = self._exchange(request, timeout=self.read_timeout)
        body = response["body"]
        label = f"record.get {record_id[:12]}"
        if response.get("status") != 200:
            raise HounddClientError(f"{label} failed: {_failure(body)}")
        result = body.get("result")
        if not isinstance(result, list) or len(result) != 1 or not isinstance(result[0], dict):
            raise HounddClientError(f"{label} returned no record")
        row = result[0]
        try:
            record = json.loads(_decode(row.get("body_base64"), label="record body"))
        except ValueError as error:
            raise HounddClientError(f"{label} body is not valid JSON") from error
        if not isinstance(record, dict):
            raise HounddClientError(f"{label} body is not an object")
        if not include_content:
            return record, b""
        content = _decode(row.get("content_base64"), label="record content")
        if hashlib.sha256(content).hexdigest() != row.get("content_sha256"):
            raise HounddClientError(f"{label} content does not match its declared digest")
        return record, content

    def _body(
        self,
        *,
        schema_version: str,
        request_id: str,
        capability: str,
        run_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "schema_version": schema_version,
            "request_id": request_id,
            "producer": {
                "owner_id": self.owner_id,
                "capability": capability,
                "run_id": run_id,
            },
            "requested_access": self.requested_access,
            "policy_id": self.policy_id,
            "operation": {"name": capability, "payload": payload},
        }

    def _exchange(self, request: dict[str, Any], *, timeout: int) -> dict[str, Any]:
        """Send one canonical request frame and require exactly one response frame."""

        raw = canonical_bytes(request)
        request_id = request["body"]["request_id"]
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(timeout)
                connection.connect(os.fspath(self.socket_path))
                connection.sendall(len(raw).to_bytes(4, "big") + raw)
                connection.shutdown(socket.SHUT_WR)
                size = int.from_bytes(_read_exact(connection, 4), "big")
                if not 0 < size <= MAX_FRAME_BYTES:
                    raise HounddClientError("houndd response frame is out of bounds")
                frame = _read_exact(connection, size)
        except OSError as error:
            raise HounddClientError(f"houndd is unavailable: {error}") from error

        try:
            response = json.loads(frame.decode("utf-8"))
        except (UnicodeError, ValueError) as error:
            raise HounddClientError("houndd response is not valid JSON") from error
        # Responses are canonical by contract, so re-encoding is the cheapest
        # proof that this frame arrived whole and unaltered.
        if not isinstance(response, dict) or canonical_bytes(response) != frame:
            raise HounddClientError("houndd response is not canonical")
        body = response.get("body")
        if (
            response.get("wire_version") != WIRE_VERSION
            or not isinstance(body, dict)
            or body.get("request_id") != request_id
        ):
            raise HounddClientError("houndd response does not answer this request")
        return response


__all__ = [
    "COMMIT_REQUEST_SCHEMA",
    "COMMIT_TIMEOUT_SECONDS",
    "HounddClient",
    "HounddClientError",
    "MAX_FRAME_BYTES",
    "READ_REQUEST_SCHEMA",
    "READ_TIMEOUT_SECONDS",
    "WIRE_VERSION",
    "canonical_bytes",
    "default_socket_path",
]
