"""Standard-library client for the houndd AF_UNIX commit/read boundary.

A lane repo that only needs to submit one durable commit, dereference one
record, or probe readiness talks to houndd through this module instead of
re-implementing the wire. It imports nothing from ``houndd``, so a consumer
can depend on the transport without depending on the daemon's internals.

The client accepts only one bounded canonical response frame. It validates the
exact commit and read response contracts before returning data to a caller.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import socket
from datetime import datetime
from pathlib import Path
from typing import Any

WIRE_VERSION = "houndd.uds.v1"
MAX_FRAME_BYTES = 1_048_576
COMMIT_REQUEST_SCHEMA = "houndd.commit-request.v1"
READ_REQUEST_SCHEMA = "houndd.read-request.v1"
COMMIT_RESPONSE_SCHEMA = "houndd.commit-response.v1"
READ_RESPONSE_SCHEMA = "houndd.read-response.v1"
MAX_FRAME_FRAGMENTS = 1_024
MAX_SOCKET_PATH_BYTES = 107

_COMMIT_PATHS = {
    "ingest.search": "/v1/ingest/search",
    "ingest.url": "/v1/ingest/url",
    "ingest.file": "/v1/ingest/file",
    "import.record": "/v1/import/record",
}
_DURABLE_ADAPTER_OUTCOMES = frozenset(
    {"failed", "partial", "degraded", "refused", "interrupted"}
)
_COMMIT_ERRORS = {
    "source_refused": (False, "source refused"),
    "invalid_request": (False, "invalid request"),
    "request_conflict": (False, "request conflict"),
    "unavailable": (True, "service unavailable"),
}
_RECORD_ERRORS = {
    "content_too_large": (False, "record content is too large"),
    "invalid_request": (False, "request is invalid"),
    "service_unavailable": (True, "service is unavailable"),
}
_ACCESS_TIERS = frozenset({"public", "workspace", "restricted"})
_JOURNAL_ENTRY_FIELDS = frozenset(
    {
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
)
_JOURNAL_ERRORS = {
    400: {
        "invalid_request": (False, "request is invalid"),
        "filter_not_available": (False, "filter is not available"),
    },
    503: {
        "service_unavailable": (True, "service is unavailable"),
        "response_too_large": (True, "service response is unavailable"),
    },
}

# A commit is synchronous: the daemon calls the search or extraction provider
# inside the request, so this bounds a provider round trip rather than an IPC
# hop. Reads only touch local state.
COMMIT_TIMEOUT_SECONDS = 180
READ_TIMEOUT_SECONDS = 15


class HounddClientError(RuntimeError):
    """Raised when the local houndd daemon cannot complete a request."""


class HounddJournalCursorRejectedError(HounddClientError):
    """The daemon could not recover a persisted journal cursor.

    There is no partial-resume option for a rejected cursor: the caller must
    resnapshot with ``cursor=None`` and rely on idempotent processing to
    absorb whatever gets redelivered.
    """


class HounddJournalFilterUnavailableError(HounddClientError):
    """The requested journal filter is not available to this caller's scope."""


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


def _read_exact(connection: socket.socket, size: int, fragments: list[int]) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            raise HounddClientError("houndd response was truncated")
        fragments[0] += 1
        if fragments[0] > MAX_FRAME_FRAGMENTS:
            raise HounddClientError("houndd response is too fragmented")
        data.extend(chunk)
    return bytes(data)


def _text(value: object, label: str) -> str:
    if type(value) is not str or not value or len(value) > 4_000:
        raise HounddClientError(f"houndd {label} is invalid")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise HounddClientError(f"houndd {label} is invalid")
    return value


def _fields(value: object, required: set[str], optional: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or not required <= set(value) <= required | optional:
        raise HounddClientError(f"houndd {label} has an invalid shape")
    return value


def _ids(value: object, label: str) -> list[str]:
    if type(value) is not list:
        raise HounddClientError(f"houndd {label} is invalid")
    values = [_text(item, f"{label} item") for item in value]
    if len(values) != len(set(values)):
        raise HounddClientError(f"houndd {label} contains duplicates")
    return values


def _usage(value: object) -> dict[str, int | float]:
    usage = _fields(value, {"requests", "bytes", "cost"}, set(), "usage")
    requests = usage["requests"]
    byte_count = usage["bytes"]
    cost = usage["cost"]
    if type(requests) is not int or requests < 0:
        raise HounddClientError("houndd usage requests is invalid")
    if type(byte_count) is not int or byte_count < 0:
        raise HounddClientError("houndd usage bytes is invalid")
    if type(cost) not in {int, float} or type(cost) is bool or not math.isfinite(cost) or cost < 0:
        raise HounddClientError("houndd usage cost is invalid")
    return {"requests": requests, "bytes": byte_count, "cost": cost}


def _error(value: object) -> dict[str, Any]:
    error = _fields(value, {"code", "retryable", "message"}, set(), "error")
    if type(error["retryable"]) is not bool:
        raise HounddClientError("houndd error retryable is invalid")
    return {
        "code": _text(error["code"], "error code"),
        "retryable": error["retryable"],
        "message": _text(error["message"], "error message"),
    }


def _safe_error(
    value: object,
    allowed: dict[str, tuple[bool, str]],
    label: str,
) -> dict[str, Any]:
    error = _error(value)
    expected = allowed.get(error["code"])
    if expected is None or (error["retryable"], error["message"]) != expected:
        raise HounddClientError(f"houndd {label} is invalid")
    return error


def _entry_usage(value: object) -> dict[str, int | float]:
    usage = _fields(value, set(), {"requests", "bytes", "cost"}, "journal entry usage")
    for key, item in usage.items():
        if type(item) is bool or type(item) not in {int, float} or not math.isfinite(item) or item < 0:
            raise HounddClientError(f"houndd journal entry usage.{key} is invalid")
    return usage


def _hash(value: object, label: str) -> str:
    text = _text(value, label)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise HounddClientError(f"houndd {label} is not a lowercase SHA-256 hex digest")
    return text


def _entry_timestamp(value: object, label: str) -> str:
    text = _text(value, label)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise HounddClientError(f"houndd {label} must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None:
        raise HounddClientError(f"houndd {label} must include a timezone")
    return text


def _journal_entry(value: object) -> dict[str, Any]:
    """Validate one journal envelope and its self-binding entry ID.

    Every field is checked against the exact envelope shape, then the entry
    ID is re-derived from the envelope's own canonical bytes: a page that is
    wire-canonical as a whole but carries a tampered field inside one entry
    (a flipped access tier, a rewritten policy ID) fails here even though the
    outer frame already passed ``_canonical_object``.
    """

    entry = _fields(value, _JOURNAL_ENTRY_FIELDS, set(), "journal entry")
    _hash(entry["entry_id"], "journal entry ID")
    if type(entry["sequence"]) is not int or entry["sequence"] < 0:
        raise HounddClientError("houndd journal entry sequence is invalid")
    _entry_timestamp(entry["appended_at"], "journal entry timestamp")
    producer = _fields(entry["producer"], {"owner_id", "capability", "run_id"}, set(), "journal entry producer")
    for key in producer:
        _text(producer[key], f"journal entry producer.{key}")
    artifact = _fields(entry["artifact"], {"kind", "schema", "record_id", "hash", "authorized_uri"}, set(), "journal entry artifact")
    for key in ("kind", "schema", "record_id", "authorized_uri"):
        _text(artifact[key], f"journal entry artifact.{key}")
    _hash(artifact["hash"], "journal entry artifact hash")
    classification = _fields(entry["classification"], {"outcome", "evidence_status"}, set(), "journal entry classification")
    for key in classification:
        _text(classification[key], f"journal entry classification.{key}")
    if entry["access"] not in _ACCESS_TIERS:
        raise HounddClientError("houndd journal entry access is invalid")
    _text(entry["policy_id"], "journal entry policy ID")
    dedupe = _fields(entry["dedupe"], {"object_key", "content_sha256"}, set(), "journal entry dedupe")
    _text(dedupe["object_key"], "journal entry dedupe object key")
    _hash(dedupe["content_sha256"], "journal entry dedupe content hash")
    lineage = _fields(entry["lineage"], {"relation", "record_id", "lead_id"}, set(), "journal entry lineage")
    for key in lineage:
        _text(lineage[key], f"journal entry lineage.{key}")
    source = _fields(entry["source"], {"provider", "native_id", "canonical_url"}, set(), "journal entry source")
    for key in source:
        _text(source[key], f"journal entry source.{key}")
    _entry_usage(entry["usage"])
    unsigned = {key: item for key, item in entry.items() if key != "entry_id"}
    if hashlib.sha256(canonical_bytes(unsigned)).hexdigest() != entry["entry_id"]:
        raise HounddClientError("houndd journal entry ID does not match its canonical envelope")
    return entry


def _journal_result_ids(result: object) -> tuple[list[str], list[str]]:
    """Light entry_id/artifact.record_id extraction for the ids-binding check.

    Deliberately shallow -- the full per-field decode lives in
    ``_journal_entry`` and only runs for a 200 that already passed this and
    every other closed-shape check.
    """

    if type(result) is not list:
        raise HounddClientError("houndd journal response result is invalid")
    entry_ids: list[str] = []
    record_ids: list[str] = []
    for item in result:
        if type(item) is not dict:
            raise HounddClientError("houndd journal entry is invalid")
        entry_ids.append(_text(item.get("entry_id"), "journal entry ID"))
        artifact = item.get("artifact")
        if type(artifact) is not dict:
            raise HounddClientError("houndd journal entry artifact is invalid")
        record_ids.append(_text(artifact.get("record_id"), "journal entry record ID"))
    return entry_ids, record_ids


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _canonical_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        message = "has duplicate JSON keys" if str(error) == "duplicate JSON key" else "is not valid JSON"
        raise HounddClientError(f"houndd {label} {message}") from error
    try:
        if type(value) is not dict or canonical_bytes(value) != raw:
            raise HounddClientError(f"houndd {label} is not canonical")
    except (TypeError, UnicodeError, ValueError, OverflowError, RecursionError) as error:
        raise HounddClientError(f"houndd {label} is not canonical") from error
    return value


def _failure(body: dict[str, Any]) -> str:
    error = body.get("error")
    if isinstance(error, dict) and isinstance(error.get("message"), str):
        return error["message"]
    outcome = body.get("outcome")
    return outcome if isinstance(outcome, str) else "unknown"


def _decode(value: object, *, label: str) -> bytes:
    if type(value) is not str:
        raise HounddClientError(f"houndd {label} is missing")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as error:
        raise HounddClientError(f"houndd {label} is not valid base64") from error
    if base64.b64encode(decoded).decode("ascii") != value:
        raise HounddClientError(f"houndd {label} is not canonical base64")
    return decoded


def _safe_socket_path(value: object) -> Path:
    try:
        raw = os.fspath(value)
    except TypeError as error:
        raise HounddClientError("houndd socket path is invalid") from error
    if type(raw) is bytes:
        try:
            raw = os.fsdecode(raw)
        except UnicodeError as error:
            raise HounddClientError("houndd socket path is invalid") from error
    if type(raw) is not str or not raw or "\x00" in raw:
        raise HounddClientError("houndd socket path is invalid")
    path = Path(raw)
    if (
        not path.is_absolute()
        or raw.startswith("//")
        or path.name in {"", ".", ".."}
        or ".." in path.parts
        or os.path.normpath(raw) != raw
        or len(os.fsencode(raw)) > MAX_SOCKET_PATH_BYTES
    ):
        raise HounddClientError("houndd socket path is unsafe")
    return path


def _validate_commit_response(response: dict[str, Any], request: dict[str, Any]) -> None:
    body = _fields(response["body"], {"schema_version", "request_id", "ok", "outcome", "record_ids", "entry_ids", "usage"}, {"error"}, "commit response")
    if body["schema_version"] != COMMIT_RESPONSE_SCHEMA:
        raise HounddClientError("houndd commit response schema is invalid")
    if body["request_id"] != request["body"]["request_id"]:
        raise HounddClientError("houndd response does not answer this request")
    if type(body["ok"]) is not bool or type(body["outcome"]) is not str:
        raise HounddClientError("houndd commit response status is invalid")
    outcome = body["outcome"]
    if outcome not in {"completed", "failed", "partial", "degraded", "refused", "interrupted", "invalid", "unavailable"} or body["ok"] != (outcome == "completed"):
        raise HounddClientError("houndd commit response status is invalid")
    record_ids = _ids(body["record_ids"], "commit record IDs")
    entry_ids = _ids(body["entry_ids"], "commit entry IDs")
    _usage(body["usage"])
    operation = request["body"]["operation"]["name"]
    if outcome == "completed":
        expected_record_count = 2 if operation == "import.record" else 1
        if (
            response["status"] != 200
            or "error" in body
            or len(record_ids) != expected_record_count
            or len(entry_ids) != 1
        ):
            raise HounddClientError("houndd completed commit response is invalid")
        if operation == "import.record" and record_ids[0] != request["body"]["operation"]["payload"].get("record_id"):
            raise HounddClientError("houndd import response does not bind its record ID")
    elif outcome in _DURABLE_ADAPTER_OUTCOMES:
        if (
            operation not in {"ingest.search", "ingest.url"}
            or response["status"] != 200
            or "error" in body
            or len(record_ids) != 1
            or len(entry_ids) != 1
        ):
            raise HounddClientError("houndd durable commit response is invalid")
    elif outcome == "invalid":
        if response["status"] == 400:
            if record_ids or entry_ids or "error" not in body:
                raise HounddClientError("houndd invalid commit response is invalid")
            _safe_error(body["error"], _COMMIT_ERRORS, "invalid commit error")
        elif response["status"] == 404:
            if record_ids or entry_ids or "error" in body:
                raise HounddClientError("houndd invalid commit response is invalid")
        else:
            raise HounddClientError("houndd invalid commit response is invalid")
    else:
        if response["status"] != 503 or record_ids or entry_ids or "error" not in body:
            raise HounddClientError("houndd unavailable commit response is invalid")
        _safe_error(body["error"], {"unavailable": _COMMIT_ERRORS["unavailable"]}, "unavailable commit error")


def _validate_journal_response(
    response: dict[str, Any],
    body: dict[str, Any],
    record_ids: list[str],
    entry_ids: list[str],
) -> None:
    if response["status"] == 200:
        if (
            body["ok"] is not True
            or body["outcome"] != "completed"
            or "result" not in body
            or "error" in body
            or "projection" in body
            or set(body) - {"schema_version", "request_id", "ok", "outcome", "record_ids", "entry_ids", "usage", "result", "cursor"}
        ):
            raise HounddClientError("houndd journal response is invalid")
        derived_entry_ids, derived_record_ids = _journal_result_ids(body["result"])
        if entry_ids != derived_entry_ids or record_ids != derived_record_ids:
            raise HounddClientError("houndd journal response ids do not bind its result")
        if "cursor" in body:
            _text(body["cursor"], "journal cursor")
        return
    expected = {400: "invalid", 404: "not_found", 503: "unavailable"}
    if (
        response["status"] not in expected
        or body["ok"] is not False
        or body["outcome"] != expected[response["status"]]
        or record_ids
        or entry_ids
        or set(body) - {"schema_version", "request_id", "ok", "outcome", "record_ids", "entry_ids", "usage", "error"}
    ):
        raise HounddClientError("houndd journal response is invalid")
    allowed = _JOURNAL_ERRORS.get(response["status"])
    if allowed is not None:
        if "error" not in body:
            raise HounddClientError("houndd journal response is invalid")
        _safe_error(body["error"], allowed, "journal error")
    elif "error" in body:
        raise HounddClientError("houndd journal response is invalid")


def _validate_read_response(response: dict[str, Any], request: dict[str, Any]) -> None:
    body = _fields(response["body"], {"schema_version", "request_id", "ok", "outcome", "record_ids", "entry_ids", "usage"}, {"result", "cursor", "projection", "error"}, "read response")
    if body["schema_version"] != READ_RESPONSE_SCHEMA:
        raise HounddClientError("houndd read response schema is invalid")
    if body["request_id"] != request["body"]["request_id"]:
        raise HounddClientError("houndd response does not answer this request")
    if type(body["ok"]) is not bool or type(body["outcome"]) is not str:
        raise HounddClientError("houndd read response status is invalid")
    record_ids = _ids(body["record_ids"], "read record IDs")
    entry_ids = _ids(body["entry_ids"], "read entry IDs")
    usage = _usage(body["usage"])
    if any(type(value) is not int or value != 0 for value in usage.values()):
        raise HounddClientError("houndd read response usage is invalid")
    path = request["path"]
    if path == "/v1/ready":
        if set(body) - {"schema_version", "request_id", "ok", "outcome", "record_ids", "entry_ids", "usage", "error"}:
            raise HounddClientError("houndd ready response is invalid")
        if response["status"] == 200 and body["ok"] is True and body["outcome"] == "completed" and not record_ids and not entry_ids and "error" not in body:
            return
        if response["status"] == 503 and body["ok"] is False and body["outcome"] == "unavailable" and not record_ids and not entry_ids and "error" in body:
            _safe_error(body["error"], {"service_unavailable": (True, "service is not ready")}, "ready error")
            return
        raise HounddClientError("houndd ready response is invalid")
    if path == "/v1/journal":
        _validate_journal_response(response, body, record_ids, entry_ids)
        return
    record_id = request["body"]["operation"]["payload"]["record_id"]
    if response["status"] == 200:
        if body["ok"] is not True or body["outcome"] != "completed" or record_ids != [record_id] or entry_ids or "error" in body or set(body) - {"schema_version", "request_id", "ok", "outcome", "record_ids", "entry_ids", "usage", "result"}:
            raise HounddClientError("houndd record response is invalid")
        result = body.get("result")
        if type(result) is not list or len(result) != 1 or type(result[0]) is not dict:
            raise HounddClientError("houndd record response is invalid")
        return
    expected = {400: "invalid", 404: "not_found", 503: "unavailable"}
    if response["status"] not in expected or body["ok"] is not False or body["outcome"] != expected[response["status"]] or record_ids or entry_ids or set(body) - {"schema_version", "request_id", "ok", "outcome", "record_ids", "entry_ids", "usage", "error"}:
        raise HounddClientError("houndd record response is invalid")
    if response["status"] == 400:
        if "error" not in body:
            raise HounddClientError("houndd record response is invalid")
        _safe_error(body["error"], {key: _RECORD_ERRORS[key] for key in ("content_too_large", "invalid_request")}, "record error")
    elif response["status"] == 503:
        if "error" not in body:
            raise HounddClientError("houndd record response is invalid")
        _safe_error(body["error"], {"service_unavailable": _RECORD_ERRORS["service_unavailable"]}, "record error")
    elif "error" in body:
        raise HounddClientError("houndd record response is invalid")


def _validate_response(response: dict[str, Any], request: dict[str, Any]) -> None:
    if set(response) != {"wire_version", "status", "body"}:
        raise HounddClientError("houndd response has an invalid shape")
    if response["wire_version"] != WIRE_VERSION or type(response["status"]) is not int or response["status"] not in {200, 400, 404, 409, 503}:
        raise HounddClientError("houndd response does not answer this request")
    if request["method"] == "POST":
        _validate_commit_response(response, request)
    else:
        _validate_read_response(response, request)


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
        self.socket_path = _safe_socket_path(socket_path if socket_path is not None else default_socket_path())
        self.owner_id = _text(owner_id, "owner ID")
        self.policy_id = _text(policy_id, "policy ID")
        if type(requested_access) is not str or requested_access not in {"public", "workspace", "restricted"}:
            raise HounddClientError("houndd requested access is invalid")
        if type(commit_timeout) is not int or commit_timeout <= 0 or type(read_timeout) is not int or read_timeout <= 0:
            raise HounddClientError("houndd timeout is invalid")
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

        if (
            type(path) is not str
            or type(capability) is not str
            or _COMMIT_PATHS.get(capability) != path
            or type(payload) is not dict
            or type(idempotency_key) is not str
        ):
            raise HounddClientError("houndd commit request is invalid")
        _text(idempotency_key, "idempotency key")
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
        record_ids = result["record_ids"]
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

        _text(record_id, "record ID")
        if type(include_content) is not bool:
            raise HounddClientError("houndd include content is invalid")
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
        result = body["result"]
        row = result[0]
        base_fields = {"schema", "record_id", "body_base64", "byte_length"}
        content_fields = base_fields | {"content_base64", "content_sha256", "content_byte_length"}
        if type(row) is not dict or frozenset(row) not in {frozenset(base_fields), frozenset(content_fields)}:
            raise HounddClientError(f"{label} row is invalid")
        if _text(row["schema"], "record schema") == "" or _text(row["record_id"], "record ID") != record_id:
            raise HounddClientError(f"{label} row is invalid")
        body_bytes = _decode(row["body_base64"], label="record body")
        if type(row["byte_length"]) is not int or row["byte_length"] != len(body_bytes):
            raise HounddClientError(f"{label} row byte length is invalid")
        try:
            record = _canonical_object(body_bytes, "record body")
        except HounddClientError as error:
            if "not canonical" in str(error):
                raise HounddClientError(f"{label} body is not canonical") from error
            raise HounddClientError(f"{label} body is not valid JSON") from error
        if not include_content:
            if set(row) != base_fields:
                raise HounddClientError(f"{label} returned unrequested content")
            return record, b""
        if set(row) == base_fields:
            return record, b""
        content = _decode(row["content_base64"], label="record content")
        if (
            type(row["content_byte_length"]) is not int
            or row["content_byte_length"] != len(content)
            or type(row["content_sha256"]) is not str
            or hashlib.sha256(content).hexdigest() != row["content_sha256"]
        ):
            raise HounddClientError(f"{label} content does not match its declared digest")
        return record, content

    def journal_query(
        self,
        *,
        query_filter: dict[str, Any] | None = None,
        cursor: str | None = None,
        limit: int = 50,
        order: str = "ascending",
        run_id: str,
        request_id: str,
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Read one page of journal entries. Returns ``(entries, next_cursor)``.

        ``order`` walks the journal oldest-first (``"ascending"``, the default)
        or newest-first (``"descending"``); either way the chain pins to the
        high-watermark the first page saw, so entries appended mid-chain are
        never spliced in. ``next_cursor`` is ``None`` once the page has drained
        everything visible at that high-watermark; the caller resnapshots with
        ``cursor=None`` to pick up a fresh watermark and continue. A cursor
        belongs to the order that issued it and cannot be replayed under the
        other one. Raises ``HounddJournalCursorRejectedError`` when a supplied
        ``cursor`` can no longer be recovered, and
        ``HounddJournalFilterUnavailableError`` when ``query_filter`` selects
        outside this caller's authorized scope.
        """

        if query_filter is None:
            query_filter = {}
        if type(query_filter) is not dict:
            raise HounddClientError("houndd journal filter is invalid")
        if type(limit) is not int or not 1 <= limit <= 100:
            raise HounddClientError("houndd journal limit is invalid")
        if type(order) is not str or order not in {"ascending", "descending"}:
            raise HounddClientError("houndd journal order is invalid")
        payload: dict[str, Any] = {"filter": query_filter, "limit": limit}
        if order != "ascending":
            payload["order"] = order
        if cursor is not None:
            payload["cursor"] = _text(cursor, "journal cursor")
        request = {
            "wire_version": WIRE_VERSION,
            "method": "GET",
            "path": "/v1/journal",
            "body": self._body(
                schema_version=READ_REQUEST_SCHEMA,
                request_id=request_id,
                capability="journal.query",
                run_id=run_id,
                payload=payload,
            ),
        }
        response = self._exchange(request, timeout=self.read_timeout)
        body = response["body"]
        if response["status"] == 200:
            entries = [_journal_entry(item) for item in body["result"]]
            return entries, body.get("cursor")
        error = body.get("error")
        error_code = error.get("code") if type(error) is dict else None
        if response["status"] == 400 and error_code == "filter_not_available":
            raise HounddJournalFilterUnavailableError(f"journal.query filter is not available: {_failure(body)}")
        if response["status"] == 400 and cursor is not None:
            raise HounddJournalCursorRejectedError(f"journal.query rejected the persisted cursor: {_failure(body)}")
        raise HounddClientError(f"journal.query failed: {_failure(body)}")

    def _body(
        self,
        *,
        schema_version: str,
        request_id: str,
        capability: str,
        run_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        if type(payload) is not dict:
            raise HounddClientError("houndd request payload is invalid")
        return {
            "schema_version": _text(schema_version, "request schema"),
            "request_id": _text(request_id, "request ID"),
            "producer": {
                "owner_id": self.owner_id,
                "capability": _text(capability, "capability"),
                "run_id": _text(run_id, "run ID"),
            },
            "requested_access": self.requested_access,
            "policy_id": self.policy_id,
            "operation": {"name": capability, "payload": payload},
        }

    def _exchange(self, request: dict[str, Any], *, timeout: int) -> dict[str, Any]:
        """Send one canonical request frame and require exactly one response frame."""

        raw = canonical_bytes(request)
        if len(raw) > MAX_FRAME_BYTES:
            raise HounddClientError("houndd request frame is out of bounds")
        request_id = request["body"]["request_id"]
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(timeout)
                connection.connect(os.fspath(self.socket_path))
                connection.sendall(len(raw).to_bytes(4, "big") + raw)
                connection.shutdown(socket.SHUT_WR)
                fragments = [0]
                size = int.from_bytes(_read_exact(connection, 4, fragments), "big")
                if not 0 < size <= MAX_FRAME_BYTES:
                    raise HounddClientError("houndd response frame is out of bounds")
                frame = _read_exact(connection, size, fragments)
                if connection.recv(1):
                    raise HounddClientError("houndd response has trailing bytes")
        except OSError as error:
            raise HounddClientError(f"houndd is unavailable: {error}") from error

        response = _canonical_object(frame, "response")
        if response.get("wire_version") != WIRE_VERSION or type(response.get("body")) is not dict or response["body"].get("request_id") != request_id:
            raise HounddClientError("houndd response does not answer this request")
        _validate_response(response, request)
        return response


__all__ = [
    "COMMIT_REQUEST_SCHEMA",
    "COMMIT_TIMEOUT_SECONDS",
    "HounddClient",
    "HounddClientError",
    "HounddJournalCursorRejectedError",
    "HounddJournalFilterUnavailableError",
    "MAX_FRAME_BYTES",
    "READ_REQUEST_SCHEMA",
    "READ_TIMEOUT_SECONDS",
    "WIRE_VERSION",
    "canonical_bytes",
    "default_socket_path",
]
