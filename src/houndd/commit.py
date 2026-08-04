"""Private Slice 3C1/3C2 commit boundary and SOURCE normalization primitives.

This module deliberately contains models and bounded source I/O only.  It does
not dispatch routes, invoke adapters, or create durable state; callers must
perform those steps after authorization and the applicable PHI gate.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import math
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from hound_research.evidence import EvidenceError, validate_public_url

from .contracts import canonical_bytes, canonical_hash


COMMIT_REQUEST_SCHEMA = "houndd.commit-request.v1"
COMMIT_RESPONSE_SCHEMA = "houndd.commit-response.v1"
MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_WIRE_BODY_BYTES = 1_048_576
SUPPORTED_SOURCE_MEDIA_TYPE = "application/octet-stream"
SUPPORTED_SOURCE_ENCODING = "identity"
SOURCE_OPERATIONS = frozenset({"ingest.file", "ingest.media", "import.record"})
ADAPTER_OPERATIONS = frozenset({"ingest.search", "ingest.url"})
MAX_QUERY_CHARS = 1_024
MAX_LEAD_ID_CHARS = 128


class CommitContractError(ValueError):
    """A value crosses the private commit boundary with an invalid shape."""


class SourceError(CommitContractError):
    """A SOURCE cannot be safely normalized and verified."""


SourceNormalizationError = SourceError
CommitRequestError = CommitContractError
RouteError = CommitContractError


def _dict(value: Any, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise CommitContractError(f"{label} must be an object")
    return value


def _str(value: Any, label: str) -> str:
    if type(value) is not str or not value:
        raise CommitContractError(f"{label} must be a non-empty string")
    return value


def _sha256(value: Any, label: str) -> str:
    value = _str(value, label)
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise CommitContractError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _uint(value: Any, label: str, *, maximum: int | None = None) -> int:
    if type(value) is not int or value < 0 or (maximum is not None and value > maximum):
        suffix = f" at most {maximum}" if maximum is not None else ""
        raise CommitContractError(f"{label} must be an unsigned integer{suffix}")
    return value


def _legacy_record_id(value: Any) -> str:
    """Keep the legacy store's safe filename grammar at the public boundary."""

    value = _str(value, "import.record.record_id")
    if len(value) > 255 or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for char in value):
        raise CommitContractError("import.record.record_id is invalid")
    return value


def _bounded_text(value: Any, label: str, maximum: int) -> str:
    value = _str(value, label)
    if len(value) > maximum or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise CommitContractError(f"{label} is invalid or too long")
    return value


def _bounded_int(value: Any, label: str, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise CommitContractError(f"{label} must be an integer from {minimum} through {maximum}")
    return value


def _public_url(value: Any) -> str:
    try:
        return validate_public_url(value, "ingest.url.url")
    except EvidenceError as error:
        raise CommitContractError("ingest.url url is not a public HTTP URL") from error


def _strict(value: dict[str, Any], required: set[str], label: str, *, optional: set[str] = set()) -> None:
    keys = set(value)
    missing = required - keys
    unknown = keys - required - optional
    if missing or unknown:
        detail: list[str] = []
        if missing:
            detail.append(f"missing {sorted(missing)!r}")
        if unknown:
            detail.append(f"unknown {sorted(unknown)!r}")
        raise CommitContractError(f"{label} has {' and '.join(detail)}")


def _url_lineage(value: Any) -> dict[str, str]:
    lineage = _dict(value, "ingest.url.lineage")
    kind = lineage.get("kind")
    if kind == "direct":
        _strict(lineage, {"kind"}, "ingest.url direct lineage")
        return {"kind": "direct"}
    _strict(lineage, {"kind", "record_id", "lead_id"}, "ingest.url search lineage")
    if type(kind) is not str or kind != "search":
        raise CommitContractError("ingest.url lineage kind must be 'direct' or 'search'")
    return {
        "kind": "search",
        "record_id": _sha256(lineage["record_id"], "ingest.url.lineage.record_id"),
        "lead_id": _bounded_text(lineage["lead_id"], "ingest.url.lineage.lead_id", MAX_LEAD_ID_CHARS),
    }


def _adapter_payload(operation: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize one source-less adapter payload into its canonical identity."""

    if operation == "ingest.search":
        _strict(payload, {"query", "limit"}, "ingest.search payload")
        return {
            "query": _bounded_text(payload["query"], "ingest.search.query", MAX_QUERY_CHARS),
            "limit": _bounded_int(payload["limit"], "ingest.search.limit", minimum=1, maximum=50),
        }
    if operation != "ingest.url":  # pragma: no cover - callers bind the allowlist
        raise CommitContractError("operation is not an adapter operation")
    _strict(payload, {"url", "lineage"}, "ingest.url payload", optional={"max_pages"})
    normalized: dict[str, Any] = {"url": _public_url(payload["url"]), "lineage": _url_lineage(payload["lineage"])}
    if "max_pages" in payload:
        normalized["max_pages"] = _bounded_int(payload["max_pages"], "ingest.url.max_pages", minimum=2, maximum=20)
    return normalized


@dataclass(frozen=True, slots=True)
class RouteBinding:
    method: str
    path: str
    operation: str
    capability: str
    available: bool

    def __post_init__(self) -> None:
        for label, value in (("method", self.method), ("path", self.path), ("operation", self.operation), ("capability", self.capability)):
            if type(value) is not str or not value:
                raise TypeError(f"route.{label} must be an exact non-empty string")
        if type(self.available) is not bool:
            raise TypeError("route.available must be an exact bool")
        if self.operation != self.capability:
            raise ValueError("route operation and capability must bind exactly")


ROUTE_BINDINGS: tuple[RouteBinding, ...] = (
    RouteBinding("POST", "/v1/ingest/search", "ingest.search", "ingest.search", True),
    RouteBinding("POST", "/v1/ingest/url", "ingest.url", "ingest.url", True),
    RouteBinding("POST", "/v1/ingest/file", "ingest.file", "ingest.file", True),
    RouteBinding("POST", "/v1/ingest/media", "ingest.media", "ingest.media", True),
    RouteBinding("POST", "/v1/transcribe", "transcribe", "transcribe", False),
    RouteBinding("POST", "/v1/import-record", "import.record", "import.record", True),
)
AVAILABLE_ROUTE_BINDINGS: tuple[RouteBinding, ...] = tuple(binding for binding in ROUTE_BINDINGS if binding.available)


def _available_binding(route: Any) -> RouteBinding:
    """Accept only one of this module's fixed, available binding objects."""

    if type(route) is not RouteBinding:
        raise CommitContractError("route must be an exact fixed RouteBinding")
    for binding in AVAILABLE_ROUTE_BINDINGS:
        if route is binding:
            return binding
    raise CommitContractError("route is unavailable")


def resolve_route(method: str, path: str, *, require_available: bool = False) -> RouteBinding:
    if type(method) is not str or type(path) is not str:
        raise CommitContractError("method and path must be exact strings")
    for binding in ROUTE_BINDINGS:
        if binding.method == method and binding.path == path:
            if require_available and not binding.available:
                raise CommitContractError("route is unavailable")
            return binding
    raise CommitContractError("route is not bound")


route_binding = resolve_route


@dataclass(frozen=True, slots=True)
class Producer:
    owner_id: str
    capability: str
    run_id: str

    def __post_init__(self) -> None:
        for value in (self.owner_id, self.capability, self.run_id):
            if type(value) is not str or not value:
                raise TypeError("producer fields must be exact non-empty strings")

    @classmethod
    def from_value(cls, value: Any) -> "Producer":
        obj = _dict(value, "producer")
        _strict(obj, {"owner_id", "capability", "run_id"}, "producer")
        return cls(_str(obj["owner_id"], "producer.owner_id"), _str(obj["capability"], "producer.capability"), _str(obj["run_id"], "producer.run_id"))

    def to_dict(self) -> dict[str, str]:
        return {"owner_id": self.owner_id, "capability": self.capability, "run_id": self.run_id}


@dataclass(frozen=True, slots=True)
class SourceDeclaration:
    kind: str
    sha256: str
    byte_length: int
    path: str | None = None
    body_base64: str | None = None

    def __post_init__(self) -> None:
        if type(self.kind) is not str or self.kind not in {"bytes", "path"}:
            raise TypeError("source kind is invalid")
        if type(self.sha256) is not str or len(self.sha256) != 64 or any(char not in "0123456789abcdef" for char in self.sha256):
            raise TypeError("source digest is invalid")
        if type(self.byte_length) is not int or not 0 <= self.byte_length <= MAX_SOURCE_BYTES:
            raise TypeError("source length is invalid")
        if self.kind == "bytes":
            if type(self.body_base64) is not str or self.path is not None:
                raise TypeError("bytes source has an invalid shape")
        elif type(self.path) is not str or self.body_base64 is not None or not self.path.startswith("/") or self.path == "/" or "\x00" in self.path:
            raise TypeError("path source has an invalid shape")

    @classmethod
    def from_value(cls, value: Any) -> "SourceDeclaration":
        obj = _dict(value, "operation.payload.source")
        _strict(obj, {"kind", "sha256", "byte_length"}, "source", optional={"path", "body_base64"})
        kind = obj["kind"]
        if type(kind) is not str or kind not in {"bytes", "path"}:
            raise CommitContractError("source.kind must be 'bytes' or 'path'")
        digest = _sha256(obj["sha256"], "source.sha256")
        length = _uint(obj["byte_length"], "source.byte_length", maximum=MAX_SOURCE_BYTES)
        if kind == "bytes":
            if set(obj) != {"kind", "body_base64", "sha256", "byte_length"} or type(obj["body_base64"]) is not str:
                raise CommitContractError("bytes source has an exact shape")
            return cls(kind, digest, length, body_base64=obj["body_base64"])
        if set(obj) != {"kind", "path", "sha256", "byte_length"} or type(obj["path"]) is not str:
            raise CommitContractError("path source has an exact shape")
        path = obj["path"]
        if not path.startswith("/") or path == "/" or "\x00" in path:
            raise CommitContractError("path source must be an absolute file path")
        return cls(kind, digest, length, path=path)

    @property
    def identity(self) -> dict[str, Any]:
        return {"sha256": self.sha256, "byte_length": self.byte_length}

    @property
    def canonical(self) -> dict[str, Any]:
        return self.identity

    def to_wire(self) -> dict[str, Any]:
        if self.kind == "bytes":
            assert self.body_base64 is not None
            return {"kind": self.kind, "body_base64": self.body_base64, "sha256": self.sha256, "byte_length": self.byte_length}
        assert self.path is not None
        return {"kind": self.kind, "path": self.path, "sha256": self.sha256, "byte_length": self.byte_length}


@dataclass(frozen=True, slots=True)
class NormalizedSource:
    sha256: str
    byte_length: int
    _data: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self.sha256) is not str or type(self.byte_length) is not int or type(self._data) is not bytes:
            raise TypeError("normalized source fields have exact runtime types")
        if not 0 <= self.byte_length <= MAX_SOURCE_BYTES or self.byte_length != len(self._data) or hashlib.sha256(self._data).hexdigest() != self.sha256:
            raise ValueError("normalized source identity does not match bytes")

    @property
    def data(self) -> bytes:
        return self._data

    @property
    def identity(self) -> dict[str, int | str]:
        return {"sha256": self.sha256, "byte_length": self.byte_length}

    @property
    def canonical(self) -> dict[str, int | str]:
        return self.identity


def _decode_inline(source: SourceDeclaration) -> bytes:
    assert source.body_base64 is not None
    try:
        decoded = base64.b64decode(source.body_base64.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as error:
        raise SourceError("inline source encoding is invalid") from error
    if base64.b64encode(decoded).decode("ascii") != source.body_base64:
        raise SourceError("inline source encoding is non-canonical")
    return decoded


@dataclass(frozen=True, slots=True)
class _PathLink:
    parent_fd: int
    child_fd: int
    name: str


@dataclass(frozen=True, slots=True)
class _HeldPath:
    path: str
    parts: tuple[str, ...]
    parents: tuple[int, ...]
    links: tuple[_PathLink, ...]


def _required_open_flag(name: str) -> int:
    value = getattr(os, name, None)
    if type(value) is not int or value == 0:
        raise SourceError("required safe path-open primitive is unavailable")
    return value


def _close_held_path(held: _HeldPath) -> None:
    for descriptor in sorted(set(held.parents), reverse=True):
        try:
            os.close(descriptor)
        except OSError:
            pass


def _open_absolute_nofollow(path: str) -> tuple[int, _HeldPath]:
    parts = path.split("/")[1:]
    if not parts or any(not part or part in {".", ".."} for part in parts):
        raise SourceError("path source spelling is unsafe")
    directory_flags = os.O_RDONLY | _required_open_flag("O_DIRECTORY") | _required_open_flag("O_NOFOLLOW") | _required_open_flag("O_NONBLOCK") | getattr(os, "O_CLOEXEC", 0)
    parent = os.open("/", directory_flags)
    parents = [parent]
    links: list[_PathLink] = []
    try:
        for part in parts[:-1]:
            child = os.open(part, directory_flags, dir_fd=parent)
            if type(child) is not int or child in parents:
                if type(child) is int and child not in parents:
                    os.close(child)
                raise SourceError("safe path-open descriptor binding is invalid")
            links.append(_PathLink(parent, child, part))
            parents.append(child)
            parent = child
        file_flags = os.O_RDONLY | _required_open_flag("O_NOFOLLOW") | _required_open_flag("O_NONBLOCK") | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(parts[-1], file_flags, dir_fd=parent)
        if type(descriptor) is not int or descriptor in parents:
            if type(descriptor) is int and descriptor not in parents:
                os.close(descriptor)
            raise SourceError("safe path-open descriptor binding is invalid")
        return descriptor, _HeldPath(path, tuple(parts), tuple(parents), tuple(links))
    except OSError as error:
        for descriptor in sorted(set(parents), reverse=True):
            os.close(descriptor)
        raise SourceError("path source cannot be opened safely") from error


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _validate_held_path(held: _HeldPath, descriptor: int) -> None:
    """Ensure the lexical ancestry and current leaf still name held FDs."""

    try:
        for link in held.links:
            visible = os.stat(link.name, dir_fd=link.parent_fd, follow_symlinks=False)
            if not stat.S_ISDIR(visible.st_mode) or not _same_file(visible, os.fstat(link.child_fd)):
                raise SourceError("path source ancestry changed")
        leaf = os.stat(held.parts[-1], dir_fd=held.parents[-1], follow_symlinks=False)
        if not _same_file(leaf, os.fstat(descriptor)):
            raise SourceError("path source binding changed")
        rebound_fd, rebound = _open_absolute_nofollow(held.path)
        try:
            if not _same_file(os.fstat(rebound_fd), os.fstat(descriptor)) or len(rebound.links) != len(held.links):
                raise SourceError("path source binding changed")
            if any(not _same_file(os.fstat(now.child_fd), os.fstat(previous.child_fd)) for now, previous in zip(rebound.links, held.links)):
                raise SourceError("path source ancestry changed")
        finally:
            os.close(rebound_fd)
            _close_held_path(rebound)
    except OSError as error:
        raise SourceError("path source binding cannot be validated") from error


def _source_file_signature(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_size


def _validate_source_file(info: os.stat_result) -> None:
    if not stat.S_ISREG(info.st_mode) or (hasattr(os, "getuid") and info.st_uid != os.getuid()) or not info.st_mode & stat.S_IRUSR:
        raise SourceError("path source is not an owner-readable regular file")
    if info.st_size < 0 or info.st_size > MAX_SOURCE_BYTES:
        raise SourceError("path source length is invalid")


def _read_held_file(source: SourceDeclaration) -> bytes:
    assert source.path is not None
    try:
        fd, held = _open_absolute_nofollow(source.path)
    except OSError as error:
        raise SourceError("path source cannot be opened safely") from error
    try:
        owner_pid = os.getpid()
        _validate_held_path(held, fd)
        before = os.fstat(fd)
        _validate_source_file(before)
        if before.st_size != source.byte_length:
            raise SourceError("path source length is invalid")
        chunks: list[bytes] = []
        total = 0
        while total <= before.st_size:
            chunk = os.read(fd, min(1024 * 1024, before.st_size + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        data = b"".join(chunks)
        if os.getpid() != owner_pid:
            raise SourceError("path source descriptor cannot be used after fork")
        after = os.fstat(fd)
        _validate_source_file(after)
        if _source_file_signature(after) != _source_file_signature(before):
            raise SourceError("path source changed during read")
        _validate_held_path(held, fd)
        return data
    except OSError as error:
        raise SourceError("path source cannot be read safely") from error
    finally:
        try:
            os.close(fd)
        finally:
            _close_held_path(held)


def normalize_source(value: Any) -> NormalizedSource:
    """Decode/read one SOURCE, verify its declared identity, and drop transport metadata."""

    declaration = SourceDeclaration.from_value(value)
    if declaration.kind == "bytes":
        data = _decode_inline(declaration)
    else:
        data = _read_held_file(declaration)
    if len(data) > MAX_SOURCE_BYTES or len(data) != declaration.byte_length:
        raise SourceError("source length does not match its declaration")
    digest = hashlib.sha256(data).hexdigest()
    if digest != declaration.sha256:
        raise SourceError("source digest does not match its declaration")
    return NormalizedSource(digest, len(data), data)


validate_source = normalize_source


@dataclass(frozen=True, slots=True)
class CommitRequest:
    request_id: str
    idempotency_key: str
    producer: Producer
    requested_access: str
    policy_id: str
    operation: str
    payload: Mapping[str, Any]
    source: SourceDeclaration | None

    def __post_init__(self) -> None:
        if type(self.request_id) is not str or not self.request_id or type(self.idempotency_key) is not str or not self.idempotency_key:
            raise TypeError("commit request identifiers must be exact non-empty strings")
        if type(self.producer) is not Producer or type(self.requested_access) is not str or self.requested_access not in {"public", "workspace", "restricted"} or type(self.policy_id) is not str or not self.policy_id:
            raise TypeError("commit request fields are invalid")
        if type(self.operation) is not str or self.operation != self.producer.capability or type(self.payload) is not dict:
            raise TypeError("commit request operation fields are invalid")
        payload = self.payload
        if self.operation in ADAPTER_OPERATIONS:
            if self.source is not None or payload != _adapter_payload(self.operation, dict(payload)):
                raise TypeError("adapter operation payload is invalid")
        elif type(self.source) is not SourceDeclaration:
            raise TypeError("commit request operation fields are invalid")
        elif self.operation == "ingest.file":
            if set(payload) != {"source", "media_type"} or payload.get("source") is not self.source or type(payload.get("media_type")) is not str or payload["media_type"] != SUPPORTED_SOURCE_MEDIA_TYPE:
                raise TypeError("ingest.file payload is invalid")
        elif self.operation == "ingest.media":
            if set(payload) != {"source", "media_type"} or payload.get("source") is not self.source or type(payload.get("media_type")) is not str or payload["media_type"] != SUPPORTED_SOURCE_MEDIA_TYPE:
                raise TypeError("ingest.media payload is invalid")
        elif self.operation == "import.record":
            if set(payload) != {"source", "record_id"} or payload.get("source") is not self.source or type(payload.get("record_id")) is not str or not payload["record_id"]:
                raise TypeError("import.record payload is invalid")
        else:
            raise TypeError("commit request operation is unavailable")
        object.__setattr__(self, "payload", MappingProxyType(dict(payload)))

    @classmethod
    def from_value(cls, value: Any, route: RouteBinding) -> "CommitRequest":
        route = _available_binding(route)
        obj = _dict(value, "commit request")
        _strict(obj, {"schema_version", "request_id", "idempotency_key", "producer", "requested_access", "policy_id", "operation"}, "commit request")
        if type(obj["schema_version"]) is not str or obj["schema_version"] != COMMIT_REQUEST_SCHEMA:
            raise CommitContractError("commit request schema_version is invalid")
        request_id = _str(obj["request_id"], "request.request_id")
        key = _str(obj["idempotency_key"], "request.idempotency_key")
        producer = Producer.from_value(obj["producer"])
        if type(obj["requested_access"]) is not str or obj["requested_access"] not in {"public", "workspace", "restricted"}:
            raise CommitContractError("request.requested_access is invalid")
        policy_id = _str(obj["policy_id"], "request.policy_id")
        operation = _dict(obj["operation"], "request.operation")
        _strict(operation, {"name", "payload"}, "request.operation")
        if type(operation["name"]) is not str or operation["name"] != route.operation or producer.capability != route.capability:
            raise CommitContractError("operation and producer capability do not match the bound route")
        payload = _dict(operation["payload"], "request.operation.payload")
        source: SourceDeclaration | None = None
        if route.operation in ADAPTER_OPERATIONS:
            copied = _adapter_payload(route.operation, payload)
        elif route.operation == "ingest.file":
            _strict(payload, {"source", "media_type"}, "ingest.file payload")
            if payload["media_type"] != SUPPORTED_SOURCE_MEDIA_TYPE or type(payload["media_type"]) is not str:
                raise CommitContractError("ingest.file media_type is unsupported")
            source = SourceDeclaration.from_value(payload["source"])
            copied = dict(payload) | {"source": source}
        elif route.operation == "ingest.media":
            _strict(payload, {"source", "media_type"}, "ingest.media payload")
            if payload["media_type"] != SUPPORTED_SOURCE_MEDIA_TYPE or type(payload["media_type"]) is not str:
                raise CommitContractError("ingest.media media_type is unsupported")
            source = SourceDeclaration.from_value(payload["source"])
            copied = dict(payload) | {"source": source}
        elif route.operation == "import.record":
            _strict(payload, {"record_id", "source"}, "import.record payload")
            source = SourceDeclaration.from_value(payload["source"])
            copied = dict(payload) | {"source": source, "record_id": _legacy_record_id(payload["record_id"])}
        else:  # pragma: no cover - the available bindings are exhaustive
            raise CommitContractError("operation is unavailable")
        request = cls(request_id, key, producer, obj["requested_access"], policy_id, route.operation, copied, source)
        if len(canonical_bytes(request.to_wire_dict())) > MAX_WIRE_BODY_BYTES:
            raise CommitContractError("commit request body exceeds the encoded JSON limit")
        return request

    def _payload_wire(self) -> dict[str, Any]:
        if self.source is None:
            return {key: dict(value) if type(value) is dict else value for key, value in self.payload.items()}
        return {**self.payload, "source": self.source.to_wire()}

    def to_wire_dict(self) -> dict[str, Any]:
        return {
            "schema_version": COMMIT_REQUEST_SCHEMA,
            "request_id": self.request_id,
            "idempotency_key": self.idempotency_key,
            "producer": self.producer.to_dict(),
            "requested_access": self.requested_access,
            "policy_id": self.policy_id,
            "operation": {"name": self.operation, "payload": self._payload_wire()},
        }

    to_dict = to_wire_dict

    def canonical_dict(self, route: RouteBinding, normalized_source: NormalizedSource | None = None) -> dict[str, Any]:
        route = _available_binding(route)
        if type(self) is not CommitRequest or self.operation != route.operation or self.producer.capability != route.capability:
            raise CommitContractError("request does not match the fixed route binding")
        if self.source is None:
            if normalized_source is not None:
                raise CommitContractError("an adapter operation has no normalized source")
            payload = self._payload_wire()
        else:
            if normalized_source is None:
                source_identity: dict[str, Any] = {"sha256": self.source.sha256, "byte_length": self.source.byte_length}
            else:
                if type(normalized_source) is not NormalizedSource or normalized_source.identity != self.source.identity:
                    raise CommitContractError("normalized source does not match the request declaration")
                source_identity = normalized_source.identity
            payload = {**self.payload, "source": source_identity}
        return {
            "route": {"method": route.method, "path": route.path, "operation": route.operation, "capability": route.capability},
            "producer": self.producer.to_dict(),
            "requested_access": self.requested_access,
            "policy_id": self.policy_id,
            "operation": {"name": self.operation, "payload": payload},
        }

    canonical_identity = canonical_dict

    def request_hash(self, route: RouteBinding, normalized_source: NormalizedSource | None = None) -> str:
        return canonical_hash(self.canonical_dict(route, normalized_source))


def parse_commit_request(value: Any, route: RouteBinding) -> CommitRequest:
    return CommitRequest.from_value(value, _available_binding(route))


def canonical_commit_request(request: CommitRequest, route: RouteBinding, normalized_source: NormalizedSource | None = None) -> dict[str, Any]:
    if type(request) is not CommitRequest:
        raise CommitContractError("canonical request inputs have invalid runtime types")
    return request.canonical_dict(_available_binding(route), normalized_source)


def canonical_commit_request_hash(request: CommitRequest, route: RouteBinding, normalized_source: NormalizedSource | None = None) -> str:
    return canonical_hash(canonical_commit_request(request, route, normalized_source))


_COMMIT_OUTCOMES = {"completed", "failed", "partial", "degraded", "refused", "interrupted", "invalid", "unavailable"}
_SAFE_ERRORS: dict[str, tuple[bool, str]] = {
    "source_refused": (False, "source refused"),
    "invalid_request": (False, "invalid request"),
    "request_conflict": (False, "request conflict"),
    "unavailable": (True, "service unavailable"),
    "operation_failed": (False, "operation failed"),
}


def _safe_error(value: Any) -> dict[str, Any]:
    error = _dict(value, "response.error")
    _strict(error, {"code", "retryable", "message"}, "response.error")
    code = error["code"]
    if type(code) is not str or code not in _SAFE_ERRORS or type(error["retryable"]) is not bool or type(error["message"]) is not str:
        raise CommitContractError("response.error is not policy-safe")
    retryable, message = _SAFE_ERRORS[code]
    if error["retryable"] != retryable or error["message"] != message:
        raise CommitContractError("response.error is not policy-safe")
    return {"code": code, "retryable": retryable, "message": message}


def validate_commit_response(value: Any) -> dict[str, Any]:
    obj = _dict(value, "commit response")
    _strict(obj, {"schema_version", "request_id", "ok", "outcome", "record_ids", "entry_ids", "usage"}, "commit response", optional={"error"})
    if type(obj["schema_version"]) is not str or obj["schema_version"] != COMMIT_RESPONSE_SCHEMA:
        raise CommitContractError("commit response schema_version is invalid")
    _str(obj["request_id"], "response.request_id")
    if type(obj["ok"]) is not bool or type(obj["outcome"]) is not str or obj["outcome"] not in _COMMIT_OUTCOMES:
        raise CommitContractError("commit response status is invalid")
    if obj["ok"] != (obj["outcome"] == "completed"):
        raise CommitContractError("commit response ok/outcome disagree")
    copied: dict[str, Any] = {
        "schema_version": COMMIT_RESPONSE_SCHEMA,
        "request_id": obj["request_id"],
        "ok": obj["ok"],
        "outcome": obj["outcome"],
    }
    for label in ("record_ids", "entry_ids"):
        values = obj[label]
        if type(values) is not list or any(type(item) is not str or not item for item in values):
            raise CommitContractError(f"response.{label} must be an array of exact strings")
        copied[label] = list(values)
    usage = _dict(obj["usage"], "response.usage")
    _strict(usage, {"requests", "bytes", "cost"}, "response.usage")
    for key, item in usage.items():
        if type(item) not in {int, float} or type(item) is bool or not math.isfinite(item) or item < 0:
            raise CommitContractError(f"response.usage.{key} must be a finite non-negative number")
    copied["usage"] = dict(usage)
    if "error" in obj:
        if obj["outcome"] == "completed":
            raise CommitContractError("completed response must omit error")
        copied["error"] = _safe_error(obj["error"])
    return copied


@dataclass(frozen=True, slots=True)
class CommitResponse:
    request_id: str
    ok: bool
    outcome: str
    record_ids: tuple[str, ...]
    entry_ids: tuple[str, ...]
    usage: Mapping[str, int | float]
    error: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if type(self.record_ids) is not tuple or type(self.entry_ids) is not tuple or type(self.usage) is not dict or (self.error is not None and type(self.error) is not dict):
            raise TypeError("commit response fields have invalid runtime types")
        value: dict[str, Any] = {
            "schema_version": COMMIT_RESPONSE_SCHEMA,
            "request_id": self.request_id,
            "ok": self.ok,
            "outcome": self.outcome,
            "record_ids": list(self.record_ids),
            "entry_ids": list(self.entry_ids),
            "usage": self.usage,
        }
        if self.error is not None:
            value["error"] = self.error
        checked = validate_commit_response(value)
        object.__setattr__(self, "record_ids", tuple(checked["record_ids"]))
        object.__setattr__(self, "entry_ids", tuple(checked["entry_ids"]))
        object.__setattr__(self, "usage", MappingProxyType(dict(checked["usage"])))
        object.__setattr__(self, "error", MappingProxyType(dict(checked["error"])) if "error" in checked else None)

    @classmethod
    def from_value(cls, value: Any) -> "CommitResponse":
        obj = validate_commit_response(value)
        return cls(
            obj["request_id"],
            obj["ok"],
            obj["outcome"],
            tuple(obj["record_ids"]),
            tuple(obj["entry_ids"]),
            dict(obj["usage"]),
            dict(obj["error"]) if "error" in obj else None,
        )

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema_version": COMMIT_RESPONSE_SCHEMA,
            "request_id": self.request_id,
            "ok": self.ok,
            "outcome": self.outcome,
            "record_ids": list(self.record_ids),
            "entry_ids": list(self.entry_ids),
            "usage": dict(self.usage),
        }
        if self.error is not None:
            value["error"] = dict(self.error)
        return validate_commit_response(value)


def make_commit_response(request_id: str, *, ok: bool, outcome: str, record_ids: list[str], entry_ids: list[str], usage: dict[str, int | float], error: dict[str, Any] | None = None) -> dict[str, Any]:
    response: dict[str, Any] = {"schema_version": COMMIT_RESPONSE_SCHEMA, "request_id": request_id, "ok": ok, "outcome": outcome, "record_ids": record_ids, "entry_ids": entry_ids, "usage": usage}
    if error is not None:
        response["error"] = error
    return validate_commit_response(response)


# Explicit aliases make the private boundary easy to discover without exposing
# the older read-response contract in ``contracts.py``.
validate_request = parse_commit_request


__all__ = [
    "ADAPTER_OPERATIONS",
    "AVAILABLE_ROUTE_BINDINGS",
    "COMMIT_REQUEST_SCHEMA",
    "COMMIT_RESPONSE_SCHEMA",
    "MAX_SOURCE_BYTES",
    "MAX_WIRE_BODY_BYTES",
    "SOURCE_OPERATIONS",
    "SUPPORTED_SOURCE_ENCODING",
    "SUPPORTED_SOURCE_MEDIA_TYPE",
    "CommitContractError",
    "CommitRequestError",
    "CommitRequest",
    "CommitResponse",
    "NormalizedSource",
    "Producer",
    "ROUTE_BINDINGS",
    "RouteBinding",
    "RouteError",
    "SourceDeclaration",
    "SourceError",
    "SourceNormalizationError",
    "canonical_commit_request",
    "canonical_commit_request_hash",
    "make_commit_response",
    "normalize_source",
    "parse_commit_request",
    "route_binding",
    "resolve_route",
    "validate_source",
    "validate_commit_response",
]
