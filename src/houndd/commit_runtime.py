"""Durable Slice 3C1 file/import coordinator.

This is deliberately separate from :mod:`houndd.transactions`.  The older
coordinator owns the legacy generic request envelope; accepting its more
permissive metadata here would make the new commit boundary depend on a second
truth.  The files below are private recovery aids, while records and journal
events remain the durable public truth.
"""

from __future__ import annotations

import fcntl
import json
import os
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

from ._safety import AnchoredRoot
from .access import PrincipalScope, authorize_event_header
from .commit import (
    CommitContractError,
    CommitRequest,
    NormalizedSource,
    RouteBinding,
    canonical_commit_request,
    canonical_commit_request_hash,
    make_commit_response,
    resolve_route,
)
from .contracts import canonical_bytes, canonical_hash, make_journal_envelope, validate_journal_envelope
from .journal import Journal, JournalError
from .store import ImmutableConflict, RecordStore, StoreError


class CommitRuntimeError(RuntimeError):
    """A Slice 3C1 durable commit cannot safely continue."""


class CommitCollision(CommitRuntimeError):
    """One key is already bound to different request semantics."""


class CommitIntegrityError(CommitRuntimeError):
    """Private reservation metadata or its public counterpart is malformed."""


class CommitUnavailable(CommitRuntimeError):
    """A required local durable primitive is unavailable."""


FaultHook = Callable[[str], None]
_RESERVATION_SCHEMA = "houndd.commit-reservation.v1"
_OPEN_SCHEMA = "houndd.commit-open.v1"
_RESERVATION_FIELDS = frozenset({"schema_version", "scope_id", "principal", "capability", "idempotency_key", "request_hash", "canonical_request", "attempt_id", "status", "response"})
_OPEN_FIELDS = frozenset({"schema_version", "scope_id", "attempt_id", "request_hash", "canonical_request", "operation", "source", "record_id", "record_body", "lineage", "access", "policy_id", "producer", "status", "envelope"})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _object(value: object, fields: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise CommitIntegrityError(f"{label} is malformed")
    return value


def _sha(value: object, label: str) -> str:
    if type(value) is not str or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise CommitIntegrityError(f"{label} is invalid")
    return value


def _legacy_id(value: object, label: str) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > 255
        or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for char in value)
    ):
        raise CommitIntegrityError(f"{label} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class ReplayProbe:
    """The only result of the source-I/O-free idempotency probe."""

    response_template: dict[str, Any] | None


class CommitRuntime:
    """One strict, crash-recoverable Slice 3C1 commit coordinator."""

    def __init__(self, root: str | os.PathLike[str], *, fault_hook: FaultHook | None = None) -> None:
        self._owner_pid = os.getpid()
        self.anchor: AnchoredRoot | None = None
        self.records: RecordStore | None = None
        self.journal: Journal | None = None
        self.fault_hook = fault_hook
        # Construction validates the complete paired namespace once.  It does
        # not repair incomplete work; hot-path replay then needs only its
        # direct reservation/open lookup.
        self._inventory_validated = False
        try:
            self.anchor = AnchoredRoot(root, error_type=CommitRuntimeError)
            self.root = self.anchor.path
            with self.anchor.operation():
                self.anchor.mkdir("commit3c1")
                self.anchor.mkdir("commit3c1", "reservations")
                self.anchor.mkdir("commit3c1", "open")
                try:
                    lock = self.anchor.open_file("commit3c1", "lock", flags=os.O_RDWR | os.O_CREAT | os.O_EXCL)
                except CommitRuntimeError:
                    lock = self.anchor.open_file("commit3c1", "lock", flags=os.O_RDWR)
                os.close(lock)
            self.records = RecordStore(self.root)
            self.journal = Journal(self.root)
            # Validate the private namespace once at construction.  A request
            # then performs only its direct pair lookup; it never scans all
            # historical reservations on the hot path.
            with self._lock():
                self._validate_inventory()
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        journal, self.journal = getattr(self, "journal", None), None
        if journal is not None:
            journal.close()
        records, self.records = getattr(self, "records", None), None
        if records is not None:
            records.close()
        anchor, self.anchor = getattr(self, "anchor", None), None
        if anchor is not None:
            anchor.close()

    @contextmanager
    def _lock(self) -> Iterator[None]:
        if self._owner_pid != os.getpid():
            raise CommitUnavailable("commit runtime cannot operate after fork")
        if self.anchor is None:
            raise CommitUnavailable("commit runtime is closed")
        with self.anchor.operation():
            descriptor = self.anchor.open_file("commit3c1", "lock", flags=os.O_RDWR)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                yield
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

    @staticmethod
    def _scope_id(principal: str, capability: str, idempotency_key: str) -> str:
        return canonical_hash({"principal": principal, "capability": capability, "idempotency_key": idempotency_key})

    @staticmethod
    def _attempt_id(principal: str, capability: str, idempotency_key: str, request_hash: str) -> str:
        return canonical_hash({"principal": principal, "capability": capability, "idempotency_key": idempotency_key, "request_hash": request_hash})

    @staticmethod
    def _names(scope_id: str, attempt_id: str) -> tuple[str, str]:
        return f"{scope_id}.json", f"{attempt_id}.json"

    @staticmethod
    def _metadata_name(name: object) -> str:
        if type(name) is not str or len(name) != 69 or not name.endswith(".json"):
            raise CommitIntegrityError("commit metadata filename is invalid")
        _sha(name[:-5], "commit metadata filename")
        return name

    def _load(self, *parts: str, fields: frozenset[str], label: str) -> dict[str, Any]:
        assert self.anchor is not None
        try:
            raw = self.anchor.read_bytes(*parts)
            value = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise CommitIntegrityError(f"{label} is unreadable") from error
        try:
            if canonical_bytes(value) != raw:
                raise CommitIntegrityError(f"{label} is non-canonical")
        except ValueError as error:
            raise CommitIntegrityError(f"{label} is non-canonical") from error
        return _object(value, fields, label)

    def _write(self, *parts: str, value: dict[str, Any]) -> None:
        assert self.anchor is not None
        try:
            self.anchor.write_bytes_atomic(*parts, data=canonical_bytes(value))
        except OSError as error:
            raise CommitUnavailable("commit metadata cannot be persisted") from error

    def _pair(self, request: CommitRequest, route: RouteBinding, principal: str) -> tuple[str, str, str, str, dict[str, Any]]:
        if type(request) is not CommitRequest or type(route) is not RouteBinding or type(principal) is not str or not principal:
            raise CommitRuntimeError("commit inputs are invalid")
        canonical = canonical_commit_request(request, route)
        request_hash = canonical_hash(canonical)
        scope_id = self._scope_id(principal, request.producer.capability, request.idempotency_key)
        attempt_id = self._attempt_id(principal, request.producer.capability, request.idempotency_key, request_hash)
        return scope_id, attempt_id, request_hash, request.producer.capability, canonical

    @staticmethod
    def _template(value: object) -> dict[str, Any]:
        if type(value) is not dict or set(value) != {"ok", "outcome", "record_ids", "entry_ids", "usage"}:
            raise CommitIntegrityError("completed response template is malformed")
        try:
            return make_commit_response(
                "replay-request",
                ok=value["ok"], outcome=value["outcome"], record_ids=value["record_ids"], entry_ids=value["entry_ids"], usage=value["usage"],
            ) | {}
        except (CommitContractError, KeyError, TypeError, ValueError) as error:
            raise CommitIntegrityError("completed response template is malformed") from error

    def _read_pair(self, request: CommitRequest, route: RouteBinding, principal: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
        assert self.anchor is not None
        scope_id, attempt_id, request_hash, capability, canonical = self._pair(request, route, principal)
        reservation_name, open_name = self._names(scope_id, attempt_id)
        reservation_exists = self.anchor.exists("commit3c1", "reservations", reservation_name)
        if reservation_exists:
            reservation = self._load("commit3c1", "reservations", reservation_name, fields=_RESERVATION_FIELDS, label="commit reservation")
            if reservation.get("request_hash") != request_hash or reservation.get("canonical_request") != canonical:
                raise CommitCollision("idempotency key is bound to another request")
            if not self.anchor.exists("commit3c1", "open", open_name):
                raise CommitIntegrityError("reservation counterpart is missing")
            marker = self._load("commit3c1", "open", open_name, fields=_OPEN_FIELDS, label="commit open marker")
            self._validate_pair_values(reservation_name, reservation, open_name, marker)
            if reservation.get("scope_id") != scope_id or reservation.get("principal") != principal or reservation.get("capability") != capability or reservation.get("idempotency_key") != request.idempotency_key or reservation.get("attempt_id") != attempt_id:
                raise CommitIntegrityError("reservation identity is invalid")
            return reservation, marker
        if not self._inventory_validated:
            raise CommitIntegrityError("commit inventory was not validated")
        return None

    def probe(self, request: CommitRequest, route: RouteBinding, *, principal: str) -> ReplayProbe:
        """Read only a completed exact reservation, before any source I/O."""
        with self._lock():
            pair = self._read_pair(request, route, principal)
            if pair is None:
                return ReplayProbe(None)
            reservation, marker = pair
            if reservation["status"] != "complete":
                raise CommitIntegrityError("incomplete commit requires recovery")
            response = self._completed_binding(reservation, marker)
            response.pop("schema_version", None)
            response.pop("request_id", None)
            return ReplayProbe(response)

    def _validate_pair_values(self, reservation_name: str, reservation: dict[str, Any], open_name: str, marker: dict[str, Any]) -> None:
        """Validate both metadata members and every shared identity symmetrically."""

        scope_id = _sha(reservation.get("scope_id"), "reservation scope_id")
        attempt_id = _sha(reservation.get("attempt_id"), "reservation attempt_id")
        request_hash = _sha(reservation.get("request_hash"), "reservation request_hash")
        principal = reservation.get("principal")
        capability = reservation.get("capability")
        key = reservation.get("idempotency_key")
        canonical = reservation.get("canonical_request")
        status = reservation.get("status")
        if (
            reservation.get("schema_version") != _RESERVATION_SCHEMA
            or type(principal) is not str
            or not principal
            or type(capability) is not str
            or not capability
            or type(key) is not str
            or not key
            or type(canonical) is not dict
            or status not in {"open", "prepared", "complete"}
            or reservation_name != f"{scope_id}.json"
            or open_name != f"{attempt_id}.json"
            or canonical_hash(canonical) != request_hash
            or self._scope_id(principal, capability, key) != scope_id
            or self._attempt_id(principal, capability, key, request_hash) != attempt_id
        ):
            raise CommitIntegrityError("reservation identity is invalid")
        route = canonical.get("route")
        producer = canonical.get("producer")
        operation = canonical.get("operation")
        if (
            set(canonical) != {"route", "producer", "requested_access", "policy_id", "operation"}
            or type(route) is not dict
            or set(route) != {"method", "path", "operation", "capability"}
            or any(type(route.get(field)) is not str for field in ("method", "path", "operation", "capability"))
            or type(producer) is not dict
            or set(producer) != {"owner_id", "capability", "run_id"}
            or any(type(producer.get(field)) is not str or not producer.get(field) for field in ("owner_id", "capability", "run_id"))
            or producer.get("capability") != capability
            or type(operation) is not dict
            or set(operation) != {"name", "payload"}
            or type(operation.get("name")) is not str
            or type(operation.get("payload")) is not dict
            or type(canonical.get("requested_access")) is not str
            or canonical.get("requested_access") not in {"public", "workspace", "restricted"}
            or type(canonical.get("policy_id")) is not str
            or not canonical.get("policy_id")
        ):
            raise CommitIntegrityError("canonical commit request is invalid")
        try:
            binding = resolve_route(route["method"], route["path"], require_available=True)
        except CommitContractError as error:
            raise CommitIntegrityError("canonical commit route is invalid") from error
        expected_route = {
            "method": binding.method,
            "path": binding.path,
            "operation": binding.operation,
            "capability": binding.capability,
        }
        if (
            route != expected_route
            or binding.operation != capability
            or operation["name"] != binding.operation
            or producer["capability"] != binding.capability
        ):
            raise CommitIntegrityError("canonical commit route is invalid")
        payload = operation["payload"]
        canonical_source = payload.get("source")
        if (
            type(canonical_source) is not dict
            or set(canonical_source) != {"sha256", "byte_length"}
            or _sha(canonical_source.get("sha256"), "canonical source sha256") != canonical_source.get("sha256")
            or type(canonical_source.get("byte_length")) is not int
            or canonical_source["byte_length"] < 0
        ):
            raise CommitIntegrityError("canonical source payload is invalid")
        if binding.operation == "ingest.file":
            if (
                set(payload) != {"source", "media_type"}
                or type(payload.get("media_type")) is not str
                or payload.get("media_type") != "application/octet-stream"
            ):
                raise CommitIntegrityError("canonical ingest.file payload is invalid")
        elif binding.operation == "import.record":
            if set(payload) != {"source", "record_id"}:
                raise CommitIntegrityError("canonical import.record payload is invalid")
            _legacy_id(payload.get("record_id"), "canonical import record_id")
        else:  # pragma: no cover - fixed available bindings are exhaustive
            raise CommitIntegrityError("canonical commit operation is invalid")
        source = marker.get("source")
        lineage = marker.get("lineage")
        body = marker.get("record_body")
        envelope = marker.get("envelope")
        record_id = _sha(marker.get("record_id"), "open record_id")
        if (
            marker.get("schema_version") != _OPEN_SCHEMA
            or marker.get("scope_id") != scope_id
            or marker.get("attempt_id") != attempt_id
            or marker.get("request_hash") != request_hash
            or marker.get("canonical_request") != canonical
            or marker.get("operation") != capability
            or marker.get("producer") != producer
            or marker.get("policy_id") != canonical.get("policy_id")
            or type(marker.get("access")) is not str
            or marker.get("access") not in {"public", "workspace", "restricted"}
            or marker.get("status") != status
            or type(source) is not dict
            or set(source) != {"sha256", "byte_length"}
            or _sha(source.get("sha256"), "open source sha256") != source.get("sha256")
            or payload.get("source") != source
            or type(source.get("byte_length")) is not int
            or source["byte_length"] < 0
            or type(lineage) is not dict
            or set(lineage) != {"relation", "record_id", "lead_id"}
            or any(type(value) is not str for value in lineage.values())
            or type(body) is not dict
            or canonical_hash(body) != record_id
            or body.get("attempt_id") != attempt_id
            or body.get("request_hash") != request_hash
            or body.get("operation") != capability
            or body.get("lineage") != lineage
            or type(envelope) is not dict
        ):
            raise CommitIntegrityError("reservation/open pair disagrees")
        try:
            checked_event = validate_journal_envelope(envelope)
        except ValueError as error:
            raise CommitIntegrityError("open marker journal event is invalid") from error
        if checked_event != envelope:
            raise CommitIntegrityError("open marker journal event changed during validation")
        artifact = envelope["artifact"]
        expected_dedupe = (
            {"object_key": f"import-outcome:{record_id}", "content_sha256": record_id}
            if capability == "import.record" and body.get("outcome") == "interrupted"
            else None
        )
        if (
            artifact["record_id"] != record_id
            or artifact["hash"] != record_id
            or envelope["producer"] != producer
            or envelope["policy_id"] != canonical["policy_id"]
            or envelope["access"] != marker["access"]
            or envelope["lineage"] != lineage
            or (envelope["dedupe"] != expected_dedupe if expected_dedupe is not None else envelope["dedupe"]["content_sha256"] != source["sha256"])
        ):
            raise CommitIntegrityError("open marker journal binding disagrees")
        self._template(reservation.get("response"))

    def _validate_inventory(self) -> list[tuple[str, dict[str, Any], str, dict[str, Any]]]:
        """Validate the private namespace as a strict one-to-one pair set.

        This runs once during construction.  A missing,
        duplicated, malformed, or copy-left counterpart is integrity failure,
        never a reason to infer state from the other directory.
        """
        assert self.anchor is not None
        reservations: dict[str, tuple[str, dict[str, Any]]] = {}
        opens: dict[str, tuple[str, dict[str, Any]]] = {}
        for name in self.anchor.listdir("commit3c1", "reservations"):
            name = self._metadata_name(name)
            reservation = self._load("commit3c1", "reservations", name, fields=_RESERVATION_FIELDS, label="commit reservation")
            scope_id = _sha(reservation.get("scope_id"), "reservation scope_id")
            attempt_id = _sha(reservation.get("attempt_id"), "reservation attempt_id")
            if name != f"{scope_id}.json" or scope_id in reservations:
                raise CommitIntegrityError("reservation filename does not bind its identity")
            if reservation.get("schema_version") != _RESERVATION_SCHEMA or reservation.get("status") not in {"open", "prepared", "complete"}:
                raise CommitIntegrityError("reservation state is invalid")
            reservations[scope_id] = (attempt_id, reservation)
        for name in self.anchor.listdir("commit3c1", "open"):
            name = self._metadata_name(name)
            marker = self._load("commit3c1", "open", name, fields=_OPEN_FIELDS, label="commit open marker")
            attempt_id = _sha(marker.get("attempt_id"), "open attempt_id")
            scope_id = _sha(marker.get("scope_id"), "open scope_id")
            if name != f"{attempt_id}.json" or attempt_id in opens:
                raise CommitIntegrityError("open filename does not bind its identity")
            if marker.get("schema_version") != _OPEN_SCHEMA or marker.get("status") not in {"open", "prepared", "complete"}:
                raise CommitIntegrityError("open state is invalid")
            opens[attempt_id] = (scope_id, marker)
        pairs: list[tuple[str, dict[str, Any], str, dict[str, Any]]] = []
        for scope_id, (attempt_id, reservation) in reservations.items():
            pair = opens.get(attempt_id)
            if pair is None:
                raise CommitIntegrityError("reservation counterpart is missing")
            marker_scope, marker = pair
            self._validate_pair_values(f"{scope_id}.json", reservation, f"{attempt_id}.json", marker)
            if marker_scope != scope_id:
                raise CommitIntegrityError("reservation/open pair disagrees")
            if reservation["status"] == "complete":
                self._completed_binding(reservation, marker)
            pairs.append((scope_id, reservation, attempt_id, marker))
        if len(opens) != len(pairs):
            raise CommitIntegrityError("open marker lacks its reservation")
        self._inventory_validated = True
        return pairs

    @staticmethod
    def _lineage(request: CommitRequest, scope: PrincipalScope | None, journal: Journal) -> dict[str, str]:
        if request.operation == "ingest.file":
            return {"relation": "none", "record_id": "none", "lead_id": "none"}
        legacy_id = request.payload["record_id"]
        assert type(legacy_id) is str
        matches: list[dict[str, str]] = []
        for event in journal.entries():
            if scope is not None and not authorize_event_header(scope, event):
                continue
            source = event.get("source")
            if type(source) is dict and source.get("provider") == "legacy" and source.get("native_id") == legacy_id:
                lineage = event.get("lineage")
                if type(lineage) is not dict or set(lineage) != {"relation", "record_id", "lead_id"} or any(type(item) is not str for item in lineage.values()):
                    raise CommitIntegrityError("authorized legacy lineage is malformed")
                matches.append(dict(lineage))
        if not matches:
            return {"relation": "none", "record_id": legacy_id, "lead_id": "none"}
        if any(item != matches[0] for item in matches[1:]):
            raise CommitIntegrityError("authorized legacy lineage is ambiguous")
        return matches[0]

    @staticmethod
    def _record_body(request: CommitRequest, request_hash: str, attempt_id: str, lineage: dict[str, str], *, outcome: str = "completed") -> dict[str, Any]:
        source = {"sha256": request.source.sha256, "byte_length": request.source.byte_length, "media_type": "application/octet-stream", "encoding": "identity"}
        evidence = "clear" if outcome == "completed" else outcome
        if request.operation == "ingest.file":
            return {"schema_version": "houndd.file-record.v1", "attempt_id": attempt_id, "request_hash": request_hash, "operation": request.operation, "outcome": outcome, "evidence_status": evidence, "source": source, "lineage": lineage}
        return {"schema_version": "houndd.import-outcome.v1", "attempt_id": attempt_id, "request_hash": request_hash, "operation": request.operation, "outcome": outcome, "evidence_status": evidence, "legacy": {"record_id": request.payload["record_id"], **source}, "lineage": lineage}

    @staticmethod
    def _event(request: CommitRequest, *, access: str, record_id: str, record_hash: str, lineage: dict[str, str], sequence: int, appended_at: str) -> dict[str, Any]:
        import_id = request.payload.get("record_id")
        if request.operation == "ingest.file":
            artifact = {"kind": "file", "schema": "houndd.file-record.v1", "record_id": record_id, "hash": record_hash, "authorized_uri": f"houndd://record/{record_id}"}
            source = {"provider": "local", "native_id": request.source.sha256, "canonical_url": "none"}
            object_key = f"file:{request.source.sha256}"
        else:
            assert type(import_id) is str
            artifact = {"kind": "import", "schema": "houndd.import-outcome.v1", "record_id": record_id, "hash": record_hash, "authorized_uri": f"houndd://record/{record_id}"}
            source = {"provider": "legacy", "native_id": import_id, "canonical_url": "none"}
            object_key = f"legacy:{import_id}"
        return make_journal_envelope(sequence=sequence, appended_at=appended_at, producer=request.producer.to_dict(), artifact=artifact, lineage=lineage, source=source, classification={"outcome": "completed", "evidence_status": "clear"}, access=access, policy_id=request.policy_id, dedupe={"object_key": object_key, "content_sha256": request.source.sha256}, usage={"requests": 0, "bytes": request.source.byte_length, "cost": 0})

    def _fault(self, phase: str) -> None:
        if self.fault_hook is not None:
            self.fault_hook(phase)

    def _preflight_import(self, request: CommitRequest, source: NormalizedSource) -> None:
        """Reject a legacy-ID/byte conflict before accepting an attempt."""
        if request.operation != "import.record":
            return
        assert self.records is not None and self.anchor is not None
        legacy_id = request.payload["record_id"]
        if type(legacy_id) is not str:
            raise CommitRuntimeError("legacy import identity is invalid")
        try:
            # ``RecordStore`` keeps the legacy bytes and its manifest as a
            # pair.  A lone member is integrity corruption; an existing pair
            # must match before the reservation/open pair is created.
            with self.records.anchor.operation():
                has_raw = self.records.anchor.exists("records", f"{legacy_id}.bin")
                has_manifest = self.records.anchor.exists("legacy", f"{legacy_id}.json")
            if has_raw != has_manifest:
                raise CommitIntegrityError("legacy import state is partial")
            if not has_raw:
                return
            existing = self.records.read(legacy_id)
            if existing != source.data or not self.records.verify_record(legacy_id, source.sha256):
                raise CommitCollision("legacy record ID is bound to different bytes")
        except CommitRuntimeError:
            raise
        except StoreError as error:
            raise CommitIntegrityError("legacy import preflight failed") from error

    def _verify_legacy_binding(self, record_id: str, digest: str, byte_length: int) -> None:
        """Require the exact legacy manifest even for content-addressed IDs."""

        assert self.records is not None
        record_id = _legacy_id(record_id, "legacy record_id")
        digest = _sha(digest, "legacy sha256")
        if type(byte_length) is not int or byte_length < 0:
            raise CommitIntegrityError("legacy byte_length is invalid")
        try:
            manifest_raw = self.records.anchor.read_bytes("legacy", f"{record_id}.json")
            manifest = json.loads(manifest_raw.decode("utf-8"))
            data = self.records.read(record_id)
        except (OSError, UnicodeError, json.JSONDecodeError, StoreError) as error:
            raise CommitIntegrityError("completed legacy import manifest is missing or unsafe") from error
        if (
            type(manifest) is not dict
            or set(manifest) != {"record_id", "sha256", "byte_length"}
            or type(manifest.get("record_id")) is not str
            or type(manifest.get("sha256")) is not str
            or type(manifest.get("byte_length")) is not int
            or manifest != {"record_id": record_id, "sha256": digest, "byte_length": byte_length}
            or canonical_bytes(manifest) != manifest_raw
            or len(data) != byte_length
            or not self.records.verify_record(record_id, digest)
        ):
            raise CommitIntegrityError("completed legacy import manifest changed")

    def _completed_binding(self, reservation: dict[str, Any], marker: dict[str, Any]) -> dict[str, Any]:
        """Re-derive a replay only from verified durable public truth."""
        assert self.records is not None and self.journal is not None
        if reservation.get("status") != "complete" or marker.get("status") != "complete":
            raise CommitIntegrityError("completed commit is not complete")
        response = self._template(reservation.get("response"))
        record_id = _sha(marker.get("record_id"), "completed record_id")
        body = marker.get("record_body")
        envelope = marker.get("envelope")
        if type(body) is not dict or canonical_hash(body) != record_id or type(envelope) is not dict:
            raise CommitIntegrityError("completed marker identity is malformed")
        if not self.records.verify_record(record_id, record_id) or self.records.read_json(record_id) != body:
            raise CommitIntegrityError("completed outcome record changed")
        entry_id = envelope.get("entry_id")
        if type(entry_id) is not str or self.journal.get(entry_id) != envelope:
            raise CommitIntegrityError("completed journal event changed")
        source = marker.get("source")
        if type(source) is not dict:
            raise CommitIntegrityError("completed event/source binding disagrees")
        operation = marker.get("operation")
        if (
            response["outcome"] != body.get("outcome")
            or envelope.get("classification") != {"outcome": body.get("outcome"), "evidence_status": body.get("evidence_status")}
            or envelope.get("lineage") != body.get("lineage")
        ):
            raise CommitIntegrityError("completed outcome graph disagrees")
        expected_records = [record_id]
        if operation == "import.record":
            legacy = body.get("legacy")
            if (
                type(legacy) is not dict
                or set(legacy) != {"record_id", "sha256", "byte_length", "media_type", "encoding"}
                or type(legacy.get("record_id")) is not str
                or legacy.get("sha256") != source.get("sha256")
                or legacy.get("byte_length") != source.get("byte_length")
            ):
                raise CommitIntegrityError("completed legacy import changed")
            if body.get("outcome") == "completed":
                if envelope.get("dedupe") != {"object_key": f"legacy:{legacy['record_id']}", "content_sha256": source["sha256"]}:
                    raise CommitIntegrityError("completed event/source binding disagrees")
                self._verify_legacy_binding(legacy["record_id"], legacy["sha256"], legacy["byte_length"])
                expected_records = [legacy["record_id"], record_id]
            elif body.get("outcome") == "interrupted":
                # Open/no-stage recovery has only declared attempt metadata.
                # It must never turn that metadata into a raw legacy-object
                # lookup, claim, or dedupe identity.
                if envelope.get("dedupe") != {"object_key": f"import-outcome:{record_id}", "content_sha256": record_id}:
                    raise CommitIntegrityError("interrupted import dedupe binding disagrees")
            else:
                raise CommitIntegrityError("completed import outcome is invalid")
        elif envelope.get("dedupe", {}).get("content_sha256") != source.get("sha256"):
            raise CommitIntegrityError("completed event/source binding disagrees")
        if response["outcome"] not in {"completed", "interrupted"} or response["record_ids"] != expected_records or response["entry_ids"] != [entry_id]:
            raise CommitIntegrityError("completed response does not bind durable truth")
        return response

    def execute(self, request: CommitRequest, route: RouteBinding, *, principal: str, access: str, source: NormalizedSource, scanner_clear: bool, scope: PrincipalScope | None = None) -> dict[str, Any]:
        """Publish exactly one strict outcome record/event after all prechecks."""
        if type(access) is not str or access not in {"public", "workspace", "restricted"}:
            raise CommitRuntimeError("effective output access is invalid")
        if type(source) is not NormalizedSource or source.identity != request.source.identity:
            raise CommitRuntimeError("normalized source does not match request")
        if scanner_clear is not True:
            raise CommitRuntimeError("uncleared source cannot be accepted")
        with self._lock():
            existing = self._read_pair(request, route, principal)
            if existing is not None:
                reservation, marker = existing
                if reservation["status"] == "complete":
                    template = self._completed_binding(reservation, marker)
                    return make_commit_response(request.request_id, ok=template["ok"], outcome=template["outcome"], record_ids=template["record_ids"], entry_ids=template["entry_ids"], usage=template["usage"])
                raise CommitIntegrityError("incomplete commit requires recovery")
            assert self.anchor is not None and self.records is not None and self.journal is not None
            self._preflight_import(request, source)
            scope_id, attempt_id, request_hash, capability, canonical = self._pair(request, route, principal)
            lineage = self._lineage(request, scope, self.journal)
            body = self._record_body(request, request_hash, attempt_id, lineage)
            record_bytes = canonical_bytes(body)
            record_id = canonical_hash(body)
            appended_at = _now()
            envelope = self._event(request, access=access, record_id=record_id, record_hash=record_id, lineage=lineage, sequence=self.journal.high_watermark() + 1, appended_at=appended_at)
            reservation_name, open_name = self._names(scope_id, attempt_id)
            template = {"ok": True, "outcome": "completed", "record_ids": ([request.payload["record_id"], record_id] if request.operation == "import.record" else [record_id]), "entry_ids": [envelope["entry_id"]], "usage": {"requests": 0, "bytes": source.byte_length, "cost": 0}}
            reservation = {"schema_version": _RESERVATION_SCHEMA, "scope_id": scope_id, "principal": principal, "capability": capability, "idempotency_key": request.idempotency_key, "request_hash": request_hash, "canonical_request": canonical, "attempt_id": attempt_id, "status": "open", "response": template}
            marker = {"schema_version": _OPEN_SCHEMA, "scope_id": scope_id, "attempt_id": attempt_id, "request_hash": request_hash, "canonical_request": canonical, "operation": request.operation, "source": source.identity, "record_id": record_id, "record_body": body, "lineage": lineage, "access": access, "policy_id": request.policy_id, "producer": request.producer.to_dict(), "status": "open", "envelope": envelope}
            self._write("commit3c1", "reservations", reservation_name, value=reservation)
            self._fault("after_reservation")
            self._write("commit3c1", "open", open_name, value=marker)
            self._fault("after_open")
            try:
                if request.operation == "ingest.file":
                    self.records.blob(source.data)
                else:
                    self.records.put_bytes(request.payload["record_id"], source.data, expected_sha256=source.sha256)
                result = self.records.put_json(body)
            except ImmutableConflict as error:
                raise CommitCollision("immutable record conflicts") from error
            except StoreError as error:
                raise CommitUnavailable("durable record publication failed") from error
            if result.record_id != record_id or result.content_sha256 != record_id:
                raise CommitIntegrityError("outcome record identity disagrees")
            reservation["status"] = marker["status"] = "prepared"
            self._write("commit3c1", "reservations", reservation_name, value=reservation)
            self._write("commit3c1", "open", open_name, value=marker)
            self._fault("after_record")
            try:
                self.journal.append(envelope)
            except JournalError as error:
                raise CommitUnavailable("journal publication failed") from error
            self._fault("after_journal")
            reservation["status"] = marker["status"] = "complete"
            self._write("commit3c1", "open", open_name, value=marker)
            self._write("commit3c1", "reservations", reservation_name, value=reservation)
            return make_commit_response(request.request_id, ok=True, outcome="completed", record_ids=template["record_ids"], entry_ids=template["entry_ids"], usage=template["usage"])

    def reconcile(self) -> list[dict[str, Any]]:
        """Finish only a proved record/no-event prepared state; otherwise fail closed."""
        assert self.anchor is not None and self.records is not None and self.journal is not None
        repaired: list[dict[str, Any]] = []
        with self._lock():
            for name in self.anchor.listdir("commit3c1", "reservations"):
                if not name.endswith(".json"):
                    raise CommitIntegrityError("unexpected reservation entry")
                reservation = self._load("commit3c1", "reservations", name, fields=_RESERVATION_FIELDS, label="commit reservation")
                attempt_id = _sha(reservation.get("attempt_id"), "attempt_id")
                open_name = f"{attempt_id}.json"
                if not self.anchor.exists("commit3c1", "open", open_name):
                    raise CommitIntegrityError("reservation counterpart is missing")
                marker = self._load("commit3c1", "open", open_name, fields=_OPEN_FIELDS, label="commit open marker")
                if marker.get("status") != reservation.get("status") or marker.get("attempt_id") != attempt_id:
                    raise CommitIntegrityError("reservation/open pair disagrees")
                if reservation["status"] == "complete":
                    continue
                if reservation["status"] == "open":
                    # The pair itself proves acceptance, but no source object or
                    # outcome record was published.  Make the required one
                    # explicit interrupted outcome without rereading a source
                    # or retrying any work.
                    canonical = marker.get("canonical_request")
                    source = marker.get("source")
                    lineage = marker.get("lineage")
                    producer = marker.get("producer")
                    if type(canonical) is not dict or type(source) is not dict or type(lineage) is not dict or type(producer) is not dict:
                        raise CommitIntegrityError("open commit recovery metadata is malformed")
                    operation = marker.get("operation")
                    if operation not in {"ingest.file", "import.record"}:
                        raise CommitIntegrityError("open commit operation is malformed")
                    request_hash = _sha(marker.get("request_hash"), "request_hash")
                    source_record = {"sha256": source.get("sha256"), "byte_length": source.get("byte_length"), "media_type": "application/octet-stream", "encoding": "identity"}
                    if operation == "ingest.file":
                        body = {"schema_version": "houndd.file-record.v1", "attempt_id": attempt_id, "request_hash": request_hash, "operation": operation, "outcome": "interrupted", "evidence_status": "interrupted", "source": source_record, "lineage": lineage}
                        artifact_kind, schema, native_id, object_key, content_sha256 = "file", "houndd.file-record.v1", source.get("sha256"), f"file:{source.get('sha256')}", source_record["sha256"]
                    else:
                        payload = canonical.get("operation", {}).get("payload") if type(canonical.get("operation")) is dict else None
                        legacy_id = payload.get("record_id") if type(payload) is dict else None
                        if type(legacy_id) is not str:
                            raise CommitIntegrityError("open import metadata is malformed")
                        body = {"schema_version": "houndd.import-outcome.v1", "attempt_id": attempt_id, "request_hash": request_hash, "operation": operation, "outcome": "interrupted", "evidence_status": "interrupted", "legacy": {"record_id": legacy_id, **source_record}, "lineage": lineage}
                        artifact_kind, schema, native_id = "import", "houndd.import-outcome.v1", legacy_id
                    try:
                        result = self.records.put_json(body)
                    except StoreError as error:
                        raise CommitIntegrityError("interrupted outcome cannot be recorded") from error
                    if operation == "import.record":
                        object_key = f"import-outcome:{result.record_id}"
                        content_sha256 = result.content_sha256
                    access = marker.get("access")
                    policy_id = marker.get("policy_id")
                    if type(access) is not str or type(policy_id) is not str:
                        raise CommitIntegrityError("open commit access metadata is malformed")
                    envelope = make_journal_envelope(
                        sequence=self.journal.high_watermark() + 1,
                        appended_at=_now(),
                        producer=producer,
                        artifact={"kind": artifact_kind, "schema": schema, "record_id": result.record_id, "hash": result.content_sha256, "authorized_uri": f"houndd://record/{result.record_id}"},
                        lineage=lineage,
                        source={"provider": "local" if operation == "ingest.file" else "legacy", "native_id": native_id, "canonical_url": "none"},
                        classification={"outcome": "interrupted", "evidence_status": "interrupted"},
                        access=access,
                        policy_id=policy_id,
                        dedupe={"object_key": object_key, "content_sha256": content_sha256},
                        usage={"requests": 0, "bytes": source_record["byte_length"], "cost": 0},
                    )
                    try:
                        self.journal.append(envelope)
                    except JournalError as error:
                        raise CommitIntegrityError("interrupted event cannot be recorded") from error
                    reservation["response"] = {"ok": False, "outcome": "interrupted", "record_ids": [result.record_id], "entry_ids": [envelope["entry_id"]], "usage": {"requests": 0, "bytes": source_record["byte_length"], "cost": 0}}
                    marker["record_id"] = result.record_id
                    marker["record_body"] = body
                    marker["envelope"] = envelope
                    reservation["status"] = marker["status"] = "complete"
                    self._write("commit3c1", "open", open_name, value=marker)
                    self._write("commit3c1", "reservations", name, value=reservation)
                    repaired.append({"attempt_id": attempt_id, "outcome": "interrupted"})
                    continue
                if reservation["status"] != "prepared":
                    raise CommitIntegrityError("reservation status is invalid")
                record_id = marker.get("record_id")
                envelope = marker.get("envelope")
                if type(record_id) is not str or type(envelope) is not dict or not self.records.verify_record(record_id, record_id):
                    raise CommitIntegrityError("prepared record is missing or changed")
                event = self.journal.get(envelope.get("entry_id")) if type(envelope.get("entry_id")) is str else None
                if event is None:
                    try:
                        self.journal.append(envelope)
                    except JournalError as error:
                        raise CommitIntegrityError("prepared event cannot be recovered") from error
                elif event != envelope:
                    raise CommitIntegrityError("journal event disagrees with prepared commit")
                reservation["status"] = marker["status"] = "complete"
                self._write("commit3c1", "open", open_name, value=marker)
                self._write("commit3c1", "reservations", name, value=reservation)
                repaired.append({"attempt_id": attempt_id, "outcome": "completed"})
        return repaired


__all__ = ["CommitCollision", "CommitIntegrityError", "CommitRuntime", "CommitRuntimeError", "CommitUnavailable", "ReplayProbe"]
