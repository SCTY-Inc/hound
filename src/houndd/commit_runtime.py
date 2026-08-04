"""Durable Slice 3C1 file/import and Slice 3C2 adapter commit coordinator.

This is deliberately separate from :mod:`houndd.transactions`.  The older
coordinator owns the legacy generic request envelope; accepting its more
permissive metadata here would make the new commit boundary depend on a second
truth.  The files below are private recovery aids, while records and journal
events remain the durable public truth.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

from ._safety import AnchoredRoot
from .access import PrincipalScope, authorize_event_header
from .adapter_host import (
    ADAPTER_MEDIA_TYPES,
    AdapterAbstained,
    AdapterHost,
    AdapterHostError,
    AdapterUnavailable,
)
from .adapter_validation import (
    AdapterOutcomeError,
    validate_adapter_outcome,
    validate_adapter_record,
)
from .commit import (
    ADAPTER_OPERATIONS,
    SOURCE_OPERATIONS,
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
from .phi import PhiInputError, scan_text
from .projection import Projection
from .store import ImmutableConflict, RecordStore, StoreError


class CommitRuntimeError(RuntimeError):
    """A Slice 3C1 durable commit cannot safely continue."""


class CommitCollision(CommitRuntimeError):
    """One key is already bound to different request semantics."""


class CommitIntegrityError(CommitRuntimeError):
    """Private reservation metadata or its public counterpart is malformed."""


class CommitUnavailable(CommitRuntimeError):
    """A required local durable primitive is unavailable."""


class CommitRefusal(CommitRuntimeError):
    """A declared reference does not resolve inside the effective scope."""


FaultHook = Callable[[str], None]
_RESERVATION_SCHEMA = "houndd.commit-reservation.v1"
_OPEN_SCHEMA = "houndd.commit-open.v1"
_RESERVATION_FIELDS = frozenset({"schema_version", "scope_id", "principal", "capability", "idempotency_key", "request_hash", "canonical_request", "attempt_id", "status", "response"})
_OPEN_FIELDS = frozenset({"schema_version", "scope_id", "attempt_id", "request_hash", "canonical_request", "operation", "source", "record_id", "record_body", "lineage", "access", "policy_id", "producer", "status", "usage", "envelope"})
_LEGACY_OPEN_FIELDS = _OPEN_FIELDS - {"usage"}
QUARANTINE_SCHEMA = "houndd.quarantine-record.v1"
SEARCH_RECORD_SCHEMA = "houndd.search-record.v1"
URL_RECORD_SCHEMA = "houndd.url-record.v1"
_ADAPTER_ARTIFACTS: dict[str, tuple[str, str]] = {"ingest.search": ("search", SEARCH_RECORD_SCHEMA), "ingest.url": ("extract", URL_RECORD_SCHEMA)}
_ADAPTER_PROVIDERS: dict[str, str] = {"ingest.search": "exa", "ingest.url": "firecrawl"}
_ADAPTER_REASONS = frozenset({"none", "provider_failed", "provider_abstained", "adapter_absent", "interrupted"})
_EVIDENCE_STATUS: dict[str, str] = {"completed": "clear", "partial": "partial", "failed": "failure", "degraded": "degraded", "refused": "refused", "interrupted": "interrupted"}
_STAGED_OUTCOMES = frozenset({"completed", "partial"})
_NO_LINEAGE: dict[str, str] = {"relation": "none", "record_id": "none", "lead_id": "none"}
_NO_CONTENT = "none"
_EMPTY_CONTENT: dict[str, Any] = {"sha256": hashlib.sha256(b"").hexdigest(), "byte_length": 0}


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
        if fields is _OPEN_FIELDS and type(value) is dict and set(value) == _LEGACY_OPEN_FIELDS:
            # A pre-3C2 marker: source-operation usage was implicit, and the
            # derived value below is byte-identical to what that slice bound
            # into its finalized response template.
            source = value.get("source")
            if type(source) is dict and type(source.get("byte_length")) is int and source["byte_length"] >= 0:
                value = dict(value)
                value["usage"] = {"requests": 0, "bytes": source["byte_length"], "cost": 0}
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
            stored_attempt_id = _sha(reservation.get("attempt_id"), "reservation attempt_id")
            stored_open_name = f"{stored_attempt_id}.json"
            if not self.anchor.exists("commit3c1", "open", stored_open_name):
                raise CommitIntegrityError("reservation counterpart is missing")
            marker = self._load("commit3c1", "open", stored_open_name, fields=_OPEN_FIELDS, label="commit open marker")
            self._validate_pair_values(reservation_name, reservation, stored_open_name, marker)
            if reservation.get("request_hash") != request_hash or reservation.get("canonical_request") != canonical:
                raise CommitCollision("idempotency key is bound to another request")
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

    @staticmethod
    def _pair_phase(reservation: dict[str, Any], marker: dict[str, Any]) -> str:
        """Accept only the two ordered, crash-recoverable metadata writes."""

        transition = (reservation.get("status"), marker.get("status"))
        phases = {
            ("open", "open"): "open",
            # Marker first makes the outcome/event plan durable before the
            # reservation exposes it as prepared.
            ("open", "prepared"): "preparing",
            ("prepared", "prepared"): "prepared",
            # The event is durable before the marker declares it final.
            ("prepared", "complete"): "finalizing",
            ("complete", "complete"): "complete",
        }
        try:
            return phases[transition]
        except KeyError as error:
            raise CommitIntegrityError("reservation/open status transition is invalid") from error

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
        if binding.operation in SOURCE_OPERATIONS:
            canonical_source = payload.get("source")
            if (
                type(canonical_source) is not dict
                or set(canonical_source) != {"sha256", "byte_length"}
                or _sha(canonical_source.get("sha256"), "canonical source sha256") != canonical_source.get("sha256")
                or type(canonical_source.get("byte_length")) is not int
                or canonical_source["byte_length"] < 0
            ):
                raise CommitIntegrityError("canonical source payload is invalid")
        if binding.operation in ADAPTER_OPERATIONS:
            self._validate_adapter_payload(binding.operation, payload)
        elif binding.operation == "ingest.file":
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
            or marker.get("status") not in {"open", "prepared", "complete"}
            or type(source) is not dict
            or set(source) != {"sha256", "byte_length"}
            or _sha(source.get("sha256"), "open source sha256") != source.get("sha256")
            or (payload.get("source") != source if capability in SOURCE_OPERATIONS else False)
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
        if (
            artifact["record_id"] != record_id
            or artifact["hash"] != record_id
            or envelope["producer"] != producer
            or envelope["policy_id"] != canonical["policy_id"]
            or envelope["access"] != marker["access"]
            or envelope["lineage"] != lineage
        ):
            raise CommitIntegrityError("open marker journal binding disagrees")
        phase = self._pair_phase(reservation, marker)
        expected = self._plan_template(marker)
        stored = self._template(reservation.get("response"))
        # During the first write of open -> prepared recovery the reservation
        # still contains its obsolete completed template.  An adapter operation
        # cannot know its outcome plan before its one provider call, so its
        # open-phase template is likewise a placeholder.  Neither is trusted,
        # returned, or used for publication; recovery replaces it from the
        # marker's already-persisted plan.  Every other state binds both files.
        placeholder = phase == "preparing" or (phase == "open" and capability in ADAPTER_OPERATIONS)
        if not placeholder and stored != self._template(expected):
            raise CommitIntegrityError("reservation response does not bind the outcome plan")

    @staticmethod
    def _validate_adapter_payload(operation: str, payload: object) -> dict[str, Any]:
        """Accept only the exact canonical payload of a source-less operation."""

        if type(payload) is not dict:
            raise CommitIntegrityError("canonical adapter payload is invalid")
        if operation == "ingest.search":
            if (
                set(payload) != {"query", "limit"}
                or type(payload.get("query")) is not str
                or not payload["query"]
                or type(payload.get("limit")) is not int
                or not 1 <= payload["limit"] <= 50
            ):
                raise CommitIntegrityError("canonical ingest.search payload is invalid")
            return payload
        lineage = payload.get("lineage")
        if (
            set(payload) - {"max_pages"} != {"url", "lineage"}
            or type(payload.get("url")) is not str
            or not payload["url"]
            or type(lineage) is not dict
            or ("max_pages" in payload and (type(payload["max_pages"]) is not int or not 2 <= payload["max_pages"] <= 20))
        ):
            raise CommitIntegrityError("canonical ingest.url payload is invalid")
        if lineage.get("kind") == "direct":
            if set(lineage) != {"kind"}:
                raise CommitIntegrityError("canonical ingest.url lineage is invalid")
        elif (
            set(lineage) != {"kind", "record_id", "lead_id"}
            or lineage.get("kind") != "search"
            or _sha(lineage.get("record_id"), "canonical url lineage record_id") != lineage.get("record_id")
            or type(lineage.get("lead_id")) is not str
            or not lineage["lead_id"]
        ):
            raise CommitIntegrityError("canonical ingest.url lineage is invalid")
        return payload

    @staticmethod
    def _plan_requires_content(marker: dict[str, Any]) -> bool:
        """Report whether the plan's outcome names a durable content object."""

        body = marker["record_body"]
        if body.get("schema_version") == QUARANTINE_SCHEMA:
            return False
        if marker["operation"] in ADAPTER_OPERATIONS:
            return body.get("outcome") in _STAGED_OUTCOMES
        return body.get("outcome") == "completed"

    def _adapter_plan(self, marker: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str], dict[str, str], list[str]]:
        """Validate one adapter outcome body and derive its exact event binding."""

        operation = marker["operation"]
        body = marker["record_body"]
        lineage = marker["lineage"]
        content = marker["source"]
        record_id = marker["record_id"]
        payload = self._validate_adapter_payload(operation, marker["canonical_request"]["operation"]["payload"])
        try:
            outcome = validate_adapter_record(
                body,
                record_id=record_id,
                expected_operation=operation,
                expected_attempt_id=marker["attempt_id"],
                expected_request_hash=marker["request_hash"],
                expected_payload=payload,
                expected_lineage=lineage,
                expected_access=marker["access"],
                content_identity=content,
            )
        except AdapterOutcomeError as error:
            raise CommitIntegrityError("adapter outcome plan is malformed") from error
        artifact = {
            "kind": outcome.kind,
            "schema": outcome.schema,
            "record_id": record_id,
            "hash": record_id,
            "authorized_uri": f"houndd://record/{record_id}",
        }
        event_source = {
            "provider": outcome.provider,
            "native_id": record_id,
            "canonical_url": outcome.canonical_url,
        }
        return artifact, event_source, outcome.dedupe, [record_id]

    def _plan_template(self, marker: dict[str, Any]) -> dict[str, Any]:
        """Validate one private outcome/event plan and derive its response."""

        operation = marker.get("operation")
        source = marker.get("source")
        lineage = marker.get("lineage")
        body = marker.get("record_body")
        envelope = marker.get("envelope")
        usage = marker.get("usage")
        record_id = _sha(marker.get("record_id"), "planned record_id")
        if type(source) is not dict or type(lineage) is not dict or type(body) is not dict or type(envelope) is not dict:
            raise CommitIntegrityError("outcome plan is malformed")
        if (
            type(usage) is not dict
            or set(usage) != {"requests", "bytes", "cost"}
            or any(type(usage[key]) is not int or usage[key] < 0 for key in ("requests", "bytes"))
            or type(usage["cost"]) not in {int, float}
            or type(usage["cost"]) is bool
            or usage["cost"] < 0
        ):
            raise CommitIntegrityError("outcome plan usage is malformed")
        source_record = {
            "sha256": source.get("sha256"),
            "byte_length": source.get("byte_length"),
            "media_type": "application/octet-stream",
            "encoding": "identity",
        }
        if type(source_record["byte_length"]) is not int or source_record["byte_length"] < 0:
            raise CommitIntegrityError("outcome plan source is malformed")
        outcome = body.get("outcome")
        if operation in ADAPTER_OPERATIONS:
            artifact, event_source, dedupe, record_ids = self._adapter_plan(marker)
            try:
                checked = validate_adapter_outcome(
                    body,
                    envelope,
                    record_id=record_id,
                    expected_operation=operation,
                    expected_attempt_id=marker["attempt_id"],
                    expected_request_hash=marker["request_hash"],
                    expected_payload=self._validate_adapter_payload(operation, marker["canonical_request"]["operation"]["payload"]),
                    expected_lineage=lineage,
                    expected_access=marker["access"],
                    content_identity=source,
                )
            except AdapterOutcomeError as error:
                raise CommitIntegrityError("adapter outcome plan is malformed") from error
            if (
                artifact["kind"] != checked.kind
                or artifact["schema"] != checked.schema
                or event_source["provider"] != checked.provider
                or event_source["canonical_url"] != checked.canonical_url
                or dedupe != checked.dedupe
            ):
                raise CommitIntegrityError("adapter outcome plan is inconsistent")
            evidence_status = checked.evidence_status
            return self._bind_plan_event(marker, record_id, body, envelope, artifact, event_source, dedupe, record_ids, usage, outcome, evidence_status, lineage)
        if outcome not in {"completed", "interrupted"}:
            raise CommitIntegrityError("outcome plan is unsupported")
        evidence_status = "clear" if outcome == "completed" else "interrupted"
        if usage != {"requests": 0, "bytes": source_record["byte_length"], "cost": 0}:
            raise CommitIntegrityError("outcome plan usage is malformed")
        expected_common = {
            "attempt_id": marker.get("attempt_id"),
            "request_hash": marker.get("request_hash"),
            "operation": operation,
            "outcome": outcome,
            "evidence_status": evidence_status,
            "lineage": lineage,
        }
        if operation == "ingest.file":
            if (
                set(body) != {"schema_version", "attempt_id", "request_hash", "operation", "outcome", "evidence_status", "source", "lineage"}
                or body.get("schema_version") != "houndd.file-record.v1"
                or {key: body.get(key) for key in expected_common} != expected_common
                or body.get("source") != source_record
            ):
                raise CommitIntegrityError("file outcome plan is malformed")
            artifact = {
                "kind": "file",
                "schema": "houndd.file-record.v1",
                "record_id": record_id,
                "hash": record_id,
                "authorized_uri": f"houndd://record/{record_id}",
            }
            event_source = {"provider": "local", "native_id": source_record["sha256"], "canonical_url": "none"}
            dedupe = {"object_key": f"file:{source_record['sha256']}", "content_sha256": source_record["sha256"]}
            record_ids = [record_id]
        elif operation == "import.record":
            legacy = body.get("legacy")
            if (
                set(body) != {"schema_version", "attempt_id", "request_hash", "operation", "outcome", "evidence_status", "legacy", "lineage"}
                or body.get("schema_version") != "houndd.import-outcome.v1"
                or {key: body.get(key) for key in expected_common} != expected_common
                or type(legacy) is not dict
                or set(legacy) != {"record_id", "sha256", "byte_length", "media_type", "encoding"}
                or _legacy_id(legacy.get("record_id"), "planned legacy record_id") != legacy.get("record_id")
                or legacy.get("record_id") != marker["canonical_request"]["operation"]["payload"].get("record_id")
                or legacy != {"record_id": legacy.get("record_id"), **source_record}
            ):
                raise CommitIntegrityError("import outcome plan is malformed")
            artifact = {
                "kind": "import",
                "schema": "houndd.import-outcome.v1",
                "record_id": record_id,
                "hash": record_id,
                "authorized_uri": f"houndd://record/{record_id}",
            }
            event_source = {"provider": "legacy", "native_id": legacy["record_id"], "canonical_url": "none"}
            dedupe = (
                {"object_key": f"legacy:{legacy['record_id']}", "content_sha256": source_record["sha256"]}
                if outcome == "completed"
                else {"object_key": f"import-outcome:{record_id}", "content_sha256": record_id}
            )
            record_ids = [legacy["record_id"], record_id] if outcome == "completed" else [record_id]
        else:
            raise CommitIntegrityError("outcome plan operation is invalid")
        return self._bind_plan_event(marker, record_id, body, envelope, artifact, event_source, dedupe, record_ids, usage, outcome, evidence_status, lineage)

    def _bind_plan_event(
        self,
        marker: dict[str, Any],
        record_id: str,
        body: dict[str, Any],
        envelope: dict[str, Any],
        artifact: dict[str, Any],
        event_source: dict[str, str],
        dedupe: dict[str, str],
        record_ids: list[str],
        usage: dict[str, Any],
        outcome: str,
        evidence_status: str,
        lineage: dict[str, Any],
    ) -> dict[str, Any]:
        """Require the derived plan and its persisted event to be one truth."""

        del marker
        if (
            canonical_hash(body) != record_id
            or envelope.get("artifact") != artifact
            or envelope.get("source") != event_source
            or envelope.get("classification") != {"outcome": outcome, "evidence_status": evidence_status}
            or envelope.get("lineage") != lineage
            or envelope.get("dedupe") != dedupe
            or envelope.get("usage") != usage
        ):
            raise CommitIntegrityError("outcome plan does not bind its public event")
        template = {
            "ok": outcome == "completed",
            "outcome": outcome,
            "record_ids": record_ids,
            "entry_ids": [envelope.get("entry_id")],
            "usage": dict(usage),
        }
        self._template(template)
        return template

    def _source_is_published(self, marker: dict[str, Any]) -> bool:
        """Verify the exact content object a plan names, without I/O guesses."""

        assert self.records is not None
        body = marker["record_body"]
        source = marker["source"]
        if not self._plan_requires_content(marker):
            return False
        if marker["operation"] != "import.record":
            digest = source["sha256"]
            try:
                data = self.records.blobs.get(digest)
            except StoreError as error:
                if self.records.anchor.exists("blobs", digest):
                    raise CommitIntegrityError("completed source blob is unsafe") from error
                return False
            if len(data) != source["byte_length"]:
                raise CommitIntegrityError("completed source blob length changed")
            return True
        legacy = body["legacy"]
        legacy_id = legacy["record_id"]
        with self.records.anchor.operation():
            has_raw = self.records.anchor.exists("records", f"{legacy_id}.bin")
            has_manifest = self.records.anchor.exists("legacy", f"{legacy_id}.json")
        if has_raw != has_manifest:
            raise CommitIntegrityError("completed legacy import state is partial")
        if not has_raw:
            return False
        self._verify_legacy_binding(legacy_id, source["sha256"], source["byte_length"])
        return True

    def _ensure_plan_record(self, marker: dict[str, Any]) -> None:
        """Create or confirm the one immutable outcome record named by the plan."""

        assert self.records is not None
        body = marker["record_body"]
        record_id = marker["record_id"]
        try:
            result = self.records.put_json(body)
        except StoreError as error:
            raise CommitIntegrityError("planned outcome record cannot be persisted") from error
        if result.record_id != record_id or result.content_sha256 != record_id:
            raise CommitIntegrityError("planned outcome record identity disagrees")

    def _verify_published_plan(self, marker: dict[str, Any]) -> None:
        """Require the full public record/source truth before an event append."""

        assert self.records is not None
        self._plan_template(marker)
        record_id = marker["record_id"]
        if not self.records.verify_record(record_id, record_id) or self.records.read_json(record_id) != marker["record_body"]:
            raise CommitIntegrityError("planned outcome record is missing or changed")
        if self._plan_requires_content(marker) and not self._source_is_published(marker):
            raise CommitIntegrityError("planned content object is missing")

    def _prepare_pair(
        self,
        reservation: dict[str, Any],
        reservation_name: str,
        marker: dict[str, Any],
        open_name: str,
    ) -> None:
        """Persist the marker plan first, then bind the prepared response."""

        template = self._plan_template(marker)
        marker["status"] = "prepared"
        self._write("commit3c1", "open", open_name, value=marker)
        reservation["response"] = template
        reservation["status"] = "prepared"
        self._write("commit3c1", "reservations", reservation_name, value=reservation)

    def _resequence_pair(
        self,
        reservation: dict[str, Any],
        reservation_name: str,
        marker: dict[str, Any],
        open_name: str,
    ) -> None:
        """Re-place a still-unappended planned event the journal outgrew."""

        assert self.journal is not None
        envelope = marker["envelope"]
        if self.journal.get(envelope["entry_id"]) is not None or envelope["sequence"] == self.journal.high_watermark() + 1:
            return
        # Only the event's journal position is renewed; its record, artifact,
        # lineage, and dedupe bindings are the same durable plan.  Demoting the
        # reservation first keeps the intermediate one-file states inside the
        # tolerated preparing phase, so a crash here still recovers once.
        reservation["status"] = "open"
        self._write("commit3c1", "reservations", reservation_name, value=reservation)
        marker["envelope"] = make_journal_envelope(
            sequence=self.journal.high_watermark() + 1,
            appended_at=_now(),
            producer=envelope["producer"],
            artifact=envelope["artifact"],
            lineage=envelope["lineage"],
            source=envelope["source"],
            classification=envelope["classification"],
            access=envelope["access"],
            policy_id=envelope["policy_id"],
            dedupe=envelope["dedupe"],
            usage=envelope["usage"],
        )
        self._prepare_pair(reservation, reservation_name, marker, open_name)

    def _append_prepared_event(self, marker: dict[str, Any]) -> None:
        """Append the one persisted event plan, or prove its exact prior append."""

        assert self.journal is not None
        self._verify_published_plan(marker)
        envelope = marker["envelope"]
        entry_id = envelope["entry_id"]
        event = self.journal.get(entry_id)
        if event is None:
            try:
                self.journal.append(envelope)
            except JournalError as error:
                raise CommitIntegrityError("prepared event cannot be recovered") from error
        elif event != envelope:
            raise CommitIntegrityError("journal event disagrees with prepared commit")

    def _refresh_projection(self, envelope: dict[str, Any]) -> None:
        """Add one committed event to the disposable index, and never raise.

        The incremental append costs one record verification and at most one
        staged read, so a commit never pays for the journal behind it.  It
        applies only where it can prove it is extending the exact projection
        of the journal prefix before ``envelope``; every other state — absent,
        lagging, gapped, or foreign-schema index — falls back to the same full
        ``rebuild`` that startup recovery and ``journal.rebuild-index`` use, so
        the two drivers cannot leave a divergent index behind.  Every failure is
        absorbed: the journal is canonical truth, a failed refresh leaves the
        prior projection byte-for-byte usable, and startup recovery repairs
        the drift.  Nothing here may fail a commit whose event is durable.
        """

        try:
            assert self.journal is not None and self.records is not None
            with Projection(self.root, create=True) as projection:
                try:
                    projection.append((envelope,), self.records)
                except Exception:
                    projection.rebuild(self.journal, self.records)
        except Exception:
            return

    def _complete_pair(
        self,
        reservation: dict[str, Any],
        reservation_name: str,
        marker: dict[str, Any],
        open_name: str,
    ) -> None:
        """Finalize only after the exact public outcome/event pair exists."""

        assert self.journal is not None
        self._verify_published_plan(marker)
        if self.journal.get(marker["envelope"]["entry_id"]) != marker["envelope"]:
            raise CommitIntegrityError("planned journal event is missing or changed")
        # Refresh before the pair reads complete so the index never lags an
        # observable commit, and so a crash in this window still leaves the
        # pair in a phase reconcile drives back through here.
        self._refresh_projection(marker["envelope"])
        marker["status"] = "complete"
        self._write("commit3c1", "open", open_name, value=marker)
        reservation["response"] = self._plan_template(marker)
        reservation["status"] = "complete"
        self._write("commit3c1", "reservations", reservation_name, value=reservation)

    def _adapter_plan_into(
        self,
        marker: dict[str, Any],
        *,
        outcome: str,
        reason: str,
        retrieved_at: str,
        content: bytes = b"",
        leads: tuple[Any, ...] = (),
        requests: int = 0,
        cost: float = 0,
        quarantine: bool = False,
    ) -> dict[str, Any]:
        """Replace the marker's plan with one validated adapter outcome plan."""

        assert self.journal is not None
        operation = marker["operation"]
        payload = marker["canonical_request"]["operation"]["payload"]
        staged = outcome in _STAGED_OUTCOMES and not quarantine
        digest = hashlib.sha256(content).hexdigest()
        common = {
            "attempt_id": marker["attempt_id"],
            "request_hash": marker["request_hash"],
            "operation": operation,
            "outcome": outcome,
            "evidence_status": _EVIDENCE_STATUS[outcome],
        }
        if quarantine:
            marker["lineage"] = dict(_NO_LINEAGE)
            body: dict[str, Any] = {
                "schema_version": QUARANTINE_SCHEMA,
                **common,
                "quarantine": {"content_sha256": digest, "byte_length": len(content), "reason": "phi_suspected", "access": marker["access"]},
                "lineage": marker["lineage"],
            }
            marker["source"] = {"sha256": digest, "byte_length": len(content)}
        else:
            body = {
                "schema_version": _ADAPTER_ARTIFACTS[operation][1],
                **common,
                "reason": reason,
                "provider": _ADAPTER_PROVIDERS[operation],
                "retrieved_at": retrieved_at,
                "content_sha256": digest if staged else _NO_CONTENT,
                "byte_length": len(content) if staged else 0,
                "lineage": marker["lineage"],
            }
            if operation == "ingest.search":
                body |= {"query": payload["query"], "limit": payload["limit"], "leads": [dict(lead) for lead in leads]}
            else:
                body["url"] = payload["url"]
            marker["source"] = {"sha256": digest, "byte_length": len(content)} if staged else dict(_EMPTY_CONTENT)
        usage = {"requests": requests, "bytes": len(content) if staged else 0, "cost": cost}
        marker["usage"] = usage
        marker["record_id"] = canonical_hash(body)
        marker["record_body"] = body
        artifact, event_source, dedupe, _ids = self._adapter_plan(marker)
        marker["envelope"] = make_journal_envelope(
            sequence=self.journal.high_watermark() + 1,
            appended_at=_now(),
            producer=marker["producer"],
            artifact=artifact,
            lineage=marker["lineage"],
            source=event_source,
            classification={"outcome": outcome, "evidence_status": _EVIDENCE_STATUS[outcome]},
            access=marker["access"],
            policy_id=marker["policy_id"],
            dedupe=dedupe,
            usage=usage,
        )
        return self._plan_template(marker)

    def _interrupted_plan(self, marker: dict[str, Any]) -> None:
        """Replace an open/no-stage plan with one persisted interrupted plan."""

        assert self.records is not None and self.journal is not None
        self._plan_template(marker)
        if marker["operation"] in ADAPTER_OPERATIONS:
            # Recovery never re-invokes the adapter; an unstaged attempt is
            # interrupted regardless of whether the provider ever answered.
            self._adapter_plan_into(marker, outcome="interrupted", reason="interrupted", retrieved_at=_now())
            self._ensure_plan_record(marker)
            return
        source = marker["source"]
        source_record = {
            "sha256": source["sha256"],
            "byte_length": source["byte_length"],
            "media_type": "application/octet-stream",
            "encoding": "identity",
        }
        operation = marker["operation"]
        if operation == "ingest.file":
            body = {
                "schema_version": "houndd.file-record.v1",
                "attempt_id": marker["attempt_id"],
                "request_hash": marker["request_hash"],
                "operation": operation,
                "outcome": "interrupted",
                "evidence_status": "interrupted",
                "source": source_record,
                "lineage": marker["lineage"],
            }
            artifact_kind = "file"
            schema = "houndd.file-record.v1"
            native_id = source_record["sha256"]
            dedupe = {"object_key": f"file:{source_record['sha256']}", "content_sha256": source_record["sha256"]}
        elif operation == "import.record":
            legacy_id = marker["canonical_request"]["operation"]["payload"]["record_id"]
            if _legacy_id(legacy_id, "open import legacy record_id") != legacy_id:
                raise CommitIntegrityError("open import recovery metadata is malformed")
            body = {
                "schema_version": "houndd.import-outcome.v1",
                "attempt_id": marker["attempt_id"],
                "request_hash": marker["request_hash"],
                "operation": operation,
                "outcome": "interrupted",
                "evidence_status": "interrupted",
                "legacy": {"record_id": legacy_id, **source_record},
                "lineage": marker["lineage"],
            }
            artifact_kind = "import"
            schema = "houndd.import-outcome.v1"
            native_id = legacy_id
            dedupe = None
        else:  # pragma: no cover - fixed bindings are exhaustive
            raise CommitIntegrityError("open commit operation is malformed")
        try:
            result = self.records.put_json(body)
        except StoreError as error:
            raise CommitIntegrityError("interrupted outcome cannot be recorded") from error
        if result.record_id != canonical_hash(body) or result.content_sha256 != result.record_id:
            raise CommitIntegrityError("interrupted outcome identity disagrees")
        if dedupe is None:
            dedupe = {"object_key": f"import-outcome:{result.record_id}", "content_sha256": result.record_id}
        envelope = make_journal_envelope(
            sequence=self.journal.high_watermark() + 1,
            appended_at=_now(),
            producer=marker["producer"],
            artifact={"kind": artifact_kind, "schema": schema, "record_id": result.record_id, "hash": result.record_id, "authorized_uri": f"houndd://record/{result.record_id}"},
            lineage=marker["lineage"],
            source={"provider": "local" if operation == "ingest.file" else "legacy", "native_id": native_id, "canonical_url": "none"},
            classification={"outcome": "interrupted", "evidence_status": "interrupted"},
            access=marker["access"],
            policy_id=marker["policy_id"],
            dedupe=dedupe,
            usage={"requests": 0, "bytes": source_record["byte_length"], "cost": 0},
        )
        marker["record_id"] = result.record_id
        marker["record_body"] = body
        marker["envelope"] = envelope
        self._plan_template(marker)

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
            if self._pair_phase(reservation, marker) == "complete":
                self._completed_binding(reservation, marker)
            pairs.append((scope_id, reservation, attempt_id, marker))
        if len(opens) != len(pairs):
            raise CommitIntegrityError("open marker lacks its reservation")
        self._inventory_validated = True
        return pairs

    @staticmethod
    def _lineage(request: CommitRequest, scope: PrincipalScope | None, journal: Journal) -> dict[str, str]:
        if request.operation in {"ingest.file", "ingest.search"}:
            return dict(_NO_LINEAGE)
        if request.operation == "ingest.url":
            declared = request.payload["lineage"]
            if declared["kind"] == "direct":
                return dict(_NO_LINEAGE)
            parent = declared["record_id"]
            for event in journal.entries():
                # A declared parent is usable only when it is an authorized,
                # completed search event inside the effective scope.
                if scope is None or not authorize_event_header(scope, event):
                    continue
                artifact = event.get("artifact")
                classification = event.get("classification")
                if (
                    type(artifact) is dict
                    and artifact.get("schema") == SEARCH_RECORD_SCHEMA
                    and artifact.get("record_id") == parent
                    and type(classification) is dict
                    and classification.get("outcome") == "completed"
                ):
                    return {"relation": "search", "record_id": parent, "lead_id": declared["lead_id"]}
            raise CommitRefusal("declared search lineage does not resolve in scope")
        legacy_id = request.payload["record_id"]
        assert type(legacy_id) is str
        matches: list[dict[str, str]] = []
        for event in journal.entries():
            # Only an authorized existing event may be selected, so an absent
            # scope authorizes none of them and can reach only no-lineage.
            if scope is None or not authorize_event_header(scope, event):
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
        if self._pair_phase(reservation, marker) != "complete":
            raise CommitIntegrityError("completed commit is not complete")
        response = self._template(reservation.get("response"))
        expected = self._plan_template(marker)
        if response != self._template(expected):
            raise CommitIntegrityError("completed response does not bind durable truth")
        self._verify_published_plan(marker)
        envelope = marker["envelope"]
        if self.journal.get(envelope["entry_id"]) != envelope:
            raise CommitIntegrityError("completed journal event changed")
        return response

    def execute(
        self,
        request: CommitRequest,
        route: RouteBinding,
        *,
        principal: str,
        access: str,
        source: NormalizedSource,
        scanner_clear: bool,
        scope: PrincipalScope | None = None,
        pre_accept: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
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
            record_id = canonical_hash(body)
            appended_at = _now()
            envelope = self._event(request, access=access, record_id=record_id, record_hash=record_id, lineage=lineage, sequence=self.journal.high_watermark() + 1, appended_at=appended_at)
            reservation_name, open_name = self._names(scope_id, attempt_id)
            template = {"ok": True, "outcome": "completed", "record_ids": ([request.payload["record_id"], record_id] if request.operation == "import.record" else [record_id]), "entry_ids": [envelope["entry_id"]], "usage": {"requests": 0, "bytes": source.byte_length, "cost": 0}}
            reservation = {"schema_version": _RESERVATION_SCHEMA, "scope_id": scope_id, "principal": principal, "capability": capability, "idempotency_key": request.idempotency_key, "request_hash": request_hash, "canonical_request": canonical, "attempt_id": attempt_id, "status": "open", "response": template}
            marker = {"schema_version": _OPEN_SCHEMA, "scope_id": scope_id, "attempt_id": attempt_id, "request_hash": request_hash, "canonical_request": canonical, "operation": request.operation, "source": source.identity, "record_id": record_id, "record_body": body, "lineage": lineage, "access": access, "policy_id": request.policy_id, "producer": request.producer.to_dict(), "status": "open", "usage": dict(template["usage"]), "envelope": envelope}
            if pre_accept is not None:
                pre_accept()
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
            self._prepare_pair(reservation, reservation_name, marker, open_name)
            self._fault("after_record")
            self._verify_published_plan(marker)
            try:
                self.journal.append(envelope)
            except JournalError as error:
                raise CommitUnavailable("journal publication failed") from error
            self._fault("after_journal")
            self._complete_pair(reservation, reservation_name, marker, open_name)
            return make_commit_response(request.request_id, ok=True, outcome="completed", record_ids=template["record_ids"], entry_ids=template["entry_ids"], usage=template["usage"])

    def _finalize_adapter(
        self,
        reservation: dict[str, Any],
        reservation_name: str,
        marker: dict[str, Any],
        open_name: str,
        request: CommitRequest,
        **plan: Any,
    ) -> dict[str, Any]:
        """Publish one adapter outcome: plan, content, record, event, response."""

        assert self.records is not None and self.journal is not None
        template = self._adapter_plan_into(marker, **plan)
        # The plan is durable before any content or record exists, so a crash
        # here recovers to interrupted rather than orphaning either object.
        self._write("commit3c1", "open", open_name, value=marker)
        self._fault("after_plan")
        content = plan.get("content", b"")
        try:
            if self._plan_requires_content(marker):
                self.records.blob(content)
                self._fault("after_content")
            self._ensure_plan_record(marker)
        except ImmutableConflict as error:
            raise CommitCollision("immutable record conflicts") from error
        except StoreError as error:
            raise CommitUnavailable("durable record publication failed") from error
        self._prepare_pair(reservation, reservation_name, marker, open_name)
        self._fault("after_record")
        self._verify_published_plan(marker)
        try:
            self.journal.append(marker["envelope"])
        except JournalError as error:
            raise CommitUnavailable("journal publication failed") from error
        self._fault("after_journal")
        self._complete_pair(reservation, reservation_name, marker, open_name)
        return make_commit_response(request.request_id, ok=template["ok"], outcome=template["outcome"], record_ids=template["record_ids"], entry_ids=template["entry_ids"], usage=template["usage"])

    def execute_adapter(
        self,
        request: CommitRequest,
        route: RouteBinding,
        *,
        principal: str,
        access: str,
        adapter_host: AdapterHost,
        scope: PrincipalScope | None = None,
        pre_accept: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        """Run exactly one allowlisted adapter and publish one durable outcome."""

        if type(access) is not str or access not in {"public", "workspace", "restricted"}:
            raise CommitRuntimeError("effective output access is invalid")
        if request.operation not in ADAPTER_OPERATIONS or request.source is not None:
            raise CommitRuntimeError("request is not an adapter operation")
        with self._lock():
            existing = self._read_pair(request, route, principal)
            if existing is not None:
                reservation, marker = existing
                if reservation["status"] != "complete":
                    raise CommitIntegrityError("incomplete commit requires recovery")
                template = self._completed_binding(reservation, marker)
                return make_commit_response(request.request_id, ok=template["ok"], outcome=template["outcome"], record_ids=template["record_ids"], entry_ids=template["entry_ids"], usage=template["usage"])
            assert self.anchor is not None and self.records is not None and self.journal is not None
            scope_id, attempt_id, request_hash, capability, canonical = self._pair(request, route, principal)
            lineage = self._lineage(request, scope, self.journal)
            reservation_name, open_name = self._names(scope_id, attempt_id)
            marker = {"schema_version": _OPEN_SCHEMA, "scope_id": scope_id, "attempt_id": attempt_id, "request_hash": request_hash, "canonical_request": canonical, "operation": request.operation, "source": dict(_EMPTY_CONTENT), "record_id": "", "record_body": {}, "lineage": lineage, "access": access, "policy_id": request.policy_id, "producer": request.producer.to_dict(), "status": "open", "usage": {"requests": 0, "bytes": 0, "cost": 0}, "envelope": {}}
            template = self._adapter_plan_into(marker, outcome="interrupted", reason="interrupted", retrieved_at=_now())
            reservation = {"schema_version": _RESERVATION_SCHEMA, "scope_id": scope_id, "principal": principal, "capability": capability, "idempotency_key": request.idempotency_key, "request_hash": request_hash, "canonical_request": canonical, "attempt_id": attempt_id, "status": "open", "response": template}
            if pre_accept is not None:
                pre_accept()
            self._write("commit3c1", "reservations", reservation_name, value=reservation)
            self._fault("after_reservation")
            self._write("commit3c1", "open", open_name, value=marker)
            self._fault("after_open")
            # One adapter call, no retry, no fallback, no caller-selected
            # provider.  Every failure below is a durable outcome, never a 5xx.
            try:
                result = adapter_host.invoke(request.operation, dict(request.payload))
            except AdapterUnavailable as error:
                return self._finalize_adapter(reservation, reservation_name, marker, open_name, request, outcome="degraded", reason="adapter_absent", retrieved_at=_now(), requests=error.requests)
            except AdapterAbstained as error:
                return self._finalize_adapter(reservation, reservation_name, marker, open_name, request, outcome="refused", reason="provider_abstained", retrieved_at=_now(), requests=error.requests)
            except AdapterHostError as error:
                return self._finalize_adapter(reservation, reservation_name, marker, open_name, request, outcome="failed", reason="provider_failed", retrieved_at=_now(), requests=error.requests)
            self._fault("after_adapter")
            try:
                decision = scan_text(result.content, ADAPTER_MEDIA_TYPES[request.operation], request.operation)
            except (PhiInputError, ValueError) as error:
                raise CommitUnavailable("adapter content scanner is unavailable") from error
            if decision == "suspected":
                return self._finalize_adapter(reservation, reservation_name, marker, open_name, request, outcome="refused", reason="provider_abstained", retrieved_at=result.retrieved_at, content=result.content, requests=result.requests, cost=result.cost, quarantine=True)
            if decision != "clear":
                raise CommitUnavailable("adapter content scanner is unavailable")
            return self._finalize_adapter(reservation, reservation_name, marker, open_name, request, outcome=result.outcome, reason="none", retrieved_at=result.retrieved_at, content=result.content, leads=result.leads, requests=result.requests, cost=result.cost)

    def reconcile(self) -> list[dict[str, Any]]:
        """Finish only proved monotonic crash states; reject every other state."""
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
                if marker.get("attempt_id") != attempt_id:
                    raise CommitIntegrityError("reservation/open pair disagrees")
                self._validate_pair_values(name, reservation, open_name, marker)
                phase = self._pair_phase(reservation, marker)
                if phase == "complete":
                    self._completed_binding(reservation, marker)
                    continue
                if phase == "open":
                    # An adapter plan is written only once its outcome is
                    # final, so it publishes as-is unless it names content that
                    # was never staged.  Recovery never re-invokes a provider.
                    if self._source_is_published(marker) or (marker["operation"] in ADAPTER_OPERATIONS and not self._plan_requires_content(marker)):
                        self._ensure_plan_record(marker)
                    else:
                        if self.records.has(marker["record_id"]):
                            raise CommitIntegrityError("open outcome record lacks its completed source")
                        self._interrupted_plan(marker)
                    self._prepare_pair(reservation, name, marker, open_name)
                elif phase == "preparing":
                    # The marker is the durable plan.  Its old reservation
                    # template is intentionally ignored and replaced below.
                    self._verify_published_plan(marker)
                    self._prepare_pair(reservation, name, marker, open_name)
                elif phase == "prepared":
                    self._verify_published_plan(marker)
                elif phase == "finalizing":
                    self._complete_pair(reservation, name, marker, open_name)
                    repaired.append({"attempt_id": attempt_id, "outcome": marker["record_body"]["outcome"]})
                    continue
                else:  # pragma: no cover - _pair_phase is exhaustive
                    raise CommitIntegrityError("reservation status is invalid")
                self._resequence_pair(reservation, name, marker, open_name)
                self._append_prepared_event(marker)
                self._complete_pair(reservation, name, marker, open_name)
                repaired.append({"attempt_id": attempt_id, "outcome": marker["record_body"]["outcome"]})
        return repaired


__all__ = [
    "QUARANTINE_SCHEMA",
    "SEARCH_RECORD_SCHEMA",
    "URL_RECORD_SCHEMA",
    "CommitCollision",
    "CommitIntegrityError",
    "CommitRefusal",
    "CommitRuntime",
    "CommitRuntimeError",
    "CommitUnavailable",
    "ReplayProbe",
]
