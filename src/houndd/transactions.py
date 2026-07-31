"""HSP-05: durable attempt staging, atomic publication, and idempotent recovery."""

from __future__ import annotations

import base64
import fcntl
import json
import os
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping

from .contracts import (
    canonical_bytes,
    canonical_hash,
    canonical_request_hash,
    make_journal_envelope,
    make_response,
    validate_journal_envelope,
    validate_request,
    validate_response,
)
from ._safety import AnchoredRoot, check_private_stat
from .journal import FaultHook, Journal, JournalError
from .store import RecordStore, StoreError


class TransactionError(StoreError):
    """A transaction cannot be safely started, committed, or recovered."""


class IdempotencyConflict(TransactionError):
    """An idempotency key was reused for a different canonical request."""


class InjectedCrash(TransactionError):
    """A deterministic fault hook stopped a transaction before acknowledgement."""


FAULT_BEFORE_PROVIDER = "before_provider_call"
FAULT_AFTER_PROVIDER = "after_provider_return_before_publish"
FAULT_AFTER_RECORD = "after_record_publish_before_journal_fsync"
FAULT_AFTER_JOURNAL = "after_journal_fsync_before_response"

_IDEMPOTENCY_REQUIRED = {"scope_id", "principal", "capability", "idempotency_key", "request_hash", "transaction_id", "status"}
_IDEMPOTENCY_OPTIONAL = {"response"}
_STAGE_REQUIRED = {"transaction_id", "scope_id", "principal", "capability", "idempotency_key", "request", "request_hash", "status", "context", "appended_at"}
_STAGE_OPTIONAL = {"prepared", "record_id", "record_hash", "content_sha256", "envelope", "response"}
_META_STATUSES = {"open", "prepared", "published", "complete"}
_COMPLETE_STATUSES = {"complete"}


def _strict_object(value: Any, required: set[str], optional: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TransactionError(f"{label} must be an object")
    unknown = set(value) - required - optional
    missing = required - set(value)
    if missing or unknown:
        parts = []
        if missing:
            parts.append(f"missing {sorted(missing)!r}")
        if unknown:
            parts.append(f"unknown {sorted(unknown)!r}")
        raise TransactionError(f"{label} has {' and '.join(parts)}")
    return value


def _private_directory(path: Path, *, create: bool = True) -> None:
    if path.is_symlink():
        raise TransactionError(f"{path} must not be a symlink")
    existed = path.exists()
    if create:
        path.mkdir(exist_ok=existed)
        if not existed:
            path.chmod(0o700)
    elif not existed:
        raise TransactionError(f"{path} is missing")
    info = path.stat()
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise TransactionError(f"{path} is not owned by the current user")
    if info.st_mode & 0o077:
        raise TransactionError(f"{path} has group/world permissions")


def _private_file(path: Path, *, create: bool = True) -> None:
    if path.is_symlink() or not path.exists():
        if create:
            raise TransactionError(f"{path} is not a safe regular file")
        raise TransactionError(f"{path} is missing")
    if not path.is_file():
        raise TransactionError(f"{path} is not a safe regular file")
    info = path.stat()
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise TransactionError(f"{path} is not owned by the current user")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise TransactionError(f"{path} has group/world permissions")


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    if path.is_symlink():
        raise TransactionError(f"{path} must not be a symlink")
    if path.exists():
        _private_file(path)
    temporary = path.with_name(f".{path.name}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical_bytes(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as error:
        temporary.unlink(missing_ok=True)
        raise TransactionError(f"cannot persist {path}") from error


@dataclass
class Transaction:
    coordinator: "TransactionCoordinator"
    transaction_id: str
    request: dict[str, Any]
    principal: str
    capability: str
    request_hash: str
    scope_id: str
    existing_response: dict[str, Any] | None = None

    def commit(
        self,
        *,
        record: Mapping[str, Any] | None = None,
        outcome: str = "completed",
        evidence_status: str = "evidence",
        blob: bytes | None = None,
        context: Mapping[str, Any] | None = None,
        fault: str | None = None,
    ) -> dict[str, Any]:
        return self.coordinator._commit(
            self,
            record=record,
            outcome=outcome,
            evidence_status=evidence_status,
            blob=blob,
            context=context,
            fault=fault,
        )


class TransactionCoordinator:
    """Coordinate one durable attempt per authenticated scope and key."""

    def __init__(self, root: str | os.PathLike[str], *, create: bool = True) -> None:
        try:
            self.anchor = AnchoredRoot(root, error_type=TransactionError, create=create)
            self.root = self.anchor.path
            self.transactions = self.root / "transactions"
            self.stages = self.transactions / "stages"
            self.idempotency = self.transactions / "idempotency"
            with self.anchor.operation():
                self.anchor.mkdir("transactions", create=create)
                self.anchor.mkdir("transactions", "stages", create=create)
                self.anchor.mkdir("transactions", "idempotency", create=create)
            self.lock_path = self.transactions / "lock"
            with self.anchor.operation():
                try:
                    descriptor = self.anchor.open_file("transactions", "lock", flags=os.O_WRONLY | ((os.O_CREAT | os.O_EXCL) if create else 0))
                except TransactionError:
                    descriptor = self.anchor.open_file("transactions", "lock", flags=os.O_WRONLY)
                try:
                    check_private_stat(os.fstat(descriptor), self.lock_path, directory=False, error_type=TransactionError)
                finally:
                    os.close(descriptor)
                for directory in ("stages", "idempotency"):
                    for name in self.anchor.listdir("transactions", directory):
                        if name.endswith(".json"):
                            check_private_stat(self.anchor.stat("transactions", directory, name), self.root / "transactions" / directory / name, directory=False, error_type=TransactionError)
            self.records = RecordStore(self.root, create=create)
            self.journal = Journal(self.root, create=create)
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        records = getattr(self, "records", None)
        if records is not None:
            records.close()
        journal = getattr(self, "journal", None)
        if journal is not None:
            journal.close()
        anchor = getattr(self, "anchor", None)
        if anchor is not None:
            anchor.close()

    def __enter__(self) -> "TransactionCoordinator":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @contextmanager
    def _lock(self) -> Iterator[None]:
        with self.anchor.operation():
            descriptor = self.anchor.open_file("transactions", "lock", flags=os.O_RDWR)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                yield
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

    @staticmethod
    def _scope_id(principal: str, capability: str, idempotency_key: str) -> str:
        return canonical_hash({"principal": principal, "capability": capability, "idempotency_key": idempotency_key})

    def _stage_path(self, transaction_id: str) -> Path:
        return self.stages / f"{transaction_id}.json"

    def _idempotency_path(self, scope_id: str) -> Path:
        return self.idempotency / f"{scope_id}.json"

    def _load_metadata(self, *parts: str) -> dict[str, Any]:
        try:
            value = json.loads(self.anchor.read_bytes(*parts).decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise TransactionError(f"cannot read transaction metadata {self.root.joinpath(*parts)}") from error
        if not isinstance(value, dict):
            raise TransactionError(f"transaction metadata {self.root.joinpath(*parts)} is not an object")
        return value

    def _write_metadata(self, *parts: str, value: Mapping[str, Any]) -> None:
        try:
            self.anchor.write_bytes_atomic(*parts, data=canonical_bytes(value))
        except OSError as error:
            raise TransactionError(f"cannot persist {self.root.joinpath(*parts)}") from error

    def _validate_reservation(
        self,
        stage: Mapping[str, Any],
        idempotency: Mapping[str, Any],
        *,
        request: Mapping[str, Any],
        principal: str,
        capability: str,
        request_hash: str,
        scope_id: str,
        transaction_id: str,
        require_complete: bool,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        stage = _strict_object(stage, _STAGE_REQUIRED, _STAGE_OPTIONAL, "transaction stage")
        idempotency = _strict_object(idempotency, _IDEMPOTENCY_REQUIRED, _IDEMPOTENCY_OPTIONAL, "idempotency metadata")
        if stage["transaction_id"] != transaction_id or idempotency["transaction_id"] != transaction_id:
            raise TransactionError("transaction identity drifted")
        if stage["scope_id"] != scope_id or idempotency["scope_id"] != scope_id:
            raise TransactionError("reservation scope drifted")
        if stage["principal"] != principal or idempotency["principal"] != principal:
            raise TransactionError("reservation principal drifted")
        if stage["capability"] != capability or idempotency["capability"] != capability:
            raise TransactionError("reservation capability drifted")
        if stage["idempotency_key"] != request["idempotency_key"] or idempotency["idempotency_key"] != request["idempotency_key"]:
            raise TransactionError("reservation key drifted")
        if stage["request_hash"] != request_hash or idempotency["request_hash"] != request_hash:
            raise TransactionError("reservation request hash drifted")
        validate_request(stage["request"])
        if canonical_request_hash(stage["request"]) != request_hash:
            raise TransactionError("reservation request payload drifted")
        if stage["status"] not in _META_STATUSES:
            raise TransactionError("reservation stage status is invalid")
        expected_idempotency_status = "complete" if stage["status"] == "complete" else "open"
        if idempotency["status"] != expected_idempotency_status:
            raise TransactionError("reservation idempotency status drifted")
        if require_complete and stage["status"] != "complete":
            raise TransactionError("reservation is not complete")
        response = None
        if stage["status"] != "open":
            prepared = _strict_object(stage.get("prepared"), {"record_body", "outcome", "evidence_status", "blob", "context"}, set(), "transaction prepared")
            record_bytes = base64.b64decode(prepared["record_body"])
            if stage["status"] == "complete":
                if "record_id" not in stage or "record_hash" not in stage or "content_sha256" not in stage or "envelope" not in stage or "response" not in stage:
                    raise TransactionError("complete reservation metadata is incomplete")
                response = validate_response(stage["response"])
                if response != validate_response(idempotency.get("response")):
                    raise TransactionError("idempotency response drifted")
                ok = prepared["outcome"] == "completed"
                expected_response = make_response(
                    stage["request"]["request_id"],
                    ok=ok,
                    outcome=prepared["outcome"],
                    record_ids=[stage["record_id"]],
                    entry_ids=[stage["envelope"]["entry_id"]],
                    usage={"requests": 1, "bytes": len(record_bytes)},
                    error=None if ok else {"code": prepared["outcome"], "retryable": prepared["outcome"] in {"interrupted", "degraded"}, "message": "durable operation outcome"},
                )
                if response != expected_response:
                    raise TransactionError("reservation response drifted")
                envelope = validate_journal_envelope(stage["envelope"])
                if envelope != stage["envelope"]:
                    raise TransactionError("reservation envelope drifted")
                expected_envelope = make_journal_envelope(
                    sequence=envelope["sequence"],
                    appended_at=stage["appended_at"],
                    producer=request["producer"],
                    artifact={
                        "kind": prepared["context"]["kind"],
                        "schema": prepared["context"]["schema"],
                        "record_id": stage["record_id"],
                        "hash": stage["record_hash"],
                        "authorized_uri": prepared["context"]["authorized_uri"],
                    },
                    lineage=prepared["context"]["lineage"],
                    source=prepared["context"]["source"],
                    classification={"outcome": prepared["outcome"], "evidence_status": prepared["evidence_status"]},
                    access=prepared["context"]["access"],
                    policy_id=prepared["context"]["policy_id"],
                    dedupe={"object_key": prepared["context"]["object_key"], "content_sha256": stage["content_sha256"]},
                    usage={"requests": 1, "bytes": len(record_bytes)},
                )
                if envelope != expected_envelope:
                    raise TransactionError("reservation envelope drifted")
                if self.journal.get(envelope["entry_id"]) != envelope:
                    raise TransactionError("reservation journal entry drifted")
                if not self.records.verify_record(stage["record_id"], stage["record_hash"]):
                    raise TransactionError("reservation record drifted")
                self.records.blobs.get(stage["content_sha256"])
        return stage, idempotency

    def _load_validated_reservation(
        self,
        request: Mapping[str, Any],
        *,
        principal: str,
        capability: str,
        require_complete: bool = False,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], str, str, str]:
        request = validate_request(request)
        if not isinstance(principal, str) or not principal:
            raise TransactionError("authenticated principal is required")
        if not isinstance(capability, str) or not capability:
            raise TransactionError("authenticated capability is required")
        request_hash = canonical_request_hash(request)
        scope_id = self._scope_id(principal, capability, request["idempotency_key"])
        transaction_id = canonical_hash({"scope": scope_id, "request_hash": request_hash})
        stage = self._load_metadata("transactions", "stages", f"{transaction_id}.json")
        idempotency = self._load_metadata("transactions", "idempotency", f"{scope_id}.json")
        stage, idempotency = self._validate_reservation(
            stage,
            idempotency,
            request=request,
            principal=principal,
            capability=capability,
            request_hash=request_hash,
            scope_id=scope_id,
            transaction_id=transaction_id,
            require_complete=require_complete,
        )
        return stage, idempotency, request, request_hash, scope_id, transaction_id

    @staticmethod
    def _neutral_context(request: Mapping[str, Any], request_hash: str) -> dict[str, Any]:
        """Provide explicit recovery metadata for an attempt with no provider result."""

        return {
            "kind": "attempt",
            "schema": "houndd.attempt.v1",
            "authorized_uri": "houndd://unavailable",
            "lineage": {"relation": "none", "record_id": request["request_id"], "lead_id": "none"},
            "source": {"provider": "none", "native_id": request["request_id"], "canonical_url": "none"},
            "object_key": f"request:{request_hash}",
            "access": request["requested_access"],
            "policy_id": request["policy_id"],
        }

    def begin(self, request: Mapping[str, Any], *, principal: str, capability: str) -> Transaction:
        """Reserve a key after authentication; ``principal`` is transport-derived."""

        request = validate_request(request)
        if not isinstance(principal, str) or not principal:
            raise TransactionError("authenticated principal is required")
        if not isinstance(capability, str) or not capability:
            raise TransactionError("authenticated capability is required")
        request_hash = canonical_request_hash(request)
        scope_id = self._scope_id(principal, capability, request["idempotency_key"])
        transaction_id = canonical_hash({"scope": scope_id, "request_hash": request_hash})
        stage_path = self._stage_path(transaction_id)
        idempotency_path = self._idempotency_path(scope_id)
        with self._lock():
            if self.anchor.exists("transactions", "idempotency", f"{scope_id}.json"):
                stored_idempotency = self._load_metadata("transactions", "idempotency", f"{scope_id}.json")
                if stored_idempotency.get("request_hash") != request_hash:
                    raise IdempotencyConflict("idempotency key was reused for a different request")
                stage = self._load_metadata("transactions", "stages", f"{transaction_id}.json")
                stage, _ = self._validate_reservation(
                    stage,
                    stored_idempotency,
                    request=request,
                    principal=principal,
                    capability=capability,
                    request_hash=request_hash,
                    scope_id=scope_id,
                    transaction_id=transaction_id,
                    require_complete=False,
                )
                response = stage.get("response") if stage["status"] == "complete" else None
                return Transaction(self, transaction_id, request, principal, capability, request_hash, scope_id, response)
            if self.anchor.exists("transactions", "stages", f"{transaction_id}.json"):
                raise TransactionError("reservation counterpart is missing")
            context = self._neutral_context(request, request_hash)
            stage = {
                "transaction_id": transaction_id,
                "scope_id": scope_id,
                "principal": principal,
                "capability": capability,
                "idempotency_key": request["idempotency_key"],
                "request": request,
                "request_hash": request_hash,
                "status": "open",
                "context": context,
                "appended_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            }
            self._write_metadata("transactions", "stages", f"{transaction_id}.json", value=stage)
            self._write_metadata(
                "transactions",
                "idempotency",
                f"{scope_id}.json",
                value={
                    "scope_id": scope_id,
                    "principal": principal,
                    "capability": capability,
                    "idempotency_key": request["idempotency_key"],
                    "request_hash": request_hash,
                    "transaction_id": transaction_id,
                    "status": "open",
                },
            )
        return Transaction(self, transaction_id, request, principal, capability, request_hash, scope_id)

    def _write_stage(self, stage: dict[str, Any]) -> None:
        self._write_metadata("transactions", "stages", f"{stage['transaction_id']}.json", value=stage)

    def _write_idempotency(self, stage: Mapping[str, Any]) -> None:
        self._write_metadata(
            "transactions",
            "idempotency",
            f"{stage['scope_id']}.json",
            value={
                "scope_id": stage["scope_id"],
                "principal": stage["principal"],
                "capability": stage["capability"],
                "idempotency_key": stage["idempotency_key"],
                "request_hash": stage["request_hash"],
                "transaction_id": stage["transaction_id"],
                "status": stage["status"],
                **({"response": stage["response"]} if "response" in stage else {}),
            },
        )

    @staticmethod
    def _hook(fault: str | None, point: str) -> None:
        if fault == point:
            raise InjectedCrash(point)

    def _commit(
        self,
        transaction: Transaction,
        *,
        record: Mapping[str, Any] | None,
        outcome: str,
        evidence_status: str,
        blob: bytes | None,
        context: Mapping[str, Any] | None,
        fault: str | None,
    ) -> dict[str, Any]:
        if transaction.existing_response is not None:
            return transaction.existing_response
        with self._lock():
            stage, _, _, _, _, _ = self._load_validated_reservation(
                transaction.request,
                principal=transaction.principal,
                capability=transaction.capability,
                require_complete=False,
            )
            if stage.get("status") == "complete":
                return stage["response"]
            self._hook(fault, FAULT_BEFORE_PROVIDER)
            if "prepared" not in stage:
                if not isinstance(outcome, str) or not outcome:
                    raise TransactionError("outcome must be a non-empty string")
                if outcome == "completed" and record is None:
                    raise TransactionError("completed outcome requires a record")
                payload = dict(record) if record is not None else {
                    "schema_version": "houndd.outcome.v1",
                    "outcome": outcome,
                    "request_id": stage["request"]["request_id"],
                }
                body = {
                    "schema_version": "houndd.record.v1",
                    "occurrence_id": stage["transaction_id"],
                    "payload": payload,
                }
                record_bytes = canonical_bytes(body)
                stage["prepared"] = {
                    "record_body": base64.b64encode(record_bytes).decode("ascii"),
                    "outcome": outcome,
                    "evidence_status": evidence_status,
                    "blob": base64.b64encode(blob).decode("ascii") if blob is not None else None,
                    "context": {**stage["context"], **dict(context or {})},
                }
                stage["status"] = "prepared"
                self._write_stage(stage)
            self._hook(fault, FAULT_AFTER_PROVIDER)
            prepared = stage["prepared"]
            record_bytes = base64.b64decode(prepared["record_body"])
            body = json.loads(record_bytes.decode("utf-8"))
            reference = self.records.put_json(body)
            blob_bytes = base64.b64decode(prepared["blob"]) if prepared["blob"] is not None else record_bytes
            content_sha256 = self.records.blob(blob_bytes)
            stage["record_id"] = reference.record_id
            stage["record_hash"] = reference.content_sha256
            stage["content_sha256"] = content_sha256
            stage["status"] = "published"
            if "envelope" not in stage:
                context_body = prepared["context"]
                sequence = self.journal.high_watermark() + 1
                artifact = {
                    "kind": context_body["kind"],
                    "schema": context_body["schema"],
                    "record_id": reference.record_id,
                    "hash": reference.content_sha256,
                    "authorized_uri": context_body["authorized_uri"],
                }
                envelope = make_journal_envelope(
                    sequence=sequence,
                    appended_at=stage.get("appended_at", "1970-01-01T00:00:00+00:00"),
                    producer=stage["request"]["producer"],
                    artifact=artifact,
                    lineage=context_body["lineage"],
                    source=context_body["source"],
                    classification={"outcome": prepared["outcome"], "evidence_status": prepared["evidence_status"]},
                    access=context_body["access"],
                    policy_id=context_body["policy_id"],
                    dedupe={"object_key": context_body["object_key"], "content_sha256": content_sha256},
                    usage={"requests": 1, "bytes": len(record_bytes)},
                )
                stage["envelope"] = envelope
            self._write_stage(stage)
            self.journal.append(stage["envelope"], before_fsync=lambda point: self._hook(fault, point))
            self._hook(fault, FAULT_AFTER_JOURNAL)
            ok = prepared["outcome"] == "completed"
            error = None if ok else {"code": prepared["outcome"], "retryable": prepared["outcome"] in {"interrupted", "degraded"}, "message": "durable operation outcome"}
            response = make_response(
                stage["request"]["request_id"],
                ok=ok,
                outcome=prepared["outcome"],
                record_ids=[reference.record_id],
                entry_ids=[stage["envelope"]["entry_id"]],
                usage={"requests": 1, "bytes": len(record_bytes)},
                error=error,
            )
            stage["response"] = response
            stage["status"] = "complete"
            self._write_stage(stage)
            self._write_idempotency(stage)
            transaction.existing_response = response
            return response

    def _recover_stage(self, stage: dict[str, Any]) -> dict[str, Any]:
        request = validate_request(stage["request"])
        request_hash = canonical_request_hash(request)
        scope_id = self._scope_id(stage["principal"], stage["capability"], request["idempotency_key"])
        transaction_id = canonical_hash({"scope": scope_id, "request_hash": request_hash})
        stage, _ = self._validate_reservation(
            stage,
            self._load_metadata("transactions", "idempotency", f"{scope_id}.json"),
            request=request,
            principal=stage["principal"],
            capability=stage["capability"],
            request_hash=request_hash,
            scope_id=scope_id,
            transaction_id=transaction_id,
            require_complete=False,
        )
        if stage.get("status") == "complete":
            return stage["response"]
        if "prepared" not in stage:
            stage["prepared"] = {
                "record_body": base64.b64encode(
                    canonical_bytes(
                        {
                            "schema_version": "houndd.record.v1",
                            "occurrence_id": stage["transaction_id"],
                            "payload": {
                                "schema_version": "houndd.outcome.v1",
                                "outcome": "interrupted",
                                "request_id": stage["request"]["request_id"],
                            },
                        }
                    )
                ).decode("ascii"),
                "outcome": "interrupted",
                "evidence_status": "failure",
                "blob": None,
                "context": stage["context"],
            }
        prepared = stage["prepared"]
        if "record_id" not in stage:
            record_bytes = base64.b64decode(prepared["record_body"])
            reference = self.records.put_json(json.loads(record_bytes.decode("utf-8")))
            stage["record_id"] = reference.record_id
            stage["record_hash"] = reference.content_sha256
            stage["content_sha256"] = self.records.blob(record_bytes)
        if "envelope" not in stage:
            context = prepared["context"]
            stage["envelope"] = make_journal_envelope(
                sequence=self.journal.high_watermark() + 1,
                appended_at=stage["appended_at"],
                producer=stage["request"]["producer"],
                artifact={"kind": context["kind"], "schema": context["schema"], "record_id": stage["record_id"], "hash": stage["record_hash"], "authorized_uri": context["authorized_uri"]},
                lineage=context["lineage"],
                source=context["source"],
                classification={"outcome": prepared["outcome"], "evidence_status": prepared["evidence_status"]},
                access=context["access"],
                policy_id=context["policy_id"],
                dedupe={"object_key": context["object_key"], "content_sha256": stage["content_sha256"]},
                usage={"requests": 1, "bytes": len(base64.b64decode(prepared["record_body"]))},
            )
        if self.journal.get(stage["envelope"]["entry_id"]) is None:
            self.journal.append(stage["envelope"])
        response = make_response(
            stage["request"]["request_id"],
            ok=prepared["outcome"] == "completed",
            outcome=prepared["outcome"],
            record_ids=[stage["record_id"]],
            entry_ids=[stage["envelope"]["entry_id"]],
            usage={"requests": 1, "bytes": len(base64.b64decode(prepared["record_body"]))},
            error=None if prepared["outcome"] == "completed" else {"code": prepared["outcome"], "retryable": True, "message": "durable operation outcome"},
        )
        stage["response"] = response
        stage["status"] = "complete"
        self._write_stage(stage)
        self._write_idempotency(stage)
        return response

    def reconcile(self) -> list[dict[str, Any]]:
        """Finalize every staged attempt exactly once after a process restart."""

        self.journal.reconcile()
        recovered = []
        with self._lock():
            for name in self.anchor.listdir("transactions", "stages"):
                if not name.endswith(".json"):
                    continue
                stage = self._load_metadata("transactions", "stages", name)
                if stage.get("status") != "complete":
                    recovered.append(self._recover_stage(stage))
        return recovered


__all__ = [
    "FAULT_AFTER_JOURNAL",
    "FAULT_AFTER_PROVIDER",
    "FAULT_AFTER_RECORD",
    "FAULT_BEFORE_PROVIDER",
    "IdempotencyConflict",
    "InjectedCrash",
    "Transaction",
    "TransactionCoordinator",
    "TransactionError",
]
