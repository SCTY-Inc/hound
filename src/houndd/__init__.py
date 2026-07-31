"""HSP-04: public standard-library-only durable Discovery Spine primitives."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from .contracts import (
    ACCESS_TIERS,
    ContractError,
    canonical_bytes,
    canonical_hash,
    canonical_json,
    canonical_request_hash,
    make_journal_envelope,
    make_response,
    validate_forbidden_fields,
    validate_journal_envelope,
    validate_request,
    validate_response,
)
from .journal import Journal, JournalError
from .projection import Projection, ProjectionError
from .store import BlobStore, ImmutableConflict, RecordRef, RecordStore, StoreError, UnsafeStoreError
from .transactions import (
    FAULT_AFTER_JOURNAL,
    FAULT_AFTER_PROVIDER,
    FAULT_AFTER_RECORD,
    FAULT_BEFORE_PROVIDER,
    IdempotencyConflict,
    InjectedCrash,
    Transaction,
    TransactionCoordinator,
    TransactionError,
)
from .verify import verify_store


class HounddStore:
    """Small composition root for the durable Slice 1 store."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        try:
            self.records = RecordStore(self.root)
            self.root = self.records.root
            self.journal = Journal(self.root)
            self.transactions = TransactionCoordinator(self.root)
            self.projection = Projection(self.root, create=True)
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        projection = getattr(self, "projection", None)
        if projection is not None:
            projection.close()
        transactions = getattr(self, "transactions", None)
        if transactions is not None:
            transactions.close()
        journal = getattr(self, "journal", None)
        if journal is not None:
            journal.close()
        records = getattr(self, "records", None)
        if records is not None:
            records.close()

    def __enter__(self) -> "HounddStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def begin(self, request: Mapping[str, Any], *, principal: str, capability: str) -> Transaction:
        return self.transactions.begin(request, principal=principal, capability=capability)

    def recover(self) -> list[dict[str, Any]]:
        recovered = self.transactions.reconcile()
        self.projection.rebuild(self.journal, self.records)
        return recovered

    def rebuild_index(self) -> dict[str, Any]:
        return self.projection.rebuild(self.journal, self.records)

    def mirror_legacy(self, record_id: str, data: bytes, *, expected_sha256: str | None = None) -> RecordRef:
        return self.records.put_bytes(record_id, data, expected_sha256=expected_sha256)

    def verify(self) -> dict[str, Any]:
        return verify_store(self.root)


__all__ = [
    "ACCESS_TIERS",
    "BlobStore",
    "ContractError",
    "FAULT_AFTER_JOURNAL",
    "FAULT_AFTER_PROVIDER",
    "FAULT_AFTER_RECORD",
    "FAULT_BEFORE_PROVIDER",
    "HounddStore",
    "IdempotencyConflict",
    "ImmutableConflict",
    "InjectedCrash",
    "Journal",
    "JournalError",
    "Projection",
    "ProjectionError",
    "RecordRef",
    "RecordStore",
    "StoreError",
    "Transaction",
    "TransactionCoordinator",
    "TransactionError",
    "UnsafeStoreError",
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
    "verify_store",
]
