"""HSP-04: public standard-library-only durable Discovery Spine primitives."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from .access import (
    AccessPolicyError,
    AccessRefusal,
    AuthenticatedPrincipal,
    EffectiveAccess,
    EventSelector,
    PolicyBundle,
    PolicyRule,
    PrincipalScope,
    ProducerClaim,
    ProducerSelector,
    authorize_event_header,
    resolve_commit_access,
    resolve_effective_access,
    resolve_scope,
)
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
from .cursor import (
    CursorBindings,
    CursorCodec,
    CursorKeyring,
    CursorRecovery,
    CursorRecoverySnapshot,
    CursorRejected,
    JournalCursorCandidate,
)
from .journal import Journal, JournalError
from .projection import Projection, ProjectionError
from .query_contracts import (
    ClassificationFilter,
    ProducerFilter,
    QueryContractError,
    QueryFilter,
    QueryRequest,
    SourceFilter,
    TimeRange,
    parse_query_filter,
    parse_query_request,
    parse_utc_instant,
)
from .provenance import (
    AnnotationHeader,
    EventProvenance,
    LaneRule,
    OwnerAnnotation,
    ProvenanceError,
    ProvenanceProjection,
    ProvenanceValue,
)
from .query_engine import (
    EMPTY_QUERY_PAGE,
    JournalQueryEngine,
    JournalQuerySnapshot,
    Page,
    QueryContext,
    QueryContextError,
    QueryEngine,
    QueryEngineError,
    QueryItem,
    QueryPage,
    QuerySnapshotError,
    ReplayDedupeResult,
    dedupe_replay_entry_ids,
)
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
from .commit import (
    AVAILABLE_ROUTE_BINDINGS,
    COMMIT_REQUEST_SCHEMA,
    COMMIT_RESPONSE_SCHEMA,
    MAX_SOURCE_BYTES,
    MAX_WIRE_BODY_BYTES,
    SUPPORTED_SOURCE_ENCODING,
    SUPPORTED_SOURCE_MEDIA_TYPE,
    CommitContractError,
    CommitRequest,
    CommitResponse,
    NormalizedSource,
    Producer,
    ROUTE_BINDINGS,
    RouteBinding,
    SourceDeclaration,
    SourceError,
    canonical_commit_request,
    canonical_commit_request_hash,
    make_commit_response,
    normalize_source,
    parse_commit_request,
    resolve_route,
    validate_commit_response,
)
from .phi import (
    PHI_MANIFEST_FILENAME,
    PHI_MANIFEST_SCHEMA,
    PhiClearEntry,
    PhiClearManifest,
    PhiInputError,
    PhiManifest,
    PhiManifestError,
    PhiScanner,
    load_clear_manifest,
    load_phi_manifest,
    phi_manifest_path,
    scan_phi,
)


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
    "AccessPolicyError",
    "AccessRefusal",
    "AnnotationHeader",
    "AuthenticatedPrincipal",
    "BlobStore",
    "ClassificationFilter",
    "ContractError",
    "CursorBindings",
    "CursorCodec",
    "CursorKeyring",
    "CursorRecovery",
    "CursorRecoverySnapshot",
    "CursorRejected",
    "EffectiveAccess",
    "EMPTY_QUERY_PAGE",
    "EventProvenance",
    "EventSelector",
    "FAULT_AFTER_JOURNAL",
    "FAULT_AFTER_PROVIDER",
    "FAULT_AFTER_RECORD",
    "FAULT_BEFORE_PROVIDER",
    "HounddStore",
    "IdempotencyConflict",
    "ImmutableConflict",
    "InjectedCrash",
    "Journal",
    "JournalQueryEngine",
    "JournalQuerySnapshot",
    "JournalCursorCandidate",
    "JournalError",
    "LaneRule",
    "OwnerAnnotation",
    "Page",
    "PolicyBundle",
    "PolicyRule",
    "PrincipalScope",
    "ProducerClaim",
    "ProducerFilter",
    "ProducerSelector",
    "ProvenanceError",
    "ProvenanceProjection",
    "ProvenanceValue",
    "QueryContext",
    "QueryContextError",
    "QueryEngine",
    "QueryEngineError",
    "QueryItem",
    "QueryPage",
    "QuerySnapshotError",
    "Projection",
    "ProjectionError",
    "QueryContractError",
    "QueryFilter",
    "QueryRequest",
    "RecordRef",
    "RecordStore",
    "ReplayDedupeResult",
    "StoreError",
    "SourceFilter",
    "TimeRange",
    "Transaction",
    "TransactionCoordinator",
    "TransactionError",
    "UnsafeStoreError",
    "authorize_event_header",
    "canonical_bytes",
    "canonical_hash",
    "canonical_json",
    "canonical_request_hash",
    "dedupe_replay_entry_ids",
    "make_journal_envelope",
    "make_response",
    "parse_query_filter",
    "parse_query_request",
    "parse_utc_instant",
    "resolve_commit_access",
    "resolve_effective_access",
    "resolve_scope",
    "validate_forbidden_fields",
    "validate_journal_envelope",
    "validate_request",
    "validate_response",
    "verify_store",
    "AVAILABLE_ROUTE_BINDINGS",
    "COMMIT_REQUEST_SCHEMA",
    "COMMIT_RESPONSE_SCHEMA",
    "MAX_SOURCE_BYTES",
    "MAX_WIRE_BODY_BYTES",
    "SUPPORTED_SOURCE_ENCODING",
    "SUPPORTED_SOURCE_MEDIA_TYPE",
    "CommitContractError",
    "CommitRequest",
    "CommitResponse",
    "NormalizedSource",
    "Producer",
    "ROUTE_BINDINGS",
    "RouteBinding",
    "SourceDeclaration",
    "SourceError",
    "canonical_commit_request",
    "canonical_commit_request_hash",
    "make_commit_response",
    "normalize_source",
    "parse_commit_request",
    "resolve_route",
    "validate_commit_response",
    "PHI_MANIFEST_FILENAME",
    "PHI_MANIFEST_SCHEMA",
    "PhiClearEntry",
    "PhiClearManifest",
    "PhiInputError",
    "PhiManifest",
    "PhiManifestError",
    "PhiScanner",
    "load_clear_manifest",
    "load_phi_manifest",
    "phi_manifest_path",
    "scan_phi",
]
