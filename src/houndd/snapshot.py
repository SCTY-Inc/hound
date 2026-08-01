"""HSP-08: durable canonical-field queries over verified journal bytes."""

from __future__ import annotations

import hashlib
import json
import secrets
from collections.abc import Callable
from typing import ClassVar

from .access import PrincipalScope, authorize_event_header
from .contracts import canonical_bytes, canonical_hash, validate_journal_envelope
from .cursor import CursorBindings, CursorCodec, CursorRejected, JournalCursorCandidate
from .journal import Journal, PersistedJournalSnapshot
from .provenance import ProvenanceProjection
from .query_contracts import QueryRequest
from .query_engine import (
    EMPTY_QUERY_PAGE,
    JournalQueryEngine,
    JournalQuerySnapshot,
    QueryContext,
    QueryEngineError,
    QueryPage,
    QuerySnapshotError,
)
from .service_identity import ServiceIdentity, ServiceIdentityState


class DurableQueryError(ValueError):
    """A durable query cannot be evaluated under the Slice 3A contract."""


class QueryFilterNotAvailable(DurableQueryError):
    """A requested derived filter has no durable Slice 3A truth source."""

    code: ClassVar[str] = "filter_not_available"
    outcome: ClassVar[str] = code

    def __init__(self, filters: tuple[str, ...]) -> None:
        normalized = tuple(sorted(set(filters)))
        if not normalized or any(value not in {"lane", "topic", "entity"} for value in normalized):
            raise ValueError("unavailable query filters are invalid")
        self.filters = normalized
        super().__init__(f"filter not available: {', '.join(normalized)}")


def _row_value(raw: object, label: str) -> dict[str, object]:
    if type(raw) is not bytes or not raw.endswith(b"\n"):
        raise QuerySnapshotError(f"persisted {label} row is partial or not immutable bytes")
    body = raw[:-1]
    if b"\n" in body or b"\r" in body:
        raise QuerySnapshotError(f"persisted {label} row contains an embedded line boundary")
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeError, ValueError) as error:
        raise QuerySnapshotError(f"persisted {label} row is invalid JSON") from error
    try:
        is_canonical = isinstance(value, dict) and canonical_bytes(value) == body
    except ValueError as error:
        raise QuerySnapshotError(f"persisted {label} row is not canonical JSON") from error
    if not is_canonical:
        raise QuerySnapshotError(f"persisted {label} row is not canonical JSON")
    return value


def _head_value(raw: object) -> dict[str, object]:
    if type(raw) is not bytes:
        raise QuerySnapshotError("persisted journal head must be immutable bytes")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as error:
        raise QuerySnapshotError("persisted journal head is invalid JSON") from error
    try:
        is_canonical = (
            isinstance(value, dict)
            and set(value) == {"sequence", "entry_id", "chain_sha256"}
            and canonical_bytes(value) == raw
        )
    except ValueError as error:
        raise QuerySnapshotError("persisted journal head is not canonical") from error
    if not is_canonical:
        raise QuerySnapshotError("persisted journal head is not canonical")
    return value


def build_journal_query_snapshot(
    persisted: PersistedJournalSnapshot,
) -> JournalQuerySnapshot:
    """Defensively build the immutable query model from exact persisted truth."""

    if type(persisted) is not PersistedJournalSnapshot:
        raise QuerySnapshotError("durable query snapshot requires persisted journal bytes")
    if type(persisted.event_rows) is not tuple or type(persisted.chain_rows) is not tuple:
        raise QuerySnapshotError("persisted journal rows must be immutable tuples")
    try:
        events = [validate_journal_envelope(_row_value(raw, "event")) for raw in persisted.event_rows]
        chains = [_row_value(raw, "chain") for raw in persisted.chain_rows]
    except QuerySnapshotError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise QuerySnapshotError("persisted journal contains an invalid canonical value") from error
    if len(events) != len(chains):
        raise QuerySnapshotError("persisted journal events and chain must be complete")

    previous = "0" * 64
    candidates: list[JournalCursorCandidate] = []
    seen_entry_ids: set[str] = set()
    seen_event_hashes: set[str] = set()
    seen_chain_hashes: set[str] = set()
    try:
        for expected_sequence, (event, chain) in enumerate(zip(events, chains, strict=True)):
            event_hash = hashlib.sha256(canonical_bytes(event)).hexdigest()
            body = {
                "sequence": event["sequence"],
                "entry_id": event["entry_id"],
                "event_sha256": event_hash,
                "previous_chain_sha256": previous,
            }
            expected_chain = {**body, "chain_sha256": canonical_hash(body)}
            if (
                event["sequence"] != expected_sequence
                or event["entry_id"] in seen_entry_ids
                or event_hash in seen_event_hashes
                or chain != expected_chain
                or expected_chain["chain_sha256"] in seen_chain_hashes
            ):
                raise QuerySnapshotError("persisted journal sequence, identity, or chain is invalid")
            candidate = JournalCursorCandidate(
                sequence=event["sequence"],
                entry_id=event["entry_id"],
                appended_at=event["appended_at"],
                chain_sha256=chain["chain_sha256"],
            )
            candidates.append(candidate)
            seen_entry_ids.add(event["entry_id"])
            seen_event_hashes.add(event_hash)
            seen_chain_hashes.add(expected_chain["chain_sha256"])
            previous = expected_chain["chain_sha256"]
    except QuerySnapshotError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise QuerySnapshotError("persisted journal sequence, identity, or chain is invalid") from error

    if events:
        expected_head = {
            "sequence": events[-1]["sequence"],
            "entry_id": events[-1]["entry_id"],
            "chain_sha256": previous,
        }
        if persisted.head_bytes is None or _head_value(persisted.head_bytes) != expected_head:
            raise QuerySnapshotError("persisted journal head does not match its chain")
    elif persisted.head_bytes is not None:
        empty_head = {"sequence": -1, "entry_id": "", "chain_sha256": "0" * 64}
        if _head_value(persisted.head_bytes) != empty_head:
            raise QuerySnapshotError("persisted empty journal head is invalid")

    try:
        return JournalQuerySnapshot(events, tuple(candidates))
    except QuerySnapshotError:
        raise
    except (TypeError, ValueError) as error:
        raise QuerySnapshotError("persisted journal cannot form an immutable query snapshot") from error


class DurableJournalQueryAdapter:
    """Execute pure canonical queries against one verified persisted snapshot."""

    def __init__(
        self,
        journal: Journal,
        service_identity: ServiceIdentity,
        *,
        nonce_source: Callable[[int], bytes] = secrets.token_bytes,
    ) -> None:
        if not isinstance(journal, Journal):
            raise DurableQueryError("durable query adapter requires a Journal")
        if not isinstance(service_identity, ServiceIdentity):
            raise DurableQueryError("durable query adapter requires a ServiceIdentity")
        if not callable(nonce_source):
            raise DurableQueryError("durable query cursor nonce source must be callable")
        self._journal = journal
        self._service_identity = service_identity
        self._nonce_source = nonce_source
        self._engine = JournalQueryEngine()

    @staticmethod
    def _unavailable_filters(request: QueryRequest) -> tuple[str, ...]:
        return tuple(
            field
            for field in ("entity", "lane", "topic")
            if getattr(request.filter, field) is not None
        )

    @staticmethod
    def _resume_context(
        request: QueryRequest,
        scope: PrincipalScope,
        snapshot: JournalQuerySnapshot,
        provenance: ProvenanceProjection,
        codec: CursorCodec,
        state: ServiceIdentityState,
    ) -> QueryContext:
        assert request.cursor is not None
        for end in range(len(snapshot.events), 0, -1):
            context_hash = provenance.access_scoped_context_hash(scope, snapshot.events[:end])
            bindings = CursorBindings(
                state.generation,
                request.filter_hash,
                scope.principal.subject,
                context_hash,
            )
            try:
                codec.recover(request.cursor, bindings, snapshot.cursor_recovery_snapshot)
            except CursorRejected:
                continue
            return QueryContext(state.generation, context_hash)
        raise CursorRejected()

    def execute(
        self,
        request: QueryRequest,
        scope: PrincipalScope | None,
    ) -> QueryPage:
        # Preserve the existing authorization-first no-dereference boundary.
        if scope is None:
            return EMPTY_QUERY_PAGE
        if not isinstance(scope, PrincipalScope):
            raise QueryEngineError("query scope must be a PrincipalScope or None")
        if not isinstance(request, QueryRequest):
            raise QueryEngineError("query request must be a QueryRequest")
        unavailable = self._unavailable_filters(request)
        if unavailable:
            raise QueryFilterNotAvailable(unavailable)

        with self._service_identity.lease() as state:
            snapshot = build_journal_query_snapshot(self._journal.verified_snapshot())
            if not any(authorize_event_header(scope, event) for event in snapshot.events):
                return EMPTY_QUERY_PAGE
            provenance = ProvenanceProjection()
            codec = CursorCodec(state.keyring, nonce_source=self._nonce_source)
            if request.cursor is None:
                context = QueryContext.from_projection(state.generation, scope, snapshot, provenance)
            else:
                context = self._resume_context(request, scope, snapshot, provenance, codec, state)
            return self._engine.execute(
                request,
                scope,
                snapshot,
                provenance,
                codec,
                context,
            )

    query = execute


__all__ = [
    "DurableJournalQueryAdapter",
    "DurableQueryError",
    "QueryFilterNotAvailable",
    "build_journal_query_snapshot",
]
