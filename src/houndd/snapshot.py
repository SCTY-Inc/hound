"""HSP-08: durable canonical-field queries over verified journal bytes."""

from __future__ import annotations

import hashlib
import json
import secrets
from collections.abc import Callable
from datetime import datetime
from typing import ClassVar
from types import MappingProxyType

from .access import (
    AuthenticatedPrincipal,
    EventSelector,
    PrincipalScope,
    ProducerSelector,
    authorize_event_header,
)
from .contracts import canonical_bytes, canonical_hash, validate_journal_envelope
from .cursor import CursorBindings, CursorCodec, CursorKeyring, CursorRejected, JournalCursorCandidate
from .journal import (
    Journal,
    PersistedJournalSnapshot,
    _validate_persisted_chain_value,
    _validate_persisted_head_value,
)
from .provenance import ProvenanceProjection
from .query_contracts import (
    ClassificationFilter,
    ProducerFilter,
    QueryFilter,
    QueryRequest,
    SourceFilter,
    TimeRange,
)
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


def _exact_text_tuple(value: object, label: str) -> tuple[str, ...] | None:
    if value is None:
        return None
    if type(value) is not tuple or any(type(item) is not str for item in value):
        raise QueryEngineError(f"{label} must contain only exact immutable strings")
    return tuple(value)


def _trusted_request(value: object) -> QueryRequest:
    if type(value) is not QueryRequest:
        raise QueryEngineError("query request must be an exact QueryRequest")
    query_filter = value.filter
    if type(query_filter) is not QueryFilter:
        raise QueryEngineError("query request filter must be an exact QueryFilter")
    if type(value.limit) is not int or not 1 <= value.limit <= 100:
        raise QueryEngineError("query request limit is invalid")
    if value.cursor is not None and type(value.cursor) is not str:
        raise QueryEngineError("query request cursor is invalid")

    time_range = query_filter.time_range
    if time_range is not None:
        if (
            type(time_range) is not TimeRange
            or type(time_range.lower) is not datetime
            or type(time_range.upper) is not datetime
        ):
            raise QueryEngineError("query time range must be an exact TimeRange")
        time_range = TimeRange(time_range.lower, time_range.upper)

    producer = query_filter.producer
    if producer is not None:
        if type(producer) is not ProducerFilter:
            raise QueryEngineError("query producer filter must be an exact ProducerFilter")
        producer = ProducerFilter(
            owner_id=_exact_text_tuple(producer.owner_id, "producer.owner_id"),
            capability=_exact_text_tuple(producer.capability, "producer.capability"),
            run_id=_exact_text_tuple(producer.run_id, "producer.run_id"),
        )

    source = query_filter.source
    if source is not None:
        if type(source) is not SourceFilter:
            raise QueryEngineError("query source filter must be an exact SourceFilter")
        source = SourceFilter(
            provider=_exact_text_tuple(source.provider, "source.provider"),
            canonical_url=_exact_text_tuple(source.canonical_url, "source.canonical_url"),
        )

    classification = query_filter.classification
    if classification is not None:
        if type(classification) is not ClassificationFilter:
            raise QueryEngineError("query classification filter must be an exact ClassificationFilter")
        classification = ClassificationFilter(
            outcome=_exact_text_tuple(classification.outcome, "classification.outcome"),
            evidence_status=_exact_text_tuple(
                classification.evidence_status,
                "classification.evidence_status",
            ),
        )

    try:
        trusted_filter = QueryFilter(
            time_range=time_range,
            producer=producer,
            lane=_exact_text_tuple(query_filter.lane, "lane"),
            topic=_exact_text_tuple(query_filter.topic, "topic"),
            source=source,
            entity=_exact_text_tuple(query_filter.entity, "entity"),
            entry_id=_exact_text_tuple(query_filter.entry_id, "entry_id"),
            record_id=_exact_text_tuple(query_filter.record_id, "record_id"),
            object_key=_exact_text_tuple(query_filter.object_key, "object_key"),
            content_sha256=_exact_text_tuple(query_filter.content_sha256, "content_sha256"),
            classification=classification,
            access=_exact_text_tuple(query_filter.access, "access"),
        )
        return QueryRequest(trusted_filter, value.limit, value.cursor)
    except (TypeError, ValueError) as error:
        if isinstance(error, QueryEngineError):
            raise
        raise QueryEngineError("query request graph is invalid") from error


def _trusted_scope(value: object) -> PrincipalScope:
    if type(value) is not PrincipalScope:
        raise QueryEngineError("query scope must be an exact PrincipalScope or None")
    principal = value.principal
    if type(principal) is not AuthenticatedPrincipal or type(principal.subject) is not str:
        raise QueryEngineError("query principal must be exact authenticated input")
    readable_tiers = value.readable_tiers
    selectors = value.permitted_event_selectors
    if type(readable_tiers) is not frozenset or any(type(tier) is not str for tier in readable_tiers):
        raise QueryEngineError("query scope tiers must be exact immutable strings")
    if type(selectors) is not tuple or any(type(selector) is not EventSelector for selector in selectors):
        raise QueryEngineError("query scope selectors must be exact EventSelector values")

    trusted_selectors: list[EventSelector] = []
    for selector in selectors:
        producer = selector.producer_selector
        tiers = selector.readable_tiers
        if (
            type(selector.policy_id) is not str
            or type(producer) is not ProducerSelector
            or type(tiers) is not frozenset
            or any(type(tier) is not str for tier in tiers)
        ):
            raise QueryEngineError("query scope selector graph is invalid")
        producer_values = (producer.owner_id, producer.capability, producer.run_id)
        if any(item is not None and type(item) is not str for item in producer_values):
            raise QueryEngineError("query producer selector values must be exact strings")
        trusted_selectors.append(
            EventSelector(
                selector.policy_id,
                ProducerSelector(producer.owner_id, producer.capability, producer.run_id),
                frozenset(tiers),
            )
        )
    try:
        return PrincipalScope(
            AuthenticatedPrincipal(principal.subject),
            frozenset(readable_tiers),
            tuple(trusted_selectors),
        )
    except (TypeError, ValueError) as error:
        raise QueryEngineError("query scope graph is invalid") from error


def _trusted_identity_state(value: object) -> ServiceIdentityState:
    if type(value) is not ServiceIdentityState or type(value.generation) is not str:
        raise QueryEngineError("service identity lease returned an invalid state")
    keyring = value.keyring
    if (
        type(keyring) is not CursorKeyring
        or type(keyring.active_kid) is not str
        or type(keyring.keys) is not MappingProxyType
    ):
        raise QueryEngineError("service identity lease returned an invalid keyring")
    keys = dict(keyring.keys)
    if any(type(kid) is not str or type(secret) is not bytes for kid, secret in keys.items()):
        raise QueryEngineError("service identity lease returned invalid cursor keys")
    try:
        return ServiceIdentityState(value.generation, CursorKeyring(keyring.active_kid, keys))
    except (TypeError, ValueError) as error:
        raise QueryEngineError("service identity lease returned invalid durable input") from error


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
        is_canonical = type(value) is dict and canonical_bytes(value) == raw
    except ValueError as error:
        raise QuerySnapshotError("persisted journal head is not canonical") from error
    if not is_canonical:
        raise QuerySnapshotError("persisted journal head is not canonical")
    try:
        return _validate_persisted_head_value(value)
    except ValueError as error:
        raise QuerySnapshotError(str(error)) from error


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
        chains = [
            _validate_persisted_chain_value(_row_value(raw, "chain"))
            for raw in persisted.chain_rows
        ]
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
                or canonical_bytes(chain) != canonical_bytes(expected_chain)
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
        if persisted.head_bytes is None:
            raise QuerySnapshotError("persisted journal head does not match its chain")
        _head_value(persisted.head_bytes)
        if persisted.head_bytes != canonical_bytes(expected_head):
            raise QuerySnapshotError("persisted journal head does not match its chain")
    elif persisted.head_bytes is not None:
        empty_head = {"sequence": -1, "entry_id": "", "chain_sha256": "0" * 64}
        _head_value(persisted.head_bytes)
        if persisted.head_bytes != canonical_bytes(empty_head):
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
        if type(journal) is not Journal:
            raise DurableQueryError("durable query adapter requires an exact Journal")
        if type(service_identity) is not ServiceIdentity:
            raise DurableQueryError("durable query adapter requires an exact ServiceIdentity")
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
        codec.authenticate(request.cursor)
        prefix_hashes = provenance.access_scoped_context_hashes(scope, snapshot.events)
        tested: set[str] = set()
        for context_hash in reversed(prefix_hashes):
            if context_hash in tested:
                continue
            tested.add(context_hash)
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
        trusted_scope = _trusted_scope(scope)
        trusted_request = _trusted_request(request)
        unavailable = self._unavailable_filters(trusted_request)
        if unavailable:
            raise QueryFilterNotAvailable(unavailable)

        with ServiceIdentity.lease(self._service_identity) as leased_state:
            state = _trusted_identity_state(leased_state)
            snapshot = build_journal_query_snapshot(Journal.verified_snapshot(self._journal))
            if not any(authorize_event_header(trusted_scope, event) for event in snapshot.events):
                return EMPTY_QUERY_PAGE
            provenance = ProvenanceProjection()
            codec = CursorCodec(state.keyring, nonce_source=self._nonce_source)
            if trusted_request.cursor is None:
                context = QueryContext.from_projection(state.generation, trusted_scope, snapshot, provenance)
            else:
                context = self._resume_context(
                    trusted_request,
                    trusted_scope,
                    snapshot,
                    provenance,
                    codec,
                    state,
                )
            return self._engine.execute(
                trusted_request,
                trusted_scope,
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
