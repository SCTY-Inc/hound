"""HSP-08/09/20: pure, immutable, authorized journal query evaluation."""

from __future__ import annotations

import hashlib
import hmac
import json
from bisect import bisect_left
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any

from .access import PrincipalScope, authorize_event_header
from .contracts import canonical_bytes, canonical_hash, validate_journal_envelope
from .cursor import (
    CursorBindings,
    CursorCodec,
    CursorRecoverySnapshot,
    CursorRejected,
    JournalCursorCandidate,
)
from .provenance import EventProvenance, ProvenanceProjection
from .query_contracts import QueryRequest, parse_utc_instant


class QuerySnapshotError(ValueError):
    """The supplied in-memory journal/recovery snapshot is not canonical truth."""


class QueryContextError(ValueError):
    """A query context cannot safely bind cursor recovery."""


class QueryEngineError(ValueError):
    """A query invocation does not satisfy the pure engine contract."""


def _is_sha256(value: object) -> bool:
    return type(value) is str and len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _sha256(value: object, label: str) -> str:
    if not _is_sha256(value):
        raise QueryContextError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _text(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise QueryContextError(f"{label} must be a non-empty string")
    try:
        value.encode("utf-8")
    except UnicodeError as error:
        raise QueryContextError(f"{label} must contain valid Unicode") from error
    return value


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        if any(type(key) is not str for key in value):
            raise QuerySnapshotError("canonical event mappings must have string keys")
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if value is None or type(value) is str or type(value) is bool or type(value) is int or type(value) is float:
        return value
    raise QuerySnapshotError("canonical event contains a non-JSON value")


def _clone_json_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        if any(type(key) is not str for key in value):
            raise QuerySnapshotError("canonical event mappings must have string keys")
        return {key: _clone_json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_clone_json_value(item) for item in value]
    if value is None or type(value) is str or type(value) is bool or type(value) is int or type(value) is float:
        return value
    raise QuerySnapshotError("canonical event contains a non-JSON value")


def _clone_envelope(value: Mapping[str, object]) -> dict[str, Any]:
    try:
        copied = _clone_json_value(value)
        validated = validate_journal_envelope(copied)
        return json.loads(canonical_bytes(validated).decode("utf-8"))
    except (TypeError, ValueError, UnicodeError, json.JSONDecodeError) as error:
        raise QuerySnapshotError("journal query snapshot contains an invalid canonical envelope") from error


def _chain_for(event: Mapping[str, object], previous: str) -> str:
    body = {
        "sequence": event["sequence"],
        "entry_id": event["entry_id"],
        "event_sha256": hashlib.sha256(canonical_bytes(event)).hexdigest(),
        "previous_chain_sha256": previous,
    }
    return canonical_hash(body)


@dataclass(frozen=True, slots=True, init=False)
class JournalQuerySnapshot:
    """Verified immutable envelopes plus the complete cursor recovery chain."""

    events: tuple[Mapping[str, object], ...]
    recovery_snapshot: CursorRecoverySnapshot

    def __init__(
        self,
        envelopes: Iterable[Mapping[str, object]],
        recovery: CursorRecoverySnapshot | Iterable[JournalCursorCandidate],
    ) -> None:
        try:
            copied_events = tuple(_clone_envelope(value) for value in envelopes)
        except TypeError as error:
            raise QuerySnapshotError("journal query envelopes must be iterable mappings") from error
        if isinstance(recovery, CursorRecoverySnapshot):
            raw_candidates = recovery.candidates
        else:
            try:
                raw_candidates = tuple(recovery)
            except TypeError as error:
                raise QuerySnapshotError("cursor recovery candidates must be iterable") from error
        if any(type(candidate) is not JournalCursorCandidate for candidate in raw_candidates):
            raise QuerySnapshotError("cursor recovery snapshot contains an invalid candidate")
        if any(
            type(candidate.sequence) is not int
            or candidate.sequence < 0
            or not _is_sha256(candidate.entry_id)
            or type(candidate.appended_at) is not datetime
            or candidate.appended_at.tzinfo is not timezone.utc
            or not _is_sha256(candidate.chain_sha256)
            for candidate in raw_candidates
        ):
            raise QuerySnapshotError("cursor recovery candidate scalars are invalid")

        events = tuple(sorted(copied_events, key=lambda event: event["sequence"]))
        candidates = tuple(sorted(raw_candidates, key=lambda candidate: candidate.sequence))
        if len(events) != len(candidates):
            raise QuerySnapshotError("journal envelopes and cursor candidates must be complete")
        previous = "0" * 64
        seen_entry_ids: set[str] = set()
        seen_chain_hashes: set[str] = set()
        copied_candidates: list[JournalCursorCandidate] = []
        for expected_sequence, (event, candidate) in enumerate(zip(events, candidates, strict=True)):
            if event["sequence"] != expected_sequence or candidate.sequence != expected_sequence:
                raise QuerySnapshotError("journal query snapshot sequences must be contiguous from zero")
            entry_id = event["entry_id"]
            if entry_id in seen_entry_ids:
                raise QuerySnapshotError("journal query snapshot entry IDs must be unique")
            expected_time = parse_utc_instant(event["appended_at"], "journal.appended_at")
            if candidate.entry_id != entry_id or candidate.appended_at != expected_time:
                raise QuerySnapshotError("cursor candidate does not exactly match its journal envelope")
            chain_sha256 = _chain_for(event, previous)
            if candidate.chain_sha256 != chain_sha256 or chain_sha256 in seen_chain_hashes:
                raise QuerySnapshotError("journal query snapshot chain is invalid")
            previous = chain_sha256
            seen_entry_ids.add(entry_id)
            seen_chain_hashes.add(chain_sha256)
            copied_candidates.append(
                JournalCursorCandidate(
                    sequence=candidate.sequence,
                    entry_id=candidate.entry_id,
                    appended_at=candidate.appended_at,
                    chain_sha256=candidate.chain_sha256,
                )
            )
        object.__setattr__(self, "events", tuple(_freeze(event) for event in events))
        object.__setattr__(self, "recovery_snapshot", CursorRecoverySnapshot(tuple(copied_candidates)))

    @property
    def envelopes(self) -> tuple[Mapping[str, object], ...]:
        return self.events

    @property
    def cursor_recovery_snapshot(self) -> CursorRecoverySnapshot:
        return self.recovery_snapshot

    @property
    def head(self) -> JournalCursorCandidate | None:
        return self.recovery_snapshot.candidates[-1] if self.recovery_snapshot.candidates else None


@dataclass(frozen=True, slots=True)
class QueryContext:
    """Service-generation and access-scoped provenance commitment material."""

    service_generation: str
    access_scoped_context_hash: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "service_generation", _text(self.service_generation, "service generation"))
        object.__setattr__(
            self,
            "access_scoped_context_hash",
            _sha256(self.access_scoped_context_hash, "access-scoped context hash"),
        )

    @property
    def query_context_hash(self) -> str:
        return self.access_scoped_context_hash

    @classmethod
    def from_projection(
        cls,
        service_generation: str,
        scope: PrincipalScope,
        snapshot: JournalQuerySnapshot,
        provenance: ProvenanceProjection,
    ) -> "QueryContext":
        if not isinstance(scope, PrincipalScope) or not isinstance(snapshot, JournalQuerySnapshot) or not isinstance(provenance, ProvenanceProjection):
            raise QueryContextError("query context requires a scope, snapshot, and provenance projection")
        return cls(service_generation, provenance.access_scoped_context_hash(scope, snapshot.events))


@dataclass(frozen=True, slots=True)
class QueryItem:
    """One authorized canonical event and only its authorized provenance."""

    event: Mapping[str, object]
    provenance: EventProvenance

    def __post_init__(self) -> None:
        if not isinstance(self.event, Mapping) or not isinstance(self.provenance, EventProvenance):
            raise QueryEngineError("query item is invalid")
        try:
            event = _freeze(_clone_envelope(self.event))
        except QuerySnapshotError as error:
            raise QueryEngineError("query item event is not a canonical journal envelope") from error
        object.__setattr__(self, "event", event)


@dataclass(frozen=True, slots=True)
class QueryPage:
    """A bounded, non-counting page with an optional opaque cursor."""

    items: tuple[QueryItem, ...]
    next_cursor: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.items, tuple) or any(not isinstance(item, QueryItem) for item in self.items):
            raise QueryEngineError("query page items are invalid")
        if self.next_cursor is not None:
            _text(self.next_cursor, "next cursor")


Page = QueryPage
EMPTY_QUERY_PAGE = QueryPage(())


@dataclass(frozen=True, slots=True)
class ReplayDedupeResult:
    """Pure consumer-side replay state; callers persist it only if they choose to."""

    new_entry_ids: tuple[str, ...]
    seen_entry_ids: frozenset[str]

    def __post_init__(self) -> None:
        if not isinstance(self.new_entry_ids, tuple) or any(not _is_sha256(value) for value in self.new_entry_ids):
            raise QueryEngineError("replay dedupe entry IDs are invalid")
        if not isinstance(self.seen_entry_ids, frozenset) or any(not _is_sha256(value) for value in self.seen_entry_ids):
            raise QueryEngineError("replay dedupe state is invalid")


def _replay_entry_ids(values: Iterable[str], label: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Iterable):
        raise QueryEngineError(f"{label} must be an iterable of entry IDs")
    try:
        copied = tuple(values)
    except TypeError as error:
        raise QueryEngineError(f"{label} must be an iterable of entry IDs") from error
    if any(not _is_sha256(value) for value in copied):
        raise QueryEngineError(f"{label} must contain canonical lowercase SHA-256 entry IDs")
    return copied


def dedupe_replay_entry_ids(
    entry_ids: Iterable[str],
    seen_entry_ids: Iterable[str] = (),
) -> ReplayDedupeResult:
    """Return accepted IDs and a new state set; never mutates or persists caller state."""

    incoming = _replay_entry_ids(entry_ids, "replay entry IDs")
    seen = frozenset(_replay_entry_ids(seen_entry_ids, "seen replay entry IDs"))
    new: list[str] = []
    state = set(seen)
    for entry_id in incoming:
        if entry_id not in state:
            new.append(entry_id)
            state.add(entry_id)
    return ReplayDedupeResult(tuple(new), frozenset(state))


def _matches_values(value: object, expected: tuple[str, ...] | None) -> bool:
    return expected is None or value in expected


def _matches_canonical(request: QueryRequest, event: Mapping[str, object], candidate: JournalCursorCandidate) -> bool:
    filters = request.filter
    if filters.time_range is not None and not filters.time_range.contains(candidate.appended_at):
        return False
    if filters.producer is not None:
        producer = event["producer"]
        if not isinstance(producer, Mapping):
            raise QueryEngineError("canonical event producer is invalid")
        if not all(
            _matches_values(producer.get(field), getattr(filters.producer, field))
            for field in ("owner_id", "capability", "run_id")
        ):
            return False
    if filters.entry_id is not None and candidate.entry_id not in filters.entry_id:
        return False
    if filters.source is not None:
        source = event["source"]
        if not isinstance(source, Mapping):
            raise QueryEngineError("canonical event source is invalid")
        if not _matches_values(source.get("provider"), filters.source.provider):
            return False
        if not _matches_values(source.get("canonical_url"), filters.source.canonical_url):
            return False
    artifact = event["artifact"]
    if not isinstance(artifact, Mapping):
        raise QueryEngineError("canonical event artifact is invalid")
    if filters.record_id is not None and artifact.get("record_id") not in filters.record_id:
        return False
    dedupe = event["dedupe"]
    if not isinstance(dedupe, Mapping):
        raise QueryEngineError("canonical event dedupe is invalid")
    if filters.object_key is not None and dedupe.get("object_key") not in filters.object_key:
        return False
    if filters.content_sha256 is not None and dedupe.get("content_sha256") not in filters.content_sha256:
        return False
    classification = event["classification"]
    if not isinstance(classification, Mapping):
        raise QueryEngineError("canonical event classification is invalid")
    if filters.classification is not None:
        if not _matches_values(classification.get("outcome"), filters.classification.outcome):
            return False
        if not _matches_values(classification.get("evidence_status"), filters.classification.evidence_status):
            return False
    return filters.access is None or event["access"] in filters.access


def _matches_provenance(request: QueryRequest, provenance: EventProvenance) -> bool:
    filters = request.filter
    if filters.lane is not None and (provenance.lane is None or provenance.lane.value not in filters.lane):
        return False
    if filters.topic is not None and not any(value.value in filters.topic for value in provenance.topics):
        return False
    return filters.entity is None or any(value.value in filters.entity for value in provenance.entities)


def _verified_context_hash(
    context: QueryContext,
    scope: PrincipalScope,
    snapshot: JournalQuerySnapshot,
    provenance: ProvenanceProjection,
    *,
    cursor_resume: bool,
) -> str:
    trusted_prefixes = provenance.access_scoped_context_hashes(scope, snapshot.events)
    if not cursor_resume:
        trusted = (
            trusted_prefixes[-1]
            if trusted_prefixes
            else provenance.access_scoped_context_hash(scope, ())
        )
        if not hmac.compare_digest(context.access_scoped_context_hash, trusted):
            raise QueryContextError("query context hash does not match trusted query inputs")
        return trusted

    for trusted in trusted_prefixes:
        if hmac.compare_digest(context.access_scoped_context_hash, trusted):
            return trusted
    raise CursorRejected()


class JournalQueryEngine:
    """Evaluate a request without filesystem, journal, projection, or server state."""

    def execute(
        self,
        request: QueryRequest,
        scope: PrincipalScope | None,
        snapshot: JournalQuerySnapshot,
        provenance: ProvenanceProjection,
        cursor_codec: CursorCodec,
        context: QueryContext,
    ) -> QueryPage:
        # This is deliberately before every other dereference: no cursor, body,
        # provenance, or metadata access is permitted for an unresolved scope.
        if scope is None:
            return EMPTY_QUERY_PAGE
        if not isinstance(scope, PrincipalScope):
            raise QueryEngineError("query scope must be a PrincipalScope or None")
        if not isinstance(snapshot, JournalQuerySnapshot):
            raise QueryEngineError("query snapshot must be a JournalQuerySnapshot")

        if not any(authorize_event_header(scope, event) for event in snapshot.events):
            return EMPTY_QUERY_PAGE

        if type(request) is not QueryRequest:
            raise QueryEngineError("query request must be a QueryRequest")
        if not isinstance(provenance, ProvenanceProjection):
            raise QueryEngineError("query provenance must be a ProvenanceProjection")
        if not isinstance(cursor_codec, CursorCodec):
            raise QueryEngineError("query cursor codec must be a CursorCodec")
        if not isinstance(context, QueryContext):
            raise QueryEngineError("query context must be a QueryContext")

        context_hash = _verified_context_hash(
            context,
            scope,
            snapshot,
            provenance,
            cursor_resume=request.cursor is not None,
        )
        bindings = CursorBindings(
            context.service_generation,
            request.filter_hash,
            scope.principal.subject,
            context_hash,
        )
        resume_after: tuple[datetime, int, str] | None = None
        high_watermark = snapshot.head
        if request.cursor is not None:
            recovery = cursor_codec.recover(request.cursor, bindings, snapshot.cursor_recovery_snapshot)
            resume_after = recovery.resume_after
            high_watermark = recovery.high_watermark
        if high_watermark is None:
            return EMPTY_QUERY_PAGE

        # Journal verification/recovery and canonical/provenance filtering are
        # intentionally O(N): the append-only journal is Slice 3B truth.
        # Retain only one page plus its continuation witness; QueryItem's
        # defensive clone is reserved for returned items.
        retained: list[tuple[tuple[datetime, int, str], Mapping[str, object], JournalCursorCandidate, EventProvenance]] = []
        capacity = request.limit + 1
        for event, candidate in zip(snapshot.events, snapshot.cursor_recovery_snapshot.candidates, strict=True):
            # The precise sequence is security material: header-only auth,
            # then HWM/resume, then canonical body filters, then provenance.
            if not authorize_event_header(scope, event):
                continue
            if candidate.sequence > high_watermark.sequence:
                continue
            if resume_after is not None and candidate.chronological_order <= resume_after:
                continue
            if not _matches_canonical(request, event, candidate):
                continue
            item_provenance = provenance.project(scope, event)
            if not _matches_provenance(request, item_provenance):
                continue
            value = (candidate.chronological_order, event, candidate, item_provenance)
            if len(retained) < capacity or value[0] < retained[-1][0]:
                position = bisect_left([item[0] for item in retained], value[0])
                retained.insert(position, value)
                if len(retained) > capacity:
                    retained.pop()
        selected = retained[: request.limit]
        if not selected:
            return EMPTY_QUERY_PAGE
        next_cursor = None
        if len(retained) > len(selected):
            next_cursor = cursor_codec.issue(bindings, last=selected[-1][2], high_watermark=high_watermark)
        return QueryPage(tuple(QueryItem(event, provenance) for _order, event, _candidate, provenance in selected), next_cursor)

    query = execute


QueryEngine = JournalQueryEngine


__all__ = [
    "EMPTY_QUERY_PAGE",
    "JournalQueryEngine",
    "JournalQuerySnapshot",
    "Page",
    "QueryContext",
    "QueryContextError",
    "QueryEngine",
    "QueryEngineError",
    "QueryItem",
    "QueryPage",
    "QuerySnapshotError",
    "ReplayDedupeResult",
    "dedupe_replay_entry_ids",
]
