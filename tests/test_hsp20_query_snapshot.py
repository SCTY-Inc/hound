"""HSP-20: immutable query snapshots and semantic cursor recovery."""

from __future__ import annotations

import hashlib
from dataclasses import FrozenInstanceError

import pytest

from houndd import (
    AuthenticatedPrincipal,
    CursorCodec,
    CursorKeyring,
    CursorRecoverySnapshot,
    CursorRejected,
    EventSelector,
    JournalCursorCandidate,
    PrincipalScope,
    ProducerSelector,
    QueryRequest,
    canonical_bytes,
    canonical_hash,
    make_journal_envelope,
    parse_query_filter,
)
from houndd.provenance import LaneRule, ProvenanceProjection
from houndd.query_engine import JournalQueryEngine, JournalQuerySnapshot, QueryContext, QuerySnapshotError


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _event(sequence: int, when: str) -> dict[str, object]:
    return make_journal_envelope(
        sequence=sequence,
        appended_at=when,
        producer={"owner_id": "owner", "capability": "capture", "run_id": f"run-{sequence}"},
        artifact={"kind": "capture", "schema": "houndd.capture.v1", "record_id": f"record-{sequence}", "hash": _digest(f"record-{sequence}"), "authorized_uri": "houndd://record"},
        lineage={"relation": "none", "record_id": f"record-{sequence}", "lead_id": "none"},
        source={"provider": "provider", "native_id": f"native-{sequence}", "canonical_url": f"https://example.test/{sequence}"},
        classification={"outcome": "completed", "evidence_status": "evidence"},
        access="public",
        policy_id=f"policy-{sequence}",
        dedupe={"object_key": f"object-{sequence}", "content_sha256": _digest(f"content-{sequence}")},
        usage={},
    )


def _recovery(events: list[dict[str, object]]) -> CursorRecoverySnapshot:
    chain = "0" * 64
    result = []
    for event in sorted(events, key=lambda item: item["sequence"]):
        body = {
            "sequence": event["sequence"],
            "entry_id": event["entry_id"],
            "event_sha256": hashlib.sha256(canonical_bytes(event)).hexdigest(),
            "previous_chain_sha256": chain,
        }
        chain = canonical_hash(body)
        result.append(JournalCursorCandidate(event["sequence"], event["entry_id"], event["appended_at"], chain))
    return CursorRecoverySnapshot(tuple(result))


def _scope(events: list[dict[str, object]]) -> PrincipalScope:
    return PrincipalScope(
        AuthenticatedPrincipal("peer:reader"),
        frozenset({"public"}),
        tuple(
            EventSelector(event["policy_id"], ProducerSelector(owner_id="owner", capability="capture"), frozenset({"public"}))
            for event in events
        ),
    )


def _materials(*, reverse: bool = False):
    events = [_event(0, "2026-07-31T02:00:00Z"), _event(1, "2026-07-31T01:00:00Z")]
    snapshot = JournalQuerySnapshot(list(reversed(events)) if reverse else events, _recovery(list(reversed(events)) if reverse else events))
    scope = _scope(events)
    provenance = ProvenanceProjection(tuple(LaneRule(event["policy_id"], "owner", "capture", "lane", source="policy") for event in events))
    context = QueryContext.from_projection("same-generation", scope, snapshot, provenance)
    return events, snapshot, scope, provenance, context


def _codec(keyring: CursorKeyring | None = None) -> CursorCodec:
    return CursorCodec(keyring or CursorKeyring("old", {"old": b"O" * 32}), nonce_source=lambda size: b"N" * size)


def _page(snapshot, scope, provenance, context, codec, *, cursor=None, limit=1):
    return JournalQueryEngine().execute(QueryRequest(parse_query_filter({}), limit=limit, cursor=cursor), scope, snapshot, provenance, codec, context)


def test_hsp20_snapshot_deeply_copies_and_freezes_canonical_events_and_candidates() -> None:
    events, snapshot, scope, provenance, context = _materials()
    original_chain = snapshot.head.chain_sha256 if snapshot.head else None
    events[0]["source"]["provider"] = "mutated-after-snapshot"
    with pytest.raises(TypeError):
        snapshot.events[0]["source"]["provider"] = "forged"  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        snapshot.events = ()  # type: ignore[misc]
    candidate = _recovery(events).candidates[0]
    object.__setattr__(candidate, "chain_sha256", _digest("tampered-after-snapshot"))
    page = _page(snapshot, scope, provenance, context, _codec())

    assert snapshot.events[0]["source"]["provider"] == "provider"
    assert snapshot.head is not None and snapshot.head.chain_sha256 == original_chain
    assert page.items[0].event["source"]["provider"] == "provider"
    with pytest.raises(FrozenInstanceError):
        page.items = ()  # type: ignore[misc]


@pytest.mark.parametrize("case", ["gap", "duplicate_entry", "duplicate_chain", "candidate_divergence", "truncation", "tampered_id", "tampered_envelope"])
def test_hsp20_snapshot_rejects_gaps_duplicates_divergence_and_tampering(case: str) -> None:
    events = [_event(0, "2026-07-31T00:00:00Z"), _event(1, "2026-07-31T01:00:00Z")]
    recovery = _recovery(events)
    if case == "gap":
        events = [_event(0, "2026-07-31T00:00:00Z"), _event(2, "2026-07-31T01:00:00Z")]
        recovery = _recovery(events)
    elif case == "duplicate_entry":
        events = [events[0], events[0]]
        recovery = CursorRecoverySnapshot((recovery.candidates[0], recovery.candidates[0]))
    elif case == "duplicate_chain":
        recovery = CursorRecoverySnapshot((recovery.candidates[0], JournalCursorCandidate(1, events[1]["entry_id"], events[1]["appended_at"], recovery.candidates[0].chain_sha256)))
    elif case == "candidate_divergence":
        recovery = CursorRecoverySnapshot((recovery.candidates[0], JournalCursorCandidate(1, _digest("different-entry"), events[1]["appended_at"], recovery.candidates[1].chain_sha256)))
    elif case == "truncation":
        recovery = CursorRecoverySnapshot((recovery.candidates[0],))
    elif case == "tampered_id":
        events[1]["entry_id"] = _digest("forged-entry-id")
    else:
        events[1]["source"]["provider"] = "forged-provider"
    with pytest.raises(QuerySnapshotError):
        JournalQuerySnapshot(events, recovery)


def test_hsp20_equivalent_rebuilt_snapshots_have_identical_manifests_and_semantic_cursor_recovery(tmp_path) -> None:
    events, first_snapshot, scope, provenance, context = _materials()
    _, second_snapshot, _, _, second_context = _materials(reverse=True)
    before = tuple(tmp_path.iterdir())
    first_codec = _codec()
    first_page = _page(first_snapshot, scope, provenance, context, first_codec)
    second_page = _page(second_snapshot, scope, provenance, second_context, _codec())
    restart_codec = _codec(CursorKeyring("old", {"old": b"O" * 32}))
    resumed = _page(second_snapshot, scope, provenance, context, restart_codec, cursor=first_page.next_cursor)

    assert context == second_context
    assert [item.event["entry_id"] for item in first_page.items] == [item.event["entry_id"] for item in second_page.items]
    assert first_page.next_cursor == second_page.next_cursor
    assert [item.event["entry_id"] for item in resumed.items] == [events[0]["entry_id"]]
    assert tuple(tmp_path.iterdir()) == before


def test_hsp20_key_overlap_recovers_same_generation_cursor_and_retirement_stays_generic() -> None:
    _, snapshot, scope, provenance, context = _materials()
    old_codec = _codec()
    first = _page(snapshot, scope, provenance, context, old_codec)
    overlap = _codec(CursorKeyring("new", {"new": b"N" * 32, "old": b"O" * 32}))
    assert _page(snapshot, scope, provenance, context, overlap, cursor=first.next_cursor).items
    retired = _codec(CursorKeyring("new", {"new": b"N" * 32}))
    with pytest.raises(CursorRejected) as rejected:
        _page(snapshot, scope, provenance, context, retired, cursor=first.next_cursor)
    assert type(rejected.value) is CursorRejected and str(rejected.value) == "cursor rejected"
