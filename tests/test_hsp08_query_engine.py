"""HSP-08: pure authorized query evaluation and consumer replay dedupe."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import pytest

from houndd import (
    AuthenticatedPrincipal,
    CursorCodec,
    CursorKeyring,
    CursorRecoverySnapshot,
    EventSelector,
    JournalCursorCandidate,
    PrincipalScope,
    ProducerClaim,
    ProducerSelector,
    QueryRequest,
    canonical_bytes,
    canonical_hash,
    make_journal_envelope,
    parse_query_filter,
)
from houndd.provenance import AnnotationHeader, LaneRule, OwnerAnnotation, ProvenanceProjection
from houndd.query_engine import (
    JournalQueryEngine,
    JournalQuerySnapshot,
    QueryContext,
    QueryEngineError,
    QueryItem,
    dedupe_replay_entry_ids,
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _event(
    sequence: int,
    *,
    when: str,
    access: str,
    run_id: str,
    provider: str,
    url: str,
    outcome: str,
    evidence_status: str,
    policy_id: str,
) -> dict[str, object]:
    return make_journal_envelope(
        sequence=sequence,
        appended_at=when,
        producer={"owner_id": "owner", "capability": "capture", "run_id": run_id},
        artifact={
            "kind": "capture",
            "schema": "houndd.capture.v1",
            "record_id": f"record-{sequence}",
            "hash": _digest(f"record-{sequence}"),
            "authorized_uri": f"houndd://record/{sequence}",
        },
        lineage={"relation": "none", "record_id": f"lineage-record-{sequence}", "lead_id": "none"},
        source={"provider": provider, "native_id": f"native-{sequence}", "canonical_url": url},
        classification={"outcome": outcome, "evidence_status": evidence_status},
        access=access,
        policy_id=policy_id,
        dedupe={"object_key": f"object-{sequence}", "content_sha256": _digest(f"content-{sequence}")},
        usage={},
    )


def _candidates(events: list[dict[str, object]]) -> CursorRecoverySnapshot:
    previous = "0" * 64
    candidates = []
    for event in sorted(events, key=lambda value: value["sequence"]):
        body = {
            "sequence": event["sequence"],
            "entry_id": event["entry_id"],
            "event_sha256": hashlib.sha256(canonical_bytes(event)).hexdigest(),
            "previous_chain_sha256": previous,
        }
        previous = canonical_hash(body)
        candidates.append(
            JournalCursorCandidate(
                sequence=event["sequence"],
                entry_id=event["entry_id"],
                appended_at=event["appended_at"],
                chain_sha256=previous,
            )
        )
    return CursorRecoverySnapshot(tuple(candidates))


def _scope(policy_ids: tuple[str, ...]) -> PrincipalScope:
    return PrincipalScope(
        AuthenticatedPrincipal("peer:reader"),
        frozenset({"public", "workspace", "restricted"}),
        tuple(
            EventSelector(
                policy_id,
                ProducerSelector(owner_id="owner", capability="capture"),
                frozenset({"public", "workspace", "restricted"}),
            )
            for policy_id in sorted(set(policy_ids))
        ),
    )


def _projection(events: list[dict[str, object]]) -> ProvenanceProjection:
    lanes = ("pulse", "benefits", "radar", "radar", "pulse", "benefits")[: len(events)]
    topics = ("care", "access", "care", "policy", "care", "access")[: len(events)]
    entities = ("entity-a", "entity-b", "entity-c", "entity-c", "entity-d", "entity-e")[: len(events)]
    annotations = tuple(
        annotation
        for event, topic, entity in zip(events, topics, entities, strict=True)
        for annotation in (
            OwnerAnnotation(
                "topic",
                event["entry_id"],
                topic,
                AnnotationHeader("workspace", event["policy_id"], ProducerClaim("owner", "capture", event["producer"]["run_id"])),
                source="owner:topics",
            ),
            OwnerAnnotation(
                "entity",
                event["entry_id"],
                entity,
                AnnotationHeader("workspace", event["policy_id"], ProducerClaim("owner", "capture", event["producer"]["run_id"])),
                source="owner:entities",
            ),
        )
    )
    return ProvenanceProjection(
        tuple(
            LaneRule(event["policy_id"], "owner", "capture", lane, source=f"policy:{lane}")
            for event, lane in zip(events, lanes, strict=True)
        ),
        annotations,
    )


def _matrix(*, include_e6: bool = False, reverse: bool = False):
    events = [
        _event(0, when="2026-07-31T03:00:00Z", access="public", run_id="run-1", provider="exa", url="https://a.test/1", outcome="completed", evidence_status="evidence", policy_id="policy-pulse-a"),
        _event(1, when="2026-07-31T01:30:00Z", access="workspace", run_id="run-2", provider="firecrawl", url="https://a.test/2", outcome="partial", evidence_status="partial", policy_id="policy-benefits-a"),
        _event(2, when="2026-07-31T02:00:00Z", access="restricted", run_id="run-3", provider="exa", url="https://a.test/3", outcome="completed", evidence_status="evidence", policy_id="policy-radar-a"),
        _event(3, when="2026-07-31T02:00:00Z", access="public", run_id="run-4", provider="firecrawl", url="https://a.test/4", outcome="failed", evidence_status="failure", policy_id="policy-radar-b"),
        _event(4, when="2026-07-31T04:00:00Z", access="workspace", run_id="run-5", provider="exa", url="https://a.test/5", outcome="completed", evidence_status="evidence", policy_id="policy-pulse-b"),
    ]
    if include_e6:
        events.append(_event(5, when="2026-07-31T00:30:00Z", access="restricted", run_id="run-6", provider="exa", url="https://a.test/6", outcome="completed", evidence_status="evidence", policy_id="policy-benefits-b"))
    presentation = list(reversed(events)) if reverse else events
    snapshot = JournalQuerySnapshot(presentation, _candidates(events))
    projection = _projection(events)
    scope = _scope(tuple(event["policy_id"] for event in events))
    context = QueryContext.from_projection("generation-1", scope, snapshot, projection)
    codec = CursorCodec(CursorKeyring("active", {"active": b"K" * 32}), nonce_source=lambda size: b"N" * size)
    return events, snapshot, projection, scope, context, codec


def _query(
    request: QueryRequest,
    snapshot: JournalQuerySnapshot,
    projection: ProvenanceProjection,
    scope: PrincipalScope,
    context: QueryContext,
    codec: CursorCodec,
):
    return JournalQueryEngine().execute(request, scope, snapshot, projection, codec, context)


def _ids(page) -> list[str]:
    return [item.event["entry_id"] for item in page.items]


def test_hsp08_six_event_matrix_orders_chronologically_and_is_insertion_independent() -> None:
    events, snapshot, projection, scope, context, codec = _matrix(reverse=True)
    page = _query(QueryRequest(parse_query_filter({}), limit=10), snapshot, projection, scope, context, codec)

    assert _ids(page) == [events[index]["entry_id"] for index in (1, 2, 3, 0, 4)]
    assert [item.provenance.lane.value for item in page.items] == ["benefits", "radar", "radar", "pulse", "pulse"]
    assert page.next_cursor is None
    assert not hasattr(page, "count") and not hasattr(page, "total") and not hasattr(page, "snippet")


@pytest.mark.parametrize(
    ("filter_value", "expected"),
    [
        ({"producer": {"owner_id": ["owner"], "capability": ["capture"], "run_id": ["run-2"]}}, [1]),
        ({"lane": ["radar"]}, [2, 3]),
        ({"topic": ["access"]}, [1]),
        ({"source": {"provider": ["firecrawl"]}}, [1, 3]),
        ({"source": {"canonical_url": ["https://a.test/3"]}}, [2]),
        ({"entity": ["entity-c"]}, [2, 3]),
        ({"record_id": ["record-4"]}, [4]),
        ({"object_key": ["object-0"]}, [0]),
        ({"content_sha256": [_digest("content-3")]}, [3]),
        ({"classification": {"outcome": ["completed"]}}, [2, 0, 4]),
        ({"classification": {"evidence_status": ["failure"]}}, [3]),
        ({"access": ["restricted"]}, [2]),
    ],
)
def test_hsp08_every_canonical_and_provenance_filter_family(filter_value, expected) -> None:
    events, snapshot, projection, scope, context, codec = _matrix()
    page = _query(QueryRequest(parse_query_filter(filter_value), limit=10), snapshot, projection, scope, context, codec)
    assert _ids(page) == [events[index]["entry_id"] for index in expected]


def test_hsp08_record_id_uses_artifact_identity_not_lineage_identity() -> None:
    events, snapshot, projection, scope, context, codec = _matrix()
    assert events[4]["artifact"]["record_id"] == "record-4"
    assert events[4]["lineage"]["record_id"] == "lineage-record-4"

    artifact_match = _query(
        QueryRequest(parse_query_filter({"record_id": ["record-4"]}), limit=10),
        snapshot,
        projection,
        scope,
        context,
        codec,
    )
    lineage_non_match = _query(
        QueryRequest(parse_query_filter({"record_id": ["lineage-record-4"]}), limit=10),
        snapshot,
        projection,
        scope,
        context,
        codec,
    )

    assert _ids(artifact_match) == [events[4]["entry_id"]]
    assert _ids(lineage_non_match) == []


def test_hsp08_entry_id_or_and_cross_family_and_time_bounds_are_exact() -> None:
    events, snapshot, projection, scope, context, codec = _matrix()
    request = QueryRequest(
        parse_query_filter(
            {
                "time_range": {"from": "2026-07-31T02:00:00Z", "to": "2026-07-31T04:00:00Z"},
                "entry_id": [events[2]["entry_id"], events[3]["entry_id"], events[4]["entry_id"]],
                "source": {"provider": ["exa", "firecrawl"]},
                "lane": ["radar", "pulse"],
            }
        ),
        limit=10,
    )
    page = _query(request, snapshot, projection, scope, context, codec)
    assert _ids(page) == [events[2]["entry_id"], events[3]["entry_id"]]


def test_hsp08_fixed_hwm_multi_page_replay_has_no_loss_or_duplication_and_excludes_concurrent_e6() -> None:
    old_events, old_snapshot, projection, _, _, codec = _matrix()
    all_events, new_snapshot, new_projection, scope, _, _ = _matrix(include_e6=True)
    old_context = QueryContext.from_projection("generation-1", scope, old_snapshot, projection)
    first = _query(QueryRequest(parse_query_filter({}), limit=2), old_snapshot, projection, scope, old_context, codec)
    assert first.next_cursor is not None

    second = _query(QueryRequest(parse_query_filter({}), limit=2, cursor=first.next_cursor), new_snapshot, new_projection, scope, old_context, codec)
    third = _query(QueryRequest(parse_query_filter({}), limit=2, cursor=second.next_cursor), new_snapshot, new_projection, scope, old_context, codec)

    seen = _ids(first) + _ids(second) + _ids(third)
    assert seen == [old_events[index]["entry_id"] for index in (1, 2, 3, 0, 4)]
    assert all_events[5]["entry_id"] not in seen
    assert third.next_cursor is None


def test_hsp08_chronological_resume_can_follow_a_higher_sequence_with_an_earlier_timestamp() -> None:
    events, snapshot, projection, scope, context, codec = _matrix(include_e6=True)
    first = _query(QueryRequest(parse_query_filter({}), limit=1), snapshot, projection, scope, context, codec)
    second = _query(QueryRequest(parse_query_filter({}), limit=1, cursor=first.next_cursor), snapshot, projection, scope, context, codec)

    assert _ids(first) == [events[5]["entry_id"]]
    assert _ids(second) == [events[1]["entry_id"]]


def test_hsp08_pure_replay_dedupe_uses_only_entry_ids_and_returns_new_state() -> None:
    first = (_digest("a"), _digest("b"), _digest("a"))
    result = dedupe_replay_entry_ids(first, (_digest("b"),))
    assert result.new_entry_ids == (_digest("a"),)
    assert result.seen_entry_ids == frozenset({_digest("a"), _digest("b")})
    assert first == (_digest("a"), _digest("b"), _digest("a"))


@pytest.mark.parametrize(
    ("entry_ids", "seen_entry_ids"),
    [
        (_digest("incoming"), ()),
        (_digest("incoming").encode("ascii"), ()),
        ((_digest("incoming"),), _digest("seen")),
        ((_digest("incoming"),), _digest("seen").encode("ascii")),
        (("A" * 64,), ()),
        (("f" * 63,), ()),
        (("g" * 64,), ()),
        ((_digest("incoming"),), ("A" * 64,)),
    ],
)
def test_hsp08_replay_dedupe_requires_collections_of_canonical_entry_ids(entry_ids, seen_entry_ids) -> None:
    with pytest.raises(QueryEngineError):
        dedupe_replay_entry_ids(entry_ids, seen_entry_ids)


def test_hsp08_direct_query_item_clones_and_deeply_freezes_its_event() -> None:
    events, snapshot, projection, scope, _, _ = _matrix()
    event = events[0]
    item = QueryItem(event, projection.project(scope, snapshot.events[0]))

    event["source"]["provider"] = "mutated-after-construction"

    assert item.event["source"]["provider"] == "exa"
    with pytest.raises(TypeError):
        item.event["source"]["provider"] = "forged"  # type: ignore[index]
