"""HSP-09: authorization ordering and non-disclosing pure query results."""

from __future__ import annotations

import hashlib

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
from houndd.provenance import AnnotationHeader, LaneRule, OwnerAnnotation, ProvenanceError, ProvenanceProjection
from houndd.query_engine import EMPTY_QUERY_PAGE, JournalQueryEngine, JournalQuerySnapshot, QueryContext


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _event(sequence: int, *, policy_id: str, owner: str, access: str, when: str, provider: str) -> dict[str, object]:
    return make_journal_envelope(
        sequence=sequence,
        appended_at=when,
        producer={"owner_id": owner, "capability": "capture", "run_id": f"run-{sequence}"},
        artifact={"kind": "capture", "schema": "houndd.capture.v1", "record_id": f"record-{sequence}", "hash": _digest(f"record-{sequence}"), "authorized_uri": "houndd://record"},
        lineage={"relation": "none", "record_id": f"record-{sequence}", "lead_id": "none"},
        source={"provider": provider, "native_id": f"native-{sequence}", "canonical_url": f"https://private.test/{sequence}"},
        classification={"outcome": "completed", "evidence_status": "evidence"},
        access=access,
        policy_id=policy_id,
        dedupe={"object_key": f"object-{sequence}", "content_sha256": _digest(f"body-{sequence}")},
        usage={},
    )


def _snapshot(events: list[dict[str, object]]) -> JournalQuerySnapshot:
    previous = "0" * 64
    candidates = []
    for event in events:
        chain_body = {
            "sequence": event["sequence"],
            "entry_id": event["entry_id"],
            "event_sha256": hashlib.sha256(canonical_bytes(event)).hexdigest(),
            "previous_chain_sha256": previous,
        }
        previous = canonical_hash(chain_body)
        candidates.append(JournalCursorCandidate(event["sequence"], event["entry_id"], event["appended_at"], previous))
    return JournalQuerySnapshot(events, CursorRecoverySnapshot(tuple(candidates)))


def _scope() -> PrincipalScope:
    return PrincipalScope(
        AuthenticatedPrincipal("transport:real-reader"),
        frozenset({"public"}),
        (EventSelector("policy-allowed", ProducerSelector(owner_id="allowed", capability="capture"), frozenset({"public"})),),
    )


def _codec() -> CursorCodec:
    return CursorCodec(CursorKeyring("key", {"key": b"S" * 32}), nonce_source=lambda size: b"Z" * size)


def _execute(request, scope, snapshot, provenance, context=None):
    if context is None and isinstance(scope, PrincipalScope):
        context = QueryContext.from_projection("generation", scope, snapshot, provenance)
    return JournalQueryEngine().execute(
        request,
        scope,
        snapshot,
        provenance,
        _codec(),
        context or QueryContext("generation", _digest("safe-context")),
    )


def test_hsp09_none_scope_returns_the_single_non_disclosing_empty_page_without_any_dereference() -> None:
    page = JournalQueryEngine().execute(object(), None, object(), object(), object(), object())  # type: ignore[arg-type]
    assert page is EMPTY_QUERY_PAGE
    assert page.items == () and page.next_cursor is None
    assert not hasattr(page, "count") and not hasattr(page, "total") and not hasattr(page, "metadata")


def test_hsp09_unauthorized_event_body_is_not_inspected_beyond_three_header_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    unauthorized = _event(0, policy_id="policy-hidden", owner="hidden", access="restricted", when="2026-07-31T00:00:00Z", provider="secret-provider")
    snapshot = _snapshot([unauthorized])

    class ObservedEvent(dict[str, object]):
        inspected: list[str]

        def __init__(self, body: dict[str, object]) -> None:
            super().__init__(body)
            self.inspected = []

        def __getitem__(self, key: str) -> object:
            self.inspected.append(key)
            if key not in {"access", "policy_id", "producer"}:
                raise AssertionError(f"unauthorized body field inspected: {key}")
            return super().__getitem__(key)

    observed = ObservedEvent(unauthorized)
    object.__setattr__(snapshot, "events", (observed,))
    project_called = False
    context_called = False
    recover_called = False
    original_project = ProvenanceProjection.project

    def project_spy(self, scope, event):
        nonlocal project_called
        project_called = True
        return original_project(self, scope, event)

    def context_spy(self, scope, events):
        nonlocal context_called
        context_called = True
        raise AssertionError("provenance context inspected for a scope with no authorized headers")

    def recover_spy(self, token, bindings, recovery):
        nonlocal recover_called
        recover_called = True
        raise AssertionError("cursor recovery called for a scope with no authorized headers")

    monkeypatch.setattr(ProvenanceProjection, "project", project_spy)
    monkeypatch.setattr(ProvenanceProjection, "access_scoped_context_hash", context_spy)
    monkeypatch.setattr(CursorCodec, "recover", recover_spy)
    page = _execute(
        QueryRequest(parse_query_filter({"source": {"provider": ["secret-provider"]}}), limit=1, cursor="opaque"),
        _scope(),
        snapshot,
        ProvenanceProjection(),
        QueryContext("generation", _digest("caller-chosen")),
    )

    assert page is EMPTY_QUERY_PAGE
    assert set(observed.inspected) == {"access", "policy_id", "producer"}
    assert project_called is False
    assert context_called is False
    assert recover_called is False


def test_hsp09_unauthorized_and_nonexistent_entry_or_topic_are_the_same_empty_shape() -> None:
    hidden = _event(0, policy_id="policy-hidden", owner="hidden", access="restricted", when="2026-07-31T00:00:00Z", provider="secret-provider")
    snapshot = _snapshot([hidden])
    projection = ProvenanceProjection()
    scope = _scope()

    pages = (
        _execute(QueryRequest(parse_query_filter({"entry_id": [hidden["entry_id"]]}), limit=1), scope, snapshot, projection),
        _execute(QueryRequest(parse_query_filter({"entry_id": [_digest("absent")]}), limit=1), scope, snapshot, projection),
        _execute(QueryRequest(parse_query_filter({"topic": ["hidden-topic"]}), limit=1), scope, snapshot, projection),
        _execute(QueryRequest(parse_query_filter({}), limit=1), None, snapshot, projection),
    )
    assert all(page is EMPTY_QUERY_PAGE for page in pages)


def test_hsp09_forged_request_producer_filter_never_replaces_the_authenticated_scope() -> None:
    allowed = _event(0, policy_id="policy-allowed", owner="allowed", access="public", when="2026-07-31T00:00:00Z", provider="visible")
    hidden = _event(1, policy_id="policy-hidden", owner="hidden", access="public", when="2026-07-31T00:01:00Z", provider="hidden")
    snapshot = _snapshot([allowed, hidden])
    request = QueryRequest(parse_query_filter({"producer": {"owner_id": ["hidden"]}}), limit=1)
    page = _execute(request, _scope(), snapshot, ProvenanceProjection())
    assert page is EMPTY_QUERY_PAGE


def test_hsp09_unauthorized_annotation_cannot_change_results_filters_cursors_or_context() -> None:
    event = _event(0, policy_id="policy-allowed", owner="allowed", access="public", when="2026-07-31T01:00:00Z", provider="visible")
    earlier = _event(1, policy_id="policy-allowed", owner="allowed", access="public", when="2026-07-31T00:00:00Z", provider="also-visible")
    snapshot = _snapshot([event, earlier])
    lane = LaneRule("policy-allowed", "allowed", "capture", "public-lane", source="policy")
    denied = OwnerAnnotation(
        "topic",
        earlier["entry_id"],
        "visible-topic",
        AnnotationHeader("restricted", "policy-hidden", ProducerClaim("hidden", "capture", "annotation")),
        source="hidden-owner",
    )
    visible = OwnerAnnotation(
        "topic",
        event["entry_id"],
        "visible-topic",
        AnnotationHeader("public", "policy-allowed", ProducerClaim("allowed", "capture", "run-0")),
        source="allowed-owner",
    )
    base = ProvenanceProjection((lane,), (visible,))
    with_denied = ProvenanceProjection((lane,), (visible, denied))
    scope = _scope()
    assert base.access_scoped_context_hash(scope, snapshot.events) == with_denied.access_scoped_context_hash(scope, snapshot.events)
    context = QueryContext.from_projection("generation", scope, snapshot, with_denied)
    base_context = QueryContext.from_projection("generation", scope, snapshot, base)
    base_unfiltered = _execute(QueryRequest(parse_query_filter({}), limit=1), scope, snapshot, base, base_context)
    with_denied_unfiltered = _execute(QueryRequest(parse_query_filter({}), limit=1), scope, snapshot, with_denied, context)
    base_filtered = _execute(QueryRequest(parse_query_filter({"topic": ["visible-topic"]}), limit=1), scope, snapshot, base, base_context)
    with_denied_filtered = _execute(QueryRequest(parse_query_filter({"topic": ["visible-topic"]}), limit=1), scope, snapshot, with_denied, context)

    assert [item.event["entry_id"] for item in base_unfiltered.items] == [earlier["entry_id"]]
    assert [item.event["entry_id"] for item in with_denied_unfiltered.items] == [earlier["entry_id"]]
    assert base_unfiltered.next_cursor == with_denied_unfiltered.next_cursor
    assert base_unfiltered.next_cursor is not None
    assert [item.event["entry_id"] for item in base_filtered.items] == [event["entry_id"]]
    assert [item.event["entry_id"] for item in with_denied_filtered.items] == [event["entry_id"]]
    assert base_filtered.next_cursor is None and with_denied_filtered.next_cursor is None


@pytest.mark.parametrize(
    "header",
    [
        AnnotationHeader("public", "policy-other", ProducerClaim("allowed", "capture", "run-0")),
        AnnotationHeader("public", "policy-allowed", ProducerClaim("other", "capture", "run-0")),
        AnnotationHeader("public", "policy-allowed", ProducerClaim("allowed", "capture", "other-run")),
    ],
)
def test_hsp09_authorized_annotation_must_match_target_event_policy_and_producer(header: AnnotationHeader) -> None:
    event = _event(0, policy_id="policy-allowed", owner="allowed", access="public", when="2026-07-31T00:00:00Z", provider="visible")
    scope = PrincipalScope(
        AuthenticatedPrincipal("transport:real-reader"),
        frozenset({"public"}),
        (
            EventSelector("policy-allowed", ProducerSelector(owner_id="allowed", capability="capture"), frozenset({"public"})),
            EventSelector(header.policy_id, ProducerSelector(owner_id=header.producer.owner_id, capability=header.producer.capability), frozenset({"public"})),
        ),
    )
    projection = ProvenanceProjection(
        owner_annotations=(
            OwnerAnnotation("topic", event["entry_id"], "cross-boundary", header, source="owner"),
        )
    )

    with pytest.raises(ProvenanceError, match="target"):
        projection.project(scope, event)


def test_hsp09_tampered_or_conflicting_provenance_artifacts_fail_closed() -> None:
    rule = LaneRule("policy-allowed", "allowed", "capture", "one", source="policy")
    object.__setattr__(rule, "provenance_id", _digest("forged"))
    with pytest.raises(ProvenanceError):
        ProvenanceProjection((rule,))

    with pytest.raises(ProvenanceError):
        ProvenanceProjection(
            (
                LaneRule("policy-allowed", "allowed", "capture", "one", source="policy-one"),
                LaneRule("policy-allowed", "allowed", "capture", "two", source="policy-two"),
            )
        )
