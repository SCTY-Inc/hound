"""B14: descending journal.query with unchanged cursor integrity guarantees.

Every test here holds one of four lines: the request contract stays additive,
descending selection is exactly the reverse of ascending selection over the
same watermark, a cursor belongs to the order that issued it, and a descending
chain pins to its issue-time high-watermark like an ascending chain does.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

import pytest

from houndd import HounddStore
from houndd.access import AuthenticatedPrincipal, EventSelector, PrincipalScope, ProducerSelector
from houndd.contracts import canonical_bytes, make_journal_envelope
from houndd.cursor import CursorRejected
from houndd.journal import Journal
from houndd.query_contracts import (
    QueryContractError,
    QueryRequest,
    parse_query_filter,
    parse_query_request,
)
from houndd.query_engine import QueryEngineError
from houndd.service_identity import ServiceIdentity
from houndd.snapshot import DurableJournalQueryAdapter


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _event(sequence: int, *, when: str, access: str = "public", provider: str = "exa") -> dict[str, object]:
    return make_journal_envelope(
        sequence=sequence,
        appended_at=when,
        producer={"owner_id": "owner", "capability": "capture", "run_id": f"run-{sequence}"},
        artifact={
            "kind": "capture",
            "schema": "houndd.capture.v1",
            "record_id": f"record-{sequence}",
            "hash": _digest(f"record-{sequence}"),
            "authorized_uri": f"houndd://records/{sequence}",
        },
        lineage={"relation": "none", "record_id": f"lineage-{sequence}", "lead_id": "none"},
        source={
            "provider": provider,
            "native_id": f"native-{sequence}",
            "canonical_url": f"https://example.test/{sequence}",
        },
        classification={"outcome": "completed", "evidence_status": "evidence"},
        access=access,
        policy_id="policy",
        dedupe={"object_key": f"object-{sequence}", "content_sha256": _digest(f"content-{sequence}")},
        usage={},
    )


# Deliberately not monotonic in time: two entries share an instant and the
# journal order is not the chronological order, so an order flip that merely
# reverses the sequence walk cannot pass.
_TIMES = (
    "2026-07-31T03:00:00Z",
    "2026-07-31T01:30:00Z",
    "2026-07-31T02:00:00Z",
    "2026-07-31T02:00:00Z",
    "2026-07-31T04:00:00Z",
    "2026-07-31T00:30:00Z",
    "2026-07-31T05:00:00Z",
)


def _scope(subject: str = "peer:reader") -> PrincipalScope:
    return PrincipalScope(
        AuthenticatedPrincipal(subject),
        frozenset({"public", "workspace", "restricted"}),
        (
            EventSelector(
                "policy",
                ProducerSelector(owner_id="owner", capability="capture"),
                frozenset({"public", "workspace", "restricted"}),
            ),
        ),
    )


def _store(root: Path, *, count: int = 6) -> tuple[Journal, DurableJournalQueryAdapter]:
    journal = Journal(root)
    for sequence in range(count):
        journal.append(_event(sequence, when=_TIMES[sequence]))
    identity = ServiceIdentity(root, create=True)
    return journal, DurableJournalQueryAdapter(journal, identity, nonce_source=lambda size: b"N" * size)


def _request(*, limit: int = 10, order: str = "ascending", cursor: str | None = None) -> QueryRequest:
    return QueryRequest(parse_query_filter({}), limit, cursor, None, order)


def _ids(page) -> list[str]:
    return [item.event["entry_id"] for item in page.items]


def _drain(adapter: DurableJournalQueryAdapter, scope: PrincipalScope, *, limit: int, order: str) -> tuple[list[str], int]:
    """Walk a whole chain, returning its entry IDs and the page count."""

    collected: list[str] = []
    cursor: str | None = None
    pages = 0
    while True:
        page = adapter.execute(_request(limit=limit, order=order, cursor=cursor), scope)
        pages += 1
        collected.extend(_ids(page))
        cursor = page.next_cursor
        if cursor is None:
            return collected, pages
        assert pages < 50, "drain did not terminate"


# --- request contract: additive, closed-shape, old requests unchanged --------


def test_b14_order_absent_is_exactly_todays_request() -> None:
    absent = parse_query_request({"filter": {}, "limit": 10})
    explicit = parse_query_request({"filter": {}, "limit": 10, "order": "ascending"})

    assert absent.order == "ascending"
    assert absent.descending is False
    assert absent.canonical == {"filter": {}, "limit": 10}
    assert explicit.canonical == absent.canonical


def test_b14_descending_is_carried_on_the_request_and_its_canonical_form() -> None:
    request = parse_query_request({"filter": {}, "limit": 10, "order": "descending"})

    assert request.order == "descending"
    assert request.descending is True
    assert request.canonical == {"filter": {}, "limit": 10, "order": "descending"}


@pytest.mark.parametrize(
    "order",
    [
        "Ascending",
        "DESCENDING",
        " descending",
        "descending ",
        "desc",
        "reverse",
        "",
        None,
        True,
        1,
        -1,
        ["descending"],
        {"order": "descending"},
    ],
)
def test_b14_order_is_a_closed_shape(order) -> None:
    with pytest.raises(QueryContractError):
        parse_query_request({"filter": {}, "limit": 10, "order": order})
    with pytest.raises(QueryContractError):
        QueryRequest(parse_query_filter({}), 10, None, None, order)


def test_b14_a_string_subclass_is_not_an_accepted_order() -> None:
    class _Order(str):
        pass

    with pytest.raises(QueryContractError):
        parse_query_request({"filter": {}, "limit": 10, "order": _Order("descending")})


def test_b14_ascending_cursor_domain_is_byte_for_byte_unchanged() -> None:
    """The pre-B14 cursor domain must survive: in-flight cursors stay valid."""

    query_filter = parse_query_filter({"access": ["public"], "source": {"provider": ["exa"]}})
    # The exact digest a pre-B14 request produced: sha256 of the canonical
    # filter object, with no discriminator of any kind.
    legacy = hashlib.sha256(
        json.dumps(query_filter.canonical, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()

    assert QueryRequest(query_filter, 10).filter_hash == legacy
    assert QueryRequest(query_filter, 10, None, None, "ascending").filter_hash == legacy
    assert parse_query_request({"filter": {"access": ["public"], "source": {"provider": ["exa"]}}}).filter_hash == legacy


def test_b14_ledger_view_cursor_domain_is_byte_for_byte_unchanged() -> None:
    query_filter = parse_query_filter({})
    legacy = hashlib.sha256(
        json.dumps(
            {"filter": query_filter.canonical, "view": "intake-ledger.v1"},
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()

    assert QueryRequest(query_filter, 10, None, "intake-ledger.v1").filter_hash == legacy
    assert QueryRequest(query_filter, 10, None, "intake-ledger.v1", "ascending").filter_hash == legacy


def test_b14_each_order_and_view_combination_gets_its_own_cursor_domain() -> None:
    query_filter = parse_query_filter({})
    hashes = {
        (view, order): QueryRequest(query_filter, 10, None, view, order).filter_hash
        for view in (None, "intake-ledger.v1")
        for order in ("ascending", "descending")
    }

    assert len(set(hashes.values())) == 4
    # The limit and the cursor are not part of the domain, in either order.
    assert QueryRequest(query_filter, 1, None, None, "descending").filter_hash == hashes[(None, "descending")]


# --- selection equivalence and pagination -----------------------------------


def test_b14_descending_drain_equals_reversed_ascending_drain(tmp_path: Path) -> None:
    _journal, adapter = _store(tmp_path / "state")
    scope = _scope()

    ascending, _ = _drain(adapter, scope, limit=100, order="ascending")
    descending, _ = _drain(adapter, scope, limit=100, order="descending")

    assert len(ascending) == 6
    assert descending == list(reversed(ascending))


@pytest.mark.parametrize("limit", [1, 2, 3, 4, 5, 6, 7])
def test_b14_descending_paginates_to_the_same_sequence_at_every_boundary(tmp_path: Path, limit: int) -> None:
    _journal, adapter = _store(tmp_path / "state")
    scope = _scope()

    whole, _ = _drain(adapter, scope, limit=100, order="descending")
    paged, pages = _drain(adapter, scope, limit=limit, order="descending")

    assert paged == whole
    assert len(set(paged)) == len(paged)
    assert pages == max(1, -(-len(whole) // limit))


def test_b14_a_drained_descending_chain_reports_no_continuation(tmp_path: Path) -> None:
    """The final page must not hand back a cursor that would replay the oldest entry."""

    _journal, adapter = _store(tmp_path / "state", count=4)
    scope = _scope()

    first = adapter.execute(_request(limit=3, order="descending"), scope)
    assert first.next_cursor is not None
    second = adapter.execute(_request(limit=3, order="descending", cursor=first.next_cursor), scope)

    assert len(second.items) == 1
    assert second.next_cursor is None


def test_b14_first_descending_page_is_the_newest_entries_in_one_exchange(tmp_path: Path) -> None:
    _journal, adapter = _store(tmp_path / "state")
    scope = _scope()

    newest = adapter.execute(_request(limit=2, order="descending"), scope)

    assert [item.event["appended_at"] for item in newest.items] == ["2026-07-31T04:00:00Z", "2026-07-31T03:00:00Z"]


def test_b14_descending_respects_filters_and_limits(tmp_path: Path) -> None:
    _journal, adapter = _store(tmp_path / "state")
    scope = _scope()
    selector = {"time_range": {"from": "2026-07-31T01:00:00Z", "to": "2026-07-31T03:00:00Z"}}

    ascending = adapter.execute(QueryRequest(parse_query_filter(selector), 10, None, None, "ascending"), scope)
    descending = adapter.execute(QueryRequest(parse_query_filter(selector), 10, None, None, "descending"), scope)

    assert len(descending.items) == 3
    assert _ids(descending) == list(reversed(_ids(ascending)))


def test_b14_an_empty_authorized_result_has_no_descending_cursor(tmp_path: Path) -> None:
    _journal, adapter = _store(tmp_path / "state")
    scope = _scope()
    empty = adapter.execute(
        QueryRequest(parse_query_filter({"source": {"provider": ["absent"]}}), 10, None, None, "descending"),
        scope,
    )

    assert empty.items == ()
    assert empty.next_cursor is None


def test_b14_execute_bounded_does_not_drop_the_order(tmp_path: Path) -> None:
    """execute_bounded rebuilds the request per fitting pass; order must survive."""

    _journal, adapter = _store(tmp_path / "state")
    scope = _scope()

    bounded = adapter.execute_bounded(_request(limit=3, order="descending"), scope, lambda page: True)
    direct = adapter.execute(_request(limit=3, order="descending"), scope)

    assert bounded is not None
    assert _ids(bounded) == _ids(direct)
    assert _ids(bounded) != _ids(adapter.execute(_request(limit=3, order="ascending"), scope))


def test_b14_execute_bounded_shrinks_a_descending_page_without_reordering(tmp_path: Path) -> None:
    _journal, adapter = _store(tmp_path / "state")
    scope = _scope()
    whole = _ids(adapter.execute(_request(limit=10, order="descending"), scope))

    bounded = adapter.execute_bounded(_request(limit=10, order="descending"), scope, lambda page: len(page.items) <= 2)

    assert bounded is not None
    assert _ids(bounded) == whole[:2]
    assert bounded.next_cursor is not None


def test_b14_ledger_view_supports_descending(tmp_path: Path) -> None:
    _journal, adapter = _store(tmp_path / "state")
    scope = _scope()
    request = QueryRequest(parse_query_filter({}), 3, None, "intake-ledger.v1", "descending")

    result = adapter.execute_ledger_bounded(request, scope, lambda page, watermark: True)

    assert result is not None
    page, _watermark = result
    assert _ids(page) == _ids(adapter.execute(_request(limit=3, order="descending"), scope))


# --- cursor integrity -------------------------------------------------------


def test_b14_an_ascending_cursor_is_rejected_by_a_descending_query(tmp_path: Path) -> None:
    _journal, adapter = _store(tmp_path / "state")
    scope = _scope()
    ascending = adapter.execute(_request(limit=2, order="ascending"), scope)
    assert ascending.next_cursor is not None

    with pytest.raises(CursorRejected):
        adapter.execute(_request(limit=2, order="descending", cursor=ascending.next_cursor), scope)


def test_b14_a_descending_cursor_is_rejected_by_an_ascending_query(tmp_path: Path) -> None:
    _journal, adapter = _store(tmp_path / "state")
    scope = _scope()
    descending = adapter.execute(_request(limit=2, order="descending"), scope)
    assert descending.next_cursor is not None

    with pytest.raises(CursorRejected):
        adapter.execute(_request(limit=2, order="ascending", cursor=descending.next_cursor), scope)


def test_b14_cross_order_reuse_is_rejected_not_reinterpreted(tmp_path: Path) -> None:
    """A rejected cross-order cursor must never silently degrade into a page."""

    _journal, adapter = _store(tmp_path / "state")
    scope = _scope()
    descending = adapter.execute(_request(limit=2, order="descending"), scope)

    with pytest.raises(CursorRejected):
        adapter.execute_bounded(
            _request(limit=2, order="ascending", cursor=descending.next_cursor),
            scope,
            lambda page: True,
        )


def test_b14_cross_order_reuse_survives_a_matching_limit_and_filter(tmp_path: Path) -> None:
    """Only the order differs between issue and replay, and that alone is fatal."""

    _journal, adapter = _store(tmp_path / "state")
    scope = _scope()
    selector = parse_query_filter({"access": ["public"]})
    issued = adapter.execute(QueryRequest(selector, 2, None, None, "descending"), scope)
    assert issued.next_cursor is not None

    same_order = adapter.execute(QueryRequest(selector, 2, issued.next_cursor, None, "descending"), scope)
    assert same_order.items

    with pytest.raises(CursorRejected):
        adapter.execute(QueryRequest(selector, 2, issued.next_cursor, None, "ascending"), scope)


def test_b14_a_ledger_view_cursor_cannot_cross_into_a_canonical_descending_query(tmp_path: Path) -> None:
    _journal, adapter = _store(tmp_path / "state")
    scope = _scope()
    ledger = adapter.execute_ledger_bounded(
        QueryRequest(parse_query_filter({}), 2, None, "intake-ledger.v1", "descending"),
        scope,
        lambda page, watermark: True,
    )
    assert ledger is not None
    cursor = ledger[0].next_cursor
    assert cursor is not None

    with pytest.raises(CursorRejected):
        adapter.execute(_request(limit=2, order="descending", cursor=cursor), scope)


@pytest.mark.parametrize("position", [0, 5, 40, 120, -1])
def test_b14_a_tampered_descending_cursor_is_rejected(tmp_path: Path, position: int) -> None:
    _journal, adapter = _store(tmp_path / "state")
    scope = _scope()
    issued = adapter.execute(_request(limit=2, order="descending"), scope)
    assert issued.next_cursor is not None
    raw = bytearray(base64.urlsafe_b64decode(issued.next_cursor))
    raw[position] ^= 0x01
    forged = base64.urlsafe_b64encode(bytes(raw)).decode("ascii")

    with pytest.raises(CursorRejected):
        adapter.execute(_request(limit=2, order="descending", cursor=forged), scope)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value[:-1],
        lambda value: value + "A",
        lambda value: "",
        lambda value: "!" * len(value),
        lambda value: value[::-1],
    ],
)
def test_b14_a_malformed_descending_cursor_is_rejected(tmp_path: Path, mutate) -> None:
    _journal, adapter = _store(tmp_path / "state")
    scope = _scope()
    issued = adapter.execute(_request(limit=2, order="descending"), scope)
    assert issued.next_cursor is not None
    forged = mutate(issued.next_cursor)

    with pytest.raises((CursorRejected, QueryEngineError, ValueError)):
        adapter.execute(_request(limit=2, order="descending", cursor=forged), scope)


def test_b14_a_foreign_principal_cannot_replay_a_descending_cursor(tmp_path: Path) -> None:
    _journal, adapter = _store(tmp_path / "state")
    issued = adapter.execute(_request(limit=2, order="descending"), _scope("peer:reader"))
    assert issued.next_cursor is not None

    with pytest.raises(CursorRejected):
        adapter.execute(_request(limit=2, order="descending", cursor=issued.next_cursor), _scope("peer:other"))


# --- watermark pinning ------------------------------------------------------


def test_b14_a_descending_chain_pins_to_its_issue_time_watermark(tmp_path: Path) -> None:
    """Entries appended after issue are not surfaced mid-chain, in either order.

    Continuation means "the rest of what the first page could see", not "the
    journal as it is now". A descending consumer that wants newer entries
    resnapshots with ``cursor=None``; it never finds them spliced into a page.
    """

    root = tmp_path / "state"
    journal, adapter = _store(root, count=6)
    scope = _scope()

    first = adapter.execute(_request(limit=2, order="descending"), scope)
    assert first.next_cursor is not None
    pinned = _ids(first)

    # Newest by both sequence and instant: an unpinned walk would surface it.
    journal.append(_event(6, when=_TIMES[6]))
    later = _event(6, when=_TIMES[6])["entry_id"]

    continued: list[str] = list(pinned)
    cursor: str | None = first.next_cursor
    while cursor is not None:
        page = adapter.execute(_request(limit=2, order="descending", cursor=cursor), scope)
        continued.extend(_ids(page))
        cursor = page.next_cursor

    assert later not in continued
    assert len(continued) == 6

    fresh = adapter.execute(_request(limit=1, order="descending"), scope)
    assert _ids(fresh) == [later]


def test_b14_a_descending_chain_never_repeats_or_skips_across_an_append(tmp_path: Path) -> None:
    root = tmp_path / "state"
    journal, adapter = _store(root, count=6)
    scope = _scope()
    expected, _ = _drain(adapter, scope, limit=100, order="descending")

    collected: list[str] = []
    cursor: str | None = None
    for step in range(6):
        page = adapter.execute(_request(limit=1, order="descending", cursor=cursor), scope)
        collected.extend(_ids(page))
        cursor = page.next_cursor
        if step == 2:
            journal.append(_event(6, when=_TIMES[6]))
        if cursor is None:
            break

    assert collected == expected
    assert len(set(collected)) == len(collected)


# --- wire and client surfaces ----------------------------------------------


def _policy(uid: int) -> dict[str, object]:
    return {
        "schema_version": "houndd.policy.v1",
        "rules": [
            {
                "subject": f"linux-uid:{uid}",
                "claim_selector": {"owner_id": "reader", "capability": "journal.query", "run_id": None},
                "policy_id": "policy-reader",
                "event_producer_selectors": [{"owner_id": "owner", "capability": "capture", "run_id": None}],
                "readable_tiers": ["public", "workspace"],
                "allowed_output_tiers": ["restricted"],
            }
        ],
    }


def _wire_event(sequence: int, when: str) -> dict[str, object]:
    return make_journal_envelope(
        sequence=sequence,
        appended_at=when,
        producer={"owner_id": "owner", "capability": "capture", "run_id": f"run-{sequence}"},
        artifact={
            "kind": "capture",
            "schema": "houndd.capture.v1",
            "record_id": f"record-{sequence}",
            "hash": _digest(f"record-{sequence}"),
            "authorized_uri": f"houndd://records/{sequence}",
        },
        lineage={"relation": "none", "record_id": f"lineage-{sequence}", "lead_id": "none"},
        source={"provider": "fixture", "native_id": f"native-{sequence}", "canonical_url": f"https://fixture.test/{sequence}"},
        classification={"outcome": "completed", "evidence_status": "evidence"},
        access="public",
        policy_id="policy-reader",
        dedupe={"object_key": f"object-{sequence}", "content_sha256": _digest(f"record-{sequence}")},
        usage={},
    )


@pytest.fixture
def running_service(tmp_path: Path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    service = state / "service"
    service.mkdir(mode=0o700)
    policy = service / "policy.json"
    policy.write_bytes(canonical_bytes(_policy(os.getuid())))
    policy.chmod(0o600)
    with HounddStore(state) as store:
        for sequence in range(3):
            body = f"record-{sequence}".encode("utf-8")
            store.records.put_bytes(f"record-{sequence}", body, expected_sha256=_digest(f"record-{sequence}"))
            assert store.records.blob(body) == _digest(f"record-{sequence}")
            store.journal.append(_wire_event(sequence, _TIMES[sequence]))
        store.rebuild_index()
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    sock = runtime / "houndd.sock"
    process = subprocess.Popen(
        [sys.executable, "-m", "houndd.cli", "serve", "--state", os.fspath(state), "--socket", os.fspath(sock)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + 5
    while not sock.exists() and process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.02)
    assert process.poll() is None, process.stderr.read()
    try:
        yield sock
    finally:
        process.terminate()
        process.wait(timeout=5)


def _exchange(path: Path, payload: dict[str, object]) -> dict[str, object]:
    request = {
        "wire_version": "houndd.uds.v1",
        "method": "GET",
        "path": "/v1/journal",
        "body": {
            "schema_version": "houndd.read-request.v1",
            "request_id": "request-1",
            "producer": {"owner_id": "reader", "capability": "journal.query", "run_id": "client-run"},
            "requested_access": "workspace",
            "policy_id": "policy-reader",
            "operation": {"name": "journal.query", "payload": payload},
        },
    }
    raw = canonical_bytes(request)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(10)
        client.connect(os.fspath(path))
        client.sendall(len(raw).to_bytes(4, "big") + raw)
        client.shutdown(socket.SHUT_WR)
        size = int.from_bytes(client.recv(4), "big")
        data = bytearray()
        while len(data) < size:
            chunk = client.recv(size - len(data))
            assert chunk
            data.extend(chunk)
    return json.loads(bytes(data).decode("utf-8"))


def test_b14_the_wire_serves_a_newest_first_page(running_service) -> None:
    ascending = _exchange(running_service, {"filter": {}, "limit": 10})
    descending = _exchange(running_service, {"filter": {}, "limit": 10, "order": "descending"})

    assert ascending["status"] == 200 and descending["status"] == 200
    ascending_ids = [event["entry_id"] for event in ascending["body"]["result"]]
    descending_ids = [event["entry_id"] for event in descending["body"]["result"]]
    assert descending_ids == list(reversed(ascending_ids))
    assert descending["body"]["result"][0]["appended_at"] == "2026-07-31T03:00:00Z"


def test_b14_an_absent_order_is_unchanged_on_the_wire(running_service) -> None:
    absent = _exchange(running_service, {"filter": {}, "limit": 10})
    explicit = _exchange(running_service, {"filter": {}, "limit": 10, "order": "ascending"})

    assert absent["body"]["result"] == explicit["body"]["result"]


@pytest.mark.parametrize("order", ["desc", "DESCENDING", "", None, 1, True, ["descending"]])
def test_b14_the_wire_rejects_an_invalid_order(running_service, order) -> None:
    response = _exchange(running_service, {"filter": {}, "limit": 10, "order": order})

    assert response["status"] == 400
    assert response["body"]["error"]["code"] == "invalid_request"


def test_b14_the_wire_rejects_a_cross_order_cursor(running_service) -> None:
    ascending = _exchange(running_service, {"filter": {}, "limit": 1})
    cursor = ascending["body"]["cursor"]

    replayed = _exchange(running_service, {"filter": {}, "limit": 1, "order": "descending", "cursor": cursor})

    assert replayed["status"] == 400
    assert replayed["body"]["error"]["code"] == "invalid_request"


def test_b14_the_research_cli_walks_newest_first(running_service, tmp_path: Path) -> None:
    base = [
        sys.executable,
        "-m",
        "hound_research.cli",
        "journal",
        "query",
        "--socket",
        os.fspath(running_service),
        "--owner-id",
        "reader",
        "--run-id",
        "client-run",
        "--policy-id",
        "policy-reader",
        "--filter-json",
        "{}",
    ]
    descending = subprocess.run([*base, "--order", "descending"], capture_output=True, text=True, check=False)
    ascending = subprocess.run(base, capture_output=True, text=True, check=False)
    rejected = subprocess.run([*base, "--order", "sideways"], capture_output=True, text=True, check=False)

    assert descending.returncode == 0, descending.stderr
    assert ascending.returncode == 0, ascending.stderr
    assert rejected.returncode == 2
    newest = [event["entry_id"] for event in json.loads(descending.stdout)["result"]]
    oldest = [event["entry_id"] for event in json.loads(ascending.stdout)["result"]]
    assert newest == list(reversed(oldest))


def _client(tmp_path: Path, monkeypatch, sent: list[dict[str, object]]):
    from hound_client import client as client_module

    def _capture(self, request, *, timeout):
        sent.append(request)
        return {"status": 200, "body": {"result": []}}

    monkeypatch.setattr(client_module.HounddClient, "_exchange", _capture)
    return client_module.HounddClient(
        tmp_path / "houndd.sock",
        owner_id="reader",
        policy_id="policy-reader",
    )


@pytest.mark.parametrize("order", ["Descending", "desc", "", None, 1, True, ["descending"], "ASCENDING"])
def test_b14_the_shared_client_rejects_an_invalid_order(tmp_path: Path, monkeypatch, order) -> None:
    from hound_client.client import HounddClientError

    sent: list[dict[str, object]] = []
    client = _client(tmp_path, monkeypatch, sent)

    with pytest.raises(HounddClientError):
        client.journal_query(order=order, run_id="run", request_id="request")
    assert sent == []


def test_b14_the_shared_client_puts_the_order_on_the_wire(tmp_path: Path, monkeypatch) -> None:
    sent: list[dict[str, object]] = []
    client = _client(tmp_path, monkeypatch, sent)

    client.journal_query(order="descending", run_id="run", request_id="request-1")
    client.journal_query(run_id="run", request_id="request-2")

    assert sent[0]["body"]["operation"]["payload"]["order"] == "descending"
    assert "order" not in sent[1]["body"]["operation"]["payload"]
    assert parse_query_request(sent[0]["body"]["operation"]["payload"]).descending is True
