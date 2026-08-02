"""Strict, read-only private intake-ledger projection coverage."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time

import pytest

from houndd import HounddStore
from houndd.access import AuthenticatedPrincipal, EventSelector, PrincipalScope, ProducerSelector
from houndd.contracts import make_journal_envelope
from houndd.intake_projection import project_intake_ledger_page
from houndd.query_contracts import QueryContractError, QueryRequest, parse_query_filter, parse_query_request
from houndd.service_identity import ServiceIdentity
from houndd.snapshot import DurableJournalQueryAdapter
from houndd.cursor import CursorRejected
from houndd.contracts import canonical_bytes


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _event(sequence: int, *, access: str = "public", when: str | None = None) -> dict[str, object]:
    digest = _digest(f"record-{sequence}")
    return make_journal_envelope(
        sequence=sequence,
        appended_at=when or f"2026-08-01T00:00:0{sequence}Z",
        producer={"owner_id": "writer", "capability": "capture", "run_id": f"run-{sequence}"},
        artifact={"kind": "capture", "schema": "houndd.capture.v1", "record_id": f"record-{sequence}", "hash": digest, "authorized_uri": f"houndd://records/{sequence}"},
        lineage={"relation": "none", "record_id": f"lineage-{sequence}", "lead_id": "none"},
        source={"provider": "fixture", "native_id": f"native-{sequence}", "canonical_url": f"https://example.test/{sequence}"},
        classification={"outcome": "completed", "evidence_status": "evidence"},
        access=access,
        policy_id="policy",
        dedupe={"object_key": f"object-{sequence}", "content_sha256": _digest(f"content-{sequence}")},
        usage={},
    )


def _scope() -> PrincipalScope:
    return PrincipalScope(
        AuthenticatedPrincipal("linux-uid:1"),
        frozenset({"public", "workspace"}),
        (EventSelector("policy", ProducerSelector(owner_id="writer", capability="capture"), frozenset({"public", "workspace"})),),
    )


def _adapter(root: Path) -> tuple[HounddStore, ServiceIdentity, DurableJournalQueryAdapter, list[dict[str, object]]]:
    store = HounddStore(root)
    events = [_event(0, when="2026-08-01T00:00:02Z"), _event(1, access="workspace", when="2026-08-01T00:00:01Z")]
    for event in events:
        store.journal.append(event)
    identity = ServiceIdentity(root, create=True)
    return store, identity, DurableJournalQueryAdapter(store.journal, identity, nonce_source=lambda size: b"N" * size), events


def test_ledger_view_is_strict_and_no_view_hash_is_unchanged() -> None:
    legacy = parse_query_request({"filter": {}})
    ledger = parse_query_request({"filter": {}, "view": "intake-ledger.v1"})
    assert legacy == QueryRequest(parse_query_filter({}))
    assert legacy.filter_hash == legacy.filter.filter_hash
    assert ledger.view == "intake-ledger.v1"
    assert ledger.filter_hash != legacy.filter_hash
    assert ledger.canonical["view"] == "intake-ledger.v1"
    for bad in ("other", b"intake-ledger.v1", None):
        with pytest.raises(QueryContractError):
            parse_query_request({"filter": {}, "view": bad})

    class View(str):
        pass

    class Object(dict):
        pass

    with pytest.raises(QueryContractError):
        parse_query_request({"filter": {}, "view": View("intake-ledger.v1")})
    with pytest.raises(QueryContractError):
        parse_query_request(Object({"filter": {}}))


def test_ledger_projection_is_allowlisted_chronological_and_has_aligned_ids(tmp_path: Path) -> None:
    store, identity, adapter, events = _adapter(tmp_path / "state")
    try:
        page = adapter.execute(QueryRequest(parse_query_filter({}), limit=10, view="intake-ledger.v1"), _scope())
        rows = project_intake_ledger_page(page)
        assert [row["entry_id"] for row in rows] == [events[1]["entry_id"], events[0]["entry_id"]]
        assert all(set(row) == {"entry_id", "appended_at", "producer", "operation", "source", "classification", "artifact", "lineage", "access"} for row in rows)
        encoded = repr(rows)
        for secret in ("native-", "https://", "houndd://", "object-", "content_sha256", "hash"):
            assert secret not in encoded
        assert [row["artifact"]["record_id"] for row in rows] == ["record-1", "record-0"]
    finally:
        identity.close()
        store.close()


def test_ledger_cursor_domain_and_hwm_survive_append_restart_and_key_rotation(tmp_path: Path) -> None:
    store, identity, adapter, _events = _adapter(tmp_path / "state")
    request = QueryRequest(parse_query_filter({}), limit=1, view="intake-ledger.v1")
    try:
        first = adapter.execute_ledger_bounded(request, _scope(), lambda _page, _hwm: True)
        assert first is not None
        first_page, first_hwm = first
        assert first_page.next_cursor is not None and first_hwm
        with pytest.raises(CursorRejected, match="cursor rejected"):
            adapter.execute(QueryRequest(parse_query_filter({}), limit=1, cursor=first_page.next_cursor), _scope())

        # A service restart reuses the persisted generation/keyring and keeps
        # the old cursor's commitment stable.
        identity.close()
        identity = ServiceIdentity(tmp_path / "state", create=True)
        adapter = DurableJournalQueryAdapter(store.journal, identity, nonce_source=lambda size: b"N" * size)
        restarted = adapter.execute_ledger_bounded(
            QueryRequest(parse_query_filter({}), limit=10, cursor=first_page.next_cursor, view="intake-ledger.v1"),
            _scope(), lambda _page, _hwm: True,
        )
        assert restarted is not None and restarted[1] == first_hwm

        store.journal.append(_event(2, when="2026-08-01T00:00:00Z"))
        old_kid = identity.state.active_kid
        identity.rotate_cursor_key()
        resumed = adapter.execute_ledger_bounded(
            QueryRequest(parse_query_filter({}), limit=10, cursor=first_page.next_cursor, view="intake-ledger.v1"),
            _scope(),
            lambda _page, _hwm: True,
        )
        assert resumed is not None
        resumed_page, resumed_hwm = resumed
        assert resumed_hwm == first_hwm
        assert all(item.event["sequence"] != 2 for item in resumed_page.items)
        # A fresh post-append page advances its HWM and uses the active key.
        fresh = adapter.execute_ledger_bounded(request, _scope(), lambda _page, _hwm: True)
        assert fresh is not None and fresh[1] != first_hwm
        identity.retire_cursor_key(old_kid)
        with pytest.raises(CursorRejected, match="cursor rejected"):
            adapter.execute_ledger_bounded(
                QueryRequest(parse_query_filter({}), limit=10, cursor=first_page.next_cursor, view="intake-ledger.v1"),
                _scope(), lambda _page, _hwm: True,
            )
    finally:
        identity.close()
        store.close()


def test_ledger_empty_filter_and_sqlite_are_projection_independent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store, identity, adapter, _events = _adapter(tmp_path / "state")
    try:
        monkeypatch.setattr(sqlite3, "connect", lambda *_args, **_kwargs: pytest.fail("ledger opened SQLite"))
        result = adapter.execute_ledger_bounded(
            QueryRequest(parse_query_filter({"source": {"provider": ["absent"]}}), view="intake-ledger.v1"),
            _scope(), lambda _page, _hwm: True,
        )
        assert result is not None
        page, commitment = result
        assert page.items == () and page.next_cursor is None and commitment
    finally:
        identity.close()
        store.close()


def test_ledger_oversized_single_row_returns_generic_503_without_legacy_change(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import houndd.service as service_module
    from houndd.service import HounddService
    from tests.test_slice3b_service import _request, _valid_state

    state = _valid_state(tmp_path / "state")
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    service = HounddService(state_root=state, socket_path=runtime / "houndd.sock")
    try:
        original = service_module.project_intake_ledger_page
        monkeypatch.setattr(service_module, "project_intake_ledger_page", lambda page: tuple({
            "entry_id": item.event["entry_id"], "appended_at": "x" * 1_048_576,
            "producer": {"owner_id": "a", "capability": "a", "run_id": "a"},
            "operation": {"capability": "a", "artifact_kind": "a"}, "source": {"provider": "a"},
            "classification": {"outcome": "a", "evidence_status": "a"}, "artifact": {"record_id": "a"},
            "lineage": {"relation": "a", "record_id": "a", "lead_id": "a"}, "access": "public",
        } for item in page.items))
        request = _request()
        request["operation"]["payload"]["view"] = "intake-ledger.v1"
        response = service._dispatch(AuthenticatedPrincipal(f"linux-uid:{os.getuid()}"), {"wire_version": "houndd.uds.v1", "method": "GET", "path": "/v1/journal", "body": request})
        assert response["status"] == 503
        assert response["body"]["error"]["code"] == "response_too_large"
        monkeypatch.setattr(service_module, "project_intake_ledger_page", original)
    finally:
        service.close()


def test_ledger_unauthorized_scope_short_circuits_before_projection_hwm_or_cursor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import houndd.service as service_module
    from houndd.service import HounddService
    from tests.test_slice3b_service import _request, _valid_state

    state = _valid_state(tmp_path / "state")
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    service = HounddService(state_root=state, socket_path=runtime / "houndd.sock")
    try:
        monkeypatch.setattr(service_module.DurableJournalQueryAdapter, "execute_ledger_bounded", lambda *_args, **_kwargs: pytest.fail("unauthorized request reached ledger execution"))
        request = _request(policy_id="wrong")
        request["operation"]["payload"].update({"view": "intake-ledger.v1", "cursor": "forged"})
        response = service._dispatch(AuthenticatedPrincipal(f"linux-uid:{os.getuid()}"), {"wire_version": "houndd.uds.v1", "method": "GET", "path": "/v1/journal", "body": request})
        assert response["status"] == 404
        assert "projection" not in response["body"] and response["body"]["entry_ids"] == []
    finally:
        service.close()


def test_ledger_client_rejects_extra_or_leaking_rows() -> None:
    from hound_research.journal_client import JournalClientError, strict_response

    row = {
        "entry_id": "a" * 64, "appended_at": "2026-08-01T00:00:00Z",
        "producer": {"owner_id": "owner", "capability": "capture", "run_id": "run"},
        "operation": {"capability": "capture", "artifact_kind": "capture"}, "source": {"provider": "fixture"},
        "classification": {"outcome": "completed", "evidence_status": "evidence"}, "artifact": {"record_id": "record"},
        "lineage": {"relation": "none", "record_id": "lineage", "lead_id": "none"}, "access": "public",
    }
    body = {
        "schema_version": "houndd.read-response.v1", "request_id": "request", "ok": True, "outcome": "completed",
        "entry_ids": [row["entry_id"]], "record_ids": ["record"], "usage": {"requests": 0, "bytes": 0, "cost": 0},
        "result": [row], "projection": {"schema_version": "houndd.intake-ledger.v1", "integrity": "verified", "high_watermark": "opaque"},
    }
    assert strict_response(canonical_bytes({"wire_version": "houndd.uds.v1", "status": 200, "body": body}), request_id="request", view="intake-ledger.v1")["body"]["result"] == [row]
    row["source"]["native_id"] = "secret"
    with pytest.raises(JournalClientError):
        strict_response(canonical_bytes({"wire_version": "houndd.uds.v1", "status": 200, "body": body}), request_id="request", view="intake-ledger.v1")


def test_ledger_view_is_real_uds_response_and_no_view_wire_stays_legacy(tmp_path: Path) -> None:
    """Exercise the service boundary; the browser-facing bridge gets this only."""

    from tests.test_slice3b_service import _exchange, _frame, _request, _valid_state

    state = _valid_state(tmp_path / "state")
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    socket_path = runtime / "houndd.sock"
    process = subprocess.Popen(
        [sys.executable, "-m", "houndd.cli", "serve", "--state", os.fspath(state), "--socket", os.fspath(socket_path)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    deadline = time.monotonic() + 5
    while not socket_path.exists() and process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.02)
    try:
        assert process.poll() is None, process.stderr.read()
        ledger_request = _request()
        ledger_request["operation"]["payload"]["view"] = "intake-ledger.v1"
        ledger = _exchange(socket_path, _frame({"wire_version": "houndd.uds.v1", "method": "GET", "path": "/v1/journal", "body": ledger_request}))
        assert ledger is not None and ledger["status"] == 200
        body = ledger["body"]
        assert set(body["projection"]) == {"schema_version", "integrity", "high_watermark"}
        assert body["projection"]["schema_version"] == "houndd.intake-ledger.v1"
        assert body["projection"]["high_watermark"]
        assert body["entry_ids"] == [row["entry_id"] for row in body["result"]]
        assert body["record_ids"] == [row["artifact"]["record_id"] for row in body["result"]]
        assert "native_id" not in json.dumps(body, sort_keys=True)
        from hound_research.journal_client import exchange
        client_request = {"wire_version": "houndd.uds.v1", "method": "GET", "path": "/v1/journal", "body": ledger_request}
        assert exchange(socket_path, client_request)["body"]["projection"]["integrity"] == "verified"
        legacy = _exchange(socket_path, _frame({"wire_version": "houndd.uds.v1", "method": "GET", "path": "/v1/journal", "body": _request()}))
        assert legacy is not None and "projection" not in legacy["body"]
    finally:
        process.terminate()
        process.wait(timeout=5)
