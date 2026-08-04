"""B6: journal verify/rebuild-index routes and the two read error-ordering fixes."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import threading
import time
from typing import Any

import pytest

from houndd import HounddStore
from houndd.adapter_host import AdapterHost, AdapterResult
from houndd.commit import normalize_source, parse_commit_request, resolve_route
from houndd.commit_runtime import CommitRuntime
from houndd.contracts import canonical_bytes
from houndd.journal import Journal
from houndd.projection import Projection
from houndd.query_engine import QuerySnapshotError
from houndd.service import HounddService, REBUILD_REPORT_SCHEMA, VERIFY_REPORT_SCHEMA
from houndd.verify import _expected_projection, verify_store
from hound_research import cli as research_cli


PRINCIPAL = f"linux-uid:{os.getuid()}"
WRITE_CAPABILITIES = ("ingest.search", "ingest.file")
READ_CAPABILITIES = ("journal.query", "record.get", "journal.verify", "journal.rebuild-index")
MAINTENANCE_CAPABILITIES = ("journal.verify", "journal.rebuild-index")
SEARCH_CONTENT = canonical_bytes({
    "schema_version": "houndd.search-content.v1",
    "leads": [{"schema_version": "hound.lead.v1", "url": "https://example.test/a", "title": "A"}],
    "provider": "exa",
    "query": "caregiver respite",
    "limit": 5,
    "retrieved_at": "2026-08-03T00:00:00Z",
})
LEADS = ({"url": "https://example.test/a", "title": "A", "native_id": "exa-1"},)
FILE_CONTENT = b"certified caregiver source"
GENERIC_404 = {
    "schema_version": "houndd.read-response.v1",
    "ok": False,
    "outcome": "not_found",
    "record_ids": [],
    "entry_ids": [],
    "usage": {"requests": 0, "bytes": 0, "cost": 0},
}
UNAVAILABLE_ERROR = {"code": "service_unavailable", "retryable": True, "message": "service is unavailable"}
REPORTS = {
    "verify": ("/v1/journal/verify", "journal.verify", VERIFY_REPORT_SCHEMA),
    "rebuild-index": ("/v1/journal/rebuild-index", "journal.rebuild-index", REBUILD_REPORT_SCHEMA),
}


def _policy() -> dict[str, object]:
    writer_selectors = [{"owner_id": "writer", "capability": capability, "run_id": None} for capability in WRITE_CAPABILITIES]
    rules: list[dict[str, object]] = [
        {
            "subject": PRINCIPAL,
            "claim_selector": {"owner_id": "writer", "capability": capability, "run_id": None},
            "policy_id": "write-policy",
            "event_producer_selectors": writer_selectors,
            "readable_tiers": ["public"],
            "allowed_output_tiers": ["public"],
        }
        for capability in WRITE_CAPABILITIES
    ]
    rules += [
        {
            "subject": PRINCIPAL,
            "claim_selector": {"owner_id": "reader", "capability": capability, "run_id": None},
            "policy_id": "write-policy",
            "event_producer_selectors": writer_selectors,
            "readable_tiers": ["public"],
            "allowed_output_tiers": ["public"],
        }
        for capability in READ_CAPABILITIES
    ]
    # A resolvable scope in a different policy partition that was granted the
    # ordinary reads but no maintenance capability at all.
    rules += [
        {
            "subject": PRINCIPAL,
            "claim_selector": {"owner_id": "stranger", "capability": capability, "run_id": None},
            "policy_id": "stranger-policy",
            "event_producer_selectors": [{"owner_id": "stranger", "capability": capability, "run_id": None}],
            "readable_tiers": ["public"],
            "allowed_output_tiers": ["public"],
        }
        for capability in ("journal.query", "record.get")
    ]
    # A maintenance grant whose only readable tier sits above the ceiling any
    # public request may ask for: the clamped scope selects nothing.
    rules += [
        {
            "subject": PRINCIPAL,
            "claim_selector": {"owner_id": "narrow", "capability": capability, "run_id": None},
            "policy_id": "narrow-policy",
            "event_producer_selectors": writer_selectors,
            "readable_tiers": ["restricted"],
            "allowed_output_tiers": ["restricted"],
        }
        for capability in MAINTENANCE_CAPABILITIES
    ]
    return {"schema_version": "houndd.policy.v1", "rules": rules}


def _state(tmp_path: Path, digests: tuple[str, ...]) -> Path:
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    HounddStore(root).close()
    service = root / "service"
    service.mkdir(mode=0o700)
    (service / "policy.json").write_bytes(canonical_bytes(_policy()))
    (service / "policy.json").chmod(0o600)
    (service / "phi-clear.json").write_bytes(canonical_bytes({
        "schema_version": "houndd.phi-clear.v1",
        "entries": [{"sha256": digest, "media_type": "application/octet-stream", "encoding": "identity"} for digest in sorted(digests)],
    }))
    (service / "phi-clear.json").chmod(0o600)
    return root


def _host() -> AdapterHost:
    return AdapterHost({
        "ingest.search": lambda _payload: AdapterResult("ingest.search", "completed", SEARCH_CONTENT, "application/json", "2026-08-03T00:00:00Z", 1, 0, LEADS),
    })


def _frame(value: object) -> bytes:
    raw = canonical_bytes(value)
    return len(raw).to_bytes(4, "big") + raw


def _read_exact(client: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        part = client.recv(size - len(data))
        if not part:
            raise AssertionError("truncated response")
        data.extend(part)
    return bytes(data)


def _exchange(path: Path, value: object) -> dict[str, Any]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(10)
        client.connect(os.fspath(path))
        client.sendall(_frame(value))
        client.shutdown(socket.SHUT_WR)
        header = _read_exact(client, 4)
        return json.loads(_read_exact(client, int.from_bytes(header, "big")).decode("utf-8"))


def _read(
    *,
    path: str,
    operation: str,
    payload: dict[str, Any],
    request_id: str,
    owner_id: str = "reader",
    policy_id: str = "write-policy",
    capability: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "schema_version": "houndd.read-request.v1",
        "request_id": request_id,
        "producer": {"owner_id": owner_id, "capability": operation if capability is None else capability, "run_id": "client-run"},
        "requested_access": "public",
        "policy_id": policy_id,
        "operation": {"name": operation, "payload": payload},
    }
    if extra is not None:
        body.update(extra)
    return {"wire_version": "houndd.uds.v1", "method": "GET", "path": path, "body": body}


def _report(verb: str, *, request_id: str, payload: dict[str, Any] | None = None, **overrides: Any) -> dict[str, Any]:
    path, operation, _schema = REPORTS[verb]
    return _read(path=path, operation=operation, payload={} if payload is None else payload, request_id=request_id, **overrides)


def _query(request_id: str, **overrides: Any) -> dict[str, Any]:
    return _read(path="/v1/journal", operation="journal.query", payload={"filter": {}, "limit": 10}, request_id=request_id, **overrides)


def _report_result(response: dict[str, Any], verb: str, request_id: str) -> bool:
    """Assert the exact maintenance-report envelope and return its verdict."""

    _path, _operation, schema = REPORTS[verb]
    assert response["status"] == 200, response
    body = response["body"]
    assert body == {
        "schema_version": "houndd.read-response.v1",
        "request_id": request_id,
        "ok": True,
        "outcome": "completed",
        "record_ids": [],
        "entry_ids": [],
        "usage": {"requests": 0, "bytes": 0, "cost": 0},
        "result": [{"schema_version": schema, "valid": body["result"][0]["valid"]}],
    }, response
    return body["result"][0]["valid"]


def _commit(*, operation: str, payload: dict[str, Any], request_id: str) -> dict[str, Any]:
    paths = {"ingest.search": "/v1/ingest/search", "ingest.file": "/v1/ingest/file"}
    return {
        "wire_version": "houndd.uds.v1",
        "method": "POST",
        "path": paths[operation],
        "body": {
            "schema_version": "houndd.commit-request.v1",
            "request_id": request_id,
            "idempotency_key": request_id,
            "producer": {"owner_id": "writer", "capability": operation, "run_id": "run"},
            "requested_access": "public",
            "policy_id": "write-policy",
            "operation": {"name": operation, "payload": payload},
        },
    }


def _serve(state: Path, tmp_path: Path):
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700, exist_ok=True)
    path = runtime / "houndd.sock"
    service = HounddService(state_root=state, socket_path=path, adapter_host=_host())
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while not path.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    return service, thread, path


@pytest.fixture
def live(tmp_path: Path):
    """One provisioned service with one committed search behind it."""

    state = _state(tmp_path, (hashlib.sha256(FILE_CONTENT).hexdigest(),))
    service, thread, path = _serve(state, tmp_path)
    try:
        response = _exchange(path, _commit(operation="ingest.search", payload={"query": "caregiver respite", "limit": 5}, request_id="commit-search"))
        assert response["status"] == 200 and response["body"]["outcome"] == "completed", response
        yield path, state
    finally:
        service.close()
        thread.join(timeout=5)


def test_b6_verify_route_reports_canonical_truth_and_ignores_the_disposable_index(live) -> None:
    path, state = live

    assert _report_result(_exchange(path, _report("verify", request_id="verify-ok")), "verify", "verify-ok") is True
    assert verify_store(state, projection=False)["valid"] is True

    # An index is never canonical truth, so losing it entirely leaves the
    # journal verdict unchanged; rebuild-index, not verify, is its remedy.
    with Projection(state) as projection:
        projection.delete()
    assert verify_store(state)["valid"] is False
    assert _report_result(_exchange(path, _report("verify", request_id="verify-no-index")), "verify", "verify-no-index") is True


def test_b6_rebuild_index_route_restores_the_projection_from_the_canonical_journal(live) -> None:
    path, state = live

    # A durable commit never refreshes the projection, so a served store is
    # already drifted before anything is deleted here.
    assert verify_store(state)["valid"] is False
    with Projection(state) as projection:
        projection.delete()
        assert projection.rows() == []

    assert _report_result(_exchange(path, _report("rebuild-index", request_id="rebuild")), "rebuild-index", "rebuild") is True

    with Journal(state, create=False) as journal, Projection(state) as projection:
        expected = _expected_projection(journal.entries())
        assert expected and projection.rows() == expected
    assert verify_store(state)["valid"] is True


def test_b6_maintenance_routes_deny_unauthorized_scopes_generically(live) -> None:
    path, _state_root = live

    denials = {
        f"{verb}-{name}": _exchange(path, _report(verb, request_id=f"{verb}-{name}", **overrides))
        for verb in REPORTS
        for name, overrides in (
            ("no-rule", {"policy_id": "absent-policy"}),
            ("no-maintenance-grant", {"owner_id": "stranger", "policy_id": "stranger-policy"}),
            ("above-the-access-ceiling", {"owner_id": "narrow", "policy_id": "narrow-policy"}),
        )
    }
    for request_id, response in denials.items():
        assert response["status"] == 404, (request_id, response)
        assert response["body"] == {**GENERIC_404, "request_id": request_id}, (request_id, response)


def test_b6_maintenance_routes_reject_unknown_fields_and_wrong_bindings(live) -> None:
    path, _state_root = live

    invalid = {
        "verify-unknown-payload-field": _report("verify", request_id="verify-unknown-payload-field", payload={"filter": {}}),
        "rebuild-unknown-payload-field": _report("rebuild-index", request_id="rebuild-unknown-payload-field", payload={"limit": 1}),
        "verify-idempotency-key": _report("verify", request_id="verify-idempotency-key", extra={"idempotency_key": "not-permitted"}),
        "rebuild-idempotency-key": _report("rebuild-index", request_id="rebuild-idempotency-key", extra={"idempotency_key": "not-permitted"}),
        "verify-capability-mismatch": _report("verify", request_id="verify-capability-mismatch", capability="journal.query"),
        "rebuild-capability-mismatch": _report("rebuild-index", request_id="rebuild-capability-mismatch", capability="journal.verify"),
        "verify-on-query-route": _read(path="/v1/journal", operation="journal.verify", payload={}, request_id="verify-on-query-route"),
        "rebuild-on-verify-route": _read(path="/v1/journal/verify", operation="journal.rebuild-index", payload={}, request_id="rebuild-on-verify-route"),
        "query-on-verify-route": _read(path="/v1/journal/verify", operation="journal.query", payload={"filter": {}, "limit": 1}, request_id="query-on-verify-route"),
    }
    for request_id, frame in invalid.items():
        response = _exchange(path, frame)
        assert response["status"] == 400, (request_id, response)
        assert response["body"] == {
            "schema_version": "houndd.read-response.v1",
            "request_id": request_id,
            "ok": False,
            "outcome": "invalid",
            "record_ids": [],
            "entry_ids": [],
            "usage": {"requests": 0, "bytes": 0, "cost": 0},
            "error": {"code": "invalid_request", "retryable": False, "message": "request is invalid"},
        }, (request_id, response)


def test_b6_maintenance_routes_are_unavailable_when_the_frozen_policy_changes(live) -> None:
    path, state = live
    policy = state / "service" / "policy.json"
    replacement = json.loads(policy.read_bytes().decode("utf-8"))
    replacement["rules"] = replacement["rules"][:1]
    policy.write_bytes(canonical_bytes(replacement))

    for verb in REPORTS:
        response = _exchange(path, _report(verb, request_id=f"{verb}-frozen"))
        assert response["status"] == 503, (verb, response)
        assert response["body"] == {
            "schema_version": "houndd.read-response.v1",
            "request_id": f"{verb}-frozen",
            "ok": False,
            "outcome": "unavailable",
            "record_ids": [],
            "entry_ids": [],
            "usage": {"requests": 0, "bytes": 0, "cost": 0},
            "error": UNAVAILABLE_ERROR,
        }, (verb, response)


def test_b6_journal_query_maps_a_corrupt_snapshot_to_unavailable(live, monkeypatch: pytest.MonkeyPatch) -> None:
    """A ``QuerySnapshotError`` is a ``ValueError``; it must not read as a bad request."""

    path, _state_root = live
    assert _exchange(path, _query("query-ok"))["status"] == 200

    def corrupt(_persisted):
        raise QuerySnapshotError("persisted journal head does not match its chain")

    monkeypatch.setattr("houndd.snapshot.build_journal_query_snapshot", corrupt)
    for request_id, frame in (("query-corrupt", _query("query-corrupt")), ("ledger-corrupt", _read(path="/v1/journal", operation="journal.query", payload={"filter": {}, "limit": 10, "view": "intake-ledger.v1"}, request_id="ledger-corrupt"))):
        response = _exchange(path, frame)
        assert response["status"] == 503, (request_id, response)
        assert response["body"]["outcome"] == "unavailable" and response["body"]["error"] == UNAVAILABLE_ERROR, (request_id, response)


def test_b6_journal_query_answers_rather_than_dying_on_a_tampered_journal(live) -> None:
    """A ``JournalError`` is a ``StoreError``: unanswered before, unavailable now."""

    path, state = live
    events = state / "journal" / "events.jsonl"
    events.write_bytes(events.read_bytes().replace(b'"sequence":0', b'"sequence":7'))

    for request_id, frame in (
        ("tampered-query", _query("tampered-query")),
        ("tampered-verify", _report("verify", request_id="tampered-verify")),
    ):
        response = _exchange(path, frame)
        assert response["status"] in {200, 503}, (request_id, response)
        if request_id == "tampered-query":
            assert response["status"] == 503 and response["body"]["error"] == UNAVAILABLE_ERROR, response
        else:
            # verify still answers: reporting the damage is the route's job.
            assert _report_result(response, "verify", request_id) is False


def test_b6_interrupted_file_content_read_omits_the_blob_that_was_never_staged(tmp_path: Path) -> None:
    """An interrupted ingest commits a source digest it never stored."""

    state = _state(tmp_path, (hashlib.sha256(FILE_CONTENT).hexdigest(),))
    route = resolve_route("POST", "/v1/ingest/file", require_available=True)
    request = parse_commit_request(
        _commit(
            operation="ingest.file",
            payload={
                "source": {"kind": "bytes", "body_base64": base64.b64encode(FILE_CONTENT).decode("ascii"), "sha256": hashlib.sha256(FILE_CONTENT).hexdigest(), "byte_length": len(FILE_CONTENT)},
                "media_type": "application/octet-stream",
            },
            request_id="interrupted",
        )["body"],
        route,
    )

    def crash(phase: str) -> None:
        if phase == "after_open":
            raise RuntimeError("simulated process death")

    runtime = CommitRuntime(state, fault_hook=crash)
    try:
        with pytest.raises(RuntimeError):
            runtime.execute(request, route, principal=PRINCIPAL, access="public", source=normalize_source(request.source.to_wire()), scanner_clear=True)
    finally:
        runtime.close()

    # Service startup reconciles the open attempt into one interrupted event.
    service, thread, path = _serve(state, tmp_path)
    try:
        assert not list((state / "blobs").iterdir())
        query = _exchange(path, _query("interrupted-query"))
        assert query["status"] == 200, query
        events = query["body"]["result"]
        assert len(events) == 1 and events[0]["classification"]["outcome"] == "interrupted", events
        record_id = events[0]["artifact"]["record_id"]
        assert events[0]["dedupe"]["content_sha256"] == hashlib.sha256(FILE_CONTENT).hexdigest()

        response = _exchange(path, _read(path="/v1/record", operation="record.get", payload={"record_id": record_id, "include_content": True}, request_id="interrupted-record"))
        assert response["status"] == 200, response
        result = response["body"]["result"][0]
        assert set(result) == {"schema", "record_id", "body_base64", "byte_length"}, result
        assert result["schema"] == "houndd.file-record.v1"
        outcome = json.loads(base64.b64decode(result["body_base64"].encode("ascii"), validate=True).decode("utf-8"))
        assert outcome["outcome"] == "interrupted" and outcome["evidence_status"] == "interrupted"
    finally:
        service.close()
        thread.join(timeout=5)


def test_b6_client_commands_run_verify_and_rebuild_index_over_the_socket(live, capsys: pytest.CaptureFixture[str]) -> None:
    path, state = live
    arguments = ["--socket", os.fspath(path), "--owner-id", "reader", "--run-id", "client-run", "--policy-id", "write-policy", "--requested-access", "public"]

    assert research_cli.main(["journal", "verify", *arguments]) == 0
    assert json.loads(capsys.readouterr().out) == {"schema_version": VERIFY_REPORT_SCHEMA, "valid": True}

    with Projection(state) as projection:
        projection.delete()
    assert research_cli.main(["journal", "rebuild-index", *arguments]) == 0
    assert json.loads(capsys.readouterr().out) == {"schema_version": REBUILD_REPORT_SCHEMA, "valid": True}
    with Journal(state, create=False) as journal, Projection(state) as projection:
        assert projection.rows() == _expected_projection(journal.entries())

    # A false verdict is reported, not hidden: exit 1 carrying a valid answer.
    events = state / "journal" / "events.jsonl"
    events.write_bytes(events.read_bytes().replace(b'"sequence":0', b'"sequence":7'))
    assert research_cli.main(["journal", "verify", *arguments]) == 1
    assert json.loads(capsys.readouterr().out) == {"schema_version": VERIFY_REPORT_SCHEMA, "valid": False}


def test_b6_client_rejects_a_report_response_that_leaks_or_drops_fields() -> None:
    from hound_research.journal_client import JournalClientError, report_strict_response

    def wire(result: list[dict[str, Any]], **body_values: Any) -> bytes:
        body = {
            "schema_version": "houndd.read-response.v1",
            "request_id": "request-1",
            "ok": True,
            "outcome": "completed",
            "record_ids": [],
            "entry_ids": [],
            "usage": {"requests": 0, "bytes": 0, "cost": 0},
            "result": result,
        }
        body.update(body_values)
        return canonical_bytes({"wire_version": "houndd.uds.v1", "status": 200, "body": body})

    exact = [{"schema_version": VERIFY_REPORT_SCHEMA, "valid": True}]
    assert report_strict_response(wire(exact), request_id="request-1", schema=VERIFY_REPORT_SCHEMA)["status"] == 200

    rejected = (
        wire([{"schema_version": VERIFY_REPORT_SCHEMA, "valid": True, "failures": ["record 0abc"]}]),
        wire([{"schema_version": REBUILD_REPORT_SCHEMA, "valid": True}]),
        wire([{"schema_version": VERIFY_REPORT_SCHEMA, "valid": "true"}]),
        wire([{"schema_version": VERIFY_REPORT_SCHEMA}]),
        wire(exact * 2),
        wire(exact, entry_ids=["entry"]),
        wire(exact, record_ids=["record"]),
        wire(exact, cursor="cursor"),
    )
    for raw in rejected:
        with pytest.raises(JournalClientError):
            report_strict_response(raw, request_id="request-1", schema=VERIFY_REPORT_SCHEMA)
