"""B7 / HSP-11: policy-filtered telemetry over provider errors, spend, freshness,
capture completeness, dedupe rate, consumer lag, unprocessed demand, and
journal/index/recovery health.

Every fixture class HSP-11 names gets its own focused proof: a provider
failure and refusal, an unbound-adapter degradation, a dedupe hit, an
interrupted-recovery event, and index staleness against the disposable
projection. A dedicated policy-partition test proves the aggregate counts
never cross a policy boundary -- the same authorization primitive
(``authorize_event_header``) the B6 journal routes already use.
"""

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
from houndd.adapter_host import AdapterAbstained, AdapterFailed, AdapterHost, AdapterResult
from houndd.commit import normalize_source, parse_commit_request, resolve_route
from houndd.commit_runtime import CommitRuntime
from houndd.contracts import canonical_bytes
from houndd.projection import Projection
from houndd.service import HounddService
from houndd.telemetry import TELEMETRY_REPORT_SCHEMA
from houndd.verify import verify_store


PRINCIPAL = f"linux-uid:{os.getuid()}"
WRITE_CAPABILITIES = ("ingest.search", "ingest.file", "ingest.url")
FILE_CONTENT = b"caregiver source bytes, committed twice on purpose"
GENERIC_404 = {
    "schema_version": "houndd.read-response.v1",
    "ok": False,
    "outcome": "not_found",
    "record_ids": [],
    "entry_ids": [],
    "usage": {"requests": 0, "bytes": 0, "cost": 0},
}
UNAVAILABLE_ERROR = {"code": "service_unavailable", "retryable": True, "message": "service is unavailable"}
EVIDENCE_DIR = Path(__file__).parent / "evidence" / "b7"


def _search_content(query: str) -> bytes:
    return canonical_bytes({
        "schema_version": "houndd.search-content.v1",
        "leads": [{"schema_version": "hound.lead.v1", "url": f"https://example.test/{query}", "title": query}],
        "provider": "exa",
        "query": query,
        "limit": 5,
        "retrieved_at": "2026-08-04T00:00:00Z",
    })


def _search_adapter(payload: dict[str, Any]) -> AdapterResult:
    """One fake provider whose outcome is selected by the query text alone."""

    query = payload["query"]
    if query == "trigger-failed":
        raise AdapterFailed("provider exchange failed", requests=1)
    if query == "trigger-refused":
        raise AdapterAbstained("provider abstained", requests=1)
    content = _search_content(query)
    return AdapterResult("ingest.search", "completed", content, "application/json", "2026-08-04T00:00:00Z", 1, 0, ({"url": f"https://example.test/{query}", "title": query, "native_id": f"exa-{query}"},))


def _host() -> AdapterHost:
    # "ingest.url" is deliberately left unbound: any ingest.url commit is an
    # uninvoked, durable "degraded" outcome (adapter_absent), the cheapest way
    # to fabricate that fixture class without a second fake provider.
    return AdapterHost({"ingest.search": _search_adapter})


def _policy() -> dict[str, object]:
    def _partition(letter: str) -> list[dict[str, object]]:
        owner = f"writer-{letter}"
        reader = f"reader-{letter}"
        policy_id = f"policy-{letter}"
        writer_selectors = [{"owner_id": owner, "capability": capability, "run_id": None} for capability in WRITE_CAPABILITIES]
        rules = [
            {
                "subject": PRINCIPAL,
                "claim_selector": {"owner_id": owner, "capability": capability, "run_id": None},
                "policy_id": policy_id,
                "event_producer_selectors": writer_selectors,
                "readable_tiers": ["public"],
                "allowed_output_tiers": ["public"],
            }
            for capability in WRITE_CAPABILITIES
        ]
        rules.append({
            "subject": PRINCIPAL,
            "claim_selector": {"owner_id": reader, "capability": "service.telemetry", "run_id": None},
            "policy_id": policy_id,
            "event_producer_selectors": writer_selectors,
            "readable_tiers": ["public"],
            "allowed_output_tiers": ["public"],
        })
        return rules

    rules = _partition("a") + _partition("b")
    # A resolvable scope with ordinary reads but no telemetry grant at all.
    rules.append({
        "subject": PRINCIPAL,
        "claim_selector": {"owner_id": "stranger", "capability": "journal.query", "run_id": None},
        "policy_id": "stranger-policy",
        "event_producer_selectors": [{"owner_id": "stranger", "capability": "journal.query", "run_id": None}],
        "readable_tiers": ["public"],
        "allowed_output_tiers": ["public"],
    })
    # A telemetry grant whose only readable tier sits above any public
    # request's ceiling: the clamped scope selects nothing.
    rules.append({
        "subject": PRINCIPAL,
        "claim_selector": {"owner_id": "narrow", "capability": "service.telemetry", "run_id": None},
        "policy_id": "narrow-policy",
        "event_producer_selectors": [{"owner_id": "writer-a", "capability": capability, "run_id": None} for capability in WRITE_CAPABILITIES],
        "readable_tiers": ["restricted"],
        "allowed_output_tiers": ["restricted"],
    })
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


def _read(*, path: str, operation: str, payload: dict[str, Any], request_id: str, owner_id: str, policy_id: str, capability: str | None = None, extra: dict[str, Any] | None = None) -> dict[str, Any]:
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


def _telemetry(request_id: str, *, owner_id: str = "reader-a", policy_id: str = "policy-a", payload: dict[str, Any] | None = None, **overrides: Any) -> dict[str, Any]:
    return _read(path="/v1/telemetry", operation="service.telemetry", payload={} if payload is None else payload, request_id=request_id, owner_id=owner_id, policy_id=policy_id, **overrides)


def _commit(*, operation: str, payload: dict[str, Any], owner_id: str, policy_id: str, request_id: str) -> dict[str, Any]:
    paths = {"ingest.search": "/v1/ingest/search", "ingest.file": "/v1/ingest/file", "ingest.url": "/v1/ingest/url"}
    return {
        "wire_version": "houndd.uds.v1",
        "method": "POST",
        "path": paths[operation],
        "body": {
            "schema_version": "houndd.commit-request.v1",
            "request_id": request_id,
            "idempotency_key": request_id,
            "producer": {"owner_id": owner_id, "capability": operation, "run_id": "run"},
            "requested_access": "public",
            "policy_id": policy_id,
            "operation": {"name": operation, "payload": payload},
        },
    }


def _file_commit(*, owner_id: str, policy_id: str, request_id: str, content: bytes) -> dict[str, Any]:
    return _commit(
        operation="ingest.file",
        payload={"source": {"kind": "bytes", "body_base64": base64.b64encode(content).decode("ascii"), "sha256": hashlib.sha256(content).hexdigest(), "byte_length": len(content)}, "media_type": "application/octet-stream"},
        owner_id=owner_id,
        policy_id=policy_id,
        request_id=request_id,
    )


def _search_commit(*, owner_id: str, policy_id: str, request_id: str, query: str) -> dict[str, Any]:
    return _commit(operation="ingest.search", payload={"query": query, "limit": 5}, owner_id=owner_id, policy_id=policy_id, request_id=request_id)


def _url_commit(*, owner_id: str, policy_id: str, request_id: str, url: str) -> dict[str, Any]:
    return _commit(operation="ingest.url", payload={"url": url, "lineage": {"kind": "direct"}}, owner_id=owner_id, policy_id=policy_id, request_id=request_id)


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
    """Two isolated policy partitions, each with a distinct outcome mix.

    Partition A: one completed search, one provider ``failed`` search, and
    two identical-content file commits (a dedupe hit).
    Partition B: one completed search, one provider ``refused`` search, and
    one ``degraded`` (adapter-absent) URL commit.
    """

    state = _state(tmp_path, (hashlib.sha256(FILE_CONTENT).hexdigest(),))
    service, thread, path = _serve(state, tmp_path)
    try:
        content_a = _search_content("caregiver-a")
        content_b = _search_content("caregiver-b")

        commits = [
            _search_commit(owner_id="writer-a", policy_id="policy-a", request_id="a-completed", query="caregiver-a"),
            _search_commit(owner_id="writer-a", policy_id="policy-a", request_id="a-failed", query="trigger-failed"),
            _file_commit(owner_id="writer-a", policy_id="policy-a", request_id="a-file-1", content=FILE_CONTENT),
            _file_commit(owner_id="writer-a", policy_id="policy-a", request_id="a-file-2", content=FILE_CONTENT),
            _search_commit(owner_id="writer-b", policy_id="policy-b", request_id="b-completed", query="caregiver-b"),
            _search_commit(owner_id="writer-b", policy_id="policy-b", request_id="b-refused", query="trigger-refused"),
            _url_commit(owner_id="writer-b", policy_id="policy-b", request_id="b-degraded", url="https://example.test/degraded"),
        ]
        for commit in commits:
            response = _exchange(path, commit)
            assert response["status"] == 200, response

        expected_a = {
            "total_events": 4,
            "outcomes": {"completed": 3, "partial": 0, "failed": 1, "degraded": 0, "refused": 0, "interrupted": 0},
            "provider_errors": {"count": 1, "rate": 0.25},
            "capture_completeness": {"count": 3, "rate": 0.75},
            "unprocessed_demand": {"count": 0, "rate": 0.0},
            "dedupe": {"duplicate_events": 1, "distinct_content": 3, "rate": 0.25},
            "spend": {"cost": 0, "requests": 2, "bytes": len(content_a) + 2 * len(FILE_CONTENT)},
        }
        expected_b = {
            "total_events": 3,
            "outcomes": {"completed": 1, "partial": 0, "failed": 0, "degraded": 1, "refused": 1, "interrupted": 0},
            "provider_errors": {"count": 1, "rate": 1 / 3},
            "capture_completeness": {"count": 1, "rate": 1 / 3},
            "unprocessed_demand": {"count": 1, "rate": 1 / 3},
            "dedupe": {"duplicate_events": 0, "distinct_content": 3, "rate": 0.0},
            "spend": {"cost": 0, "requests": 2, "bytes": len(content_b)},
        }
        yield path, state, expected_a, expected_b
    finally:
        service.close()
        thread.join(timeout=5)


def _snapshot(response: dict[str, Any]) -> dict[str, Any]:
    assert response["status"] == 200, response
    body = response["body"]
    assert body["ok"] is True and body["outcome"] == "completed"
    assert body["entry_ids"] == [] and body["record_ids"] == []
    assert "result" in body and len(body["result"]) == 1
    snapshot = body["result"][0]
    assert snapshot["schema_version"] == TELEMETRY_REPORT_SCHEMA
    return snapshot


def _assert_matches(snapshot: dict[str, Any], expected: dict[str, Any]) -> None:
    for key, value in expected.items():
        assert snapshot[key] == value, (key, snapshot[key], value)


def test_b7_telemetry_snapshot_is_numerically_consistent_with_its_fixture(live) -> None:
    """Provider error, degraded, and dedupe-hit fixture classes in one closed shape."""

    path, _state_root, expected_a, expected_b = live

    snapshot_a = _snapshot(_exchange(path, _telemetry("telemetry-a", owner_id="reader-a", policy_id="policy-a")))
    _assert_matches(snapshot_a, expected_a)
    assert snapshot_a["freshness"]["freshest_capture_at"] is not None
    assert snapshot_a["consumer_lag"] == {"unindexed_events": 0, "index_current": True}
    assert snapshot_a["recovery"] == {"journal_valid": True}
    assert set(snapshot_a) == {
        "schema_version", "generated_at", "total_events", "outcomes", "provider_errors",
        "capture_completeness", "unprocessed_demand", "dedupe", "spend", "freshness",
        "consumer_lag", "recovery",
    }

    snapshot_b = _snapshot(_exchange(path, _telemetry("telemetry-b", owner_id="reader-b", policy_id="policy-b")))
    _assert_matches(snapshot_b, expected_b)
    assert snapshot_b["consumer_lag"] == {"unindexed_events": 0, "index_current": True}
    assert snapshot_b["recovery"] == {"journal_valid": True}


def test_b7_telemetry_never_leaks_a_count_across_a_policy_partition(live) -> None:
    """Reader-a and reader-b each see exactly their own partition's totals, never the sum."""

    path, _state_root, expected_a, expected_b = live

    snapshot_a = _snapshot(_exchange(path, _telemetry("leak-a", owner_id="reader-a", policy_id="policy-a")))
    snapshot_b = _snapshot(_exchange(path, _telemetry("leak-b", owner_id="reader-b", policy_id="policy-b")))

    assert snapshot_a["total_events"] == expected_a["total_events"]
    assert snapshot_b["total_events"] == expected_b["total_events"]
    combined = expected_a["total_events"] + expected_b["total_events"]
    assert snapshot_a["total_events"] != combined and snapshot_b["total_events"] != combined

    # Partition B's provider-refused and degraded events must not surface in
    # partition A's counts, and partition A's dedupe hit must not surface in B.
    assert snapshot_a["outcomes"]["refused"] == 0 and snapshot_a["outcomes"]["degraded"] == 0
    assert snapshot_b["dedupe"]["duplicate_events"] == 0
    assert snapshot_a["spend"]["cost"] == expected_a["spend"]["cost"]
    assert snapshot_b["spend"]["cost"] == expected_b["spend"]["cost"]


def test_b7_telemetry_reports_consumer_lag_against_the_disposable_index(live) -> None:
    """Consumer lag is the caller's own authorized entries the index has not absorbed yet."""

    path, state, expected_a, _expected_b = live

    with Projection(state) as projection:
        projection.delete()

    snapshot = _snapshot(_exchange(path, _telemetry("lag-a", owner_id="reader-a", policy_id="policy-a")))
    assert snapshot["consumer_lag"] == {"unindexed_events": expected_a["total_events"], "index_current": False}
    # Deleting the index never changes canonical truth: every other signal is unaffected.
    assert snapshot["total_events"] == expected_a["total_events"] and snapshot["recovery"] == {"journal_valid": True}

    # A live commit's own refresh cannot prove it extends a missing index, so
    # it falls back to a full rebuild (B9/B11) -- proving the read side and
    # the write side agree on what "current" means.
    response = _exchange(path, _search_commit(owner_id="writer-a", policy_id="policy-a", request_id="a-lag-refresh", query="caregiver-a-refresh"))
    assert response["status"] == 200, response
    reference = _snapshot(_exchange(path, _telemetry("lag-a-again", owner_id="reader-a", policy_id="policy-a")))
    assert reference["consumer_lag"] == {"unindexed_events": 0, "index_current": True}
    assert reference["total_events"] == expected_a["total_events"] + 1


def test_b7_telemetry_reflects_an_interrupted_recovery(tmp_path: Path) -> None:
    """The interrupted fixture class: durable, non-complete, counted as unprocessed demand."""

    interrupted_content = b"a distinct interrupted-recovery source payload"
    state = _state(tmp_path, (hashlib.sha256(interrupted_content).hexdigest(),))
    route = resolve_route("POST", "/v1/ingest/file", require_available=True)
    request = parse_commit_request(
        _file_commit(owner_id="writer-a", policy_id="policy-a", request_id="interrupted", content=interrupted_content)["body"],
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

    service, thread, path = _serve(state, tmp_path)
    try:
        snapshot = _snapshot(_exchange(path, _telemetry("interrupted-telemetry", owner_id="reader-a", policy_id="policy-a")))
        assert snapshot["total_events"] == 1
        assert snapshot["outcomes"] == {"completed": 0, "partial": 0, "failed": 0, "degraded": 0, "refused": 0, "interrupted": 1}
        assert snapshot["capture_completeness"] == {"count": 0, "rate": 0.0}
        assert snapshot["unprocessed_demand"] == {"count": 1, "rate": 1.0}
        assert snapshot["provider_errors"] == {"count": 0, "rate": 0.0}
        assert snapshot["recovery"] == {"journal_valid": True}
    finally:
        service.close()
        thread.join(timeout=5)


def test_b7_telemetry_denies_unauthorized_scopes_generically(live) -> None:
    path, _state_root, _a, _b = live

    denials = {
        "no-rule": _telemetry("no-rule", policy_id="absent-policy"),
        "no-telemetry-grant": _telemetry("no-telemetry-grant", owner_id="stranger", policy_id="stranger-policy"),
        "above-the-access-ceiling": _telemetry("above-the-access-ceiling", owner_id="narrow", policy_id="narrow-policy"),
    }
    for request_id, frame in denials.items():
        response = _exchange(path, frame)
        assert response["status"] == 404, (request_id, response)
        assert response["body"] == {**GENERIC_404, "request_id": request_id}, (request_id, response)


def test_b7_telemetry_rejects_unknown_fields_and_wrong_bindings(live) -> None:
    path, _state_root, _a, _b = live

    invalid = {
        "unknown-payload-field": _telemetry("unknown-payload-field", payload={"filter": {}}),
        "idempotency-key": _telemetry("idempotency-key", extra={"idempotency_key": "not-permitted"}),
        "capability-mismatch": _telemetry("capability-mismatch", capability="journal.query"),
        "telemetry-on-verify-route": _read(path="/v1/journal/verify", operation="service.telemetry", payload={}, request_id="telemetry-on-verify-route", owner_id="reader-a", policy_id="policy-a"),
        "verify-on-telemetry-route": _read(path="/v1/telemetry", operation="journal.verify", payload={}, request_id="verify-on-telemetry-route", owner_id="reader-a", policy_id="policy-a"),
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


def test_b7_telemetry_is_unavailable_when_the_frozen_policy_changes(live) -> None:
    path, state, _a, _b = live
    policy = state / "service" / "policy.json"
    replacement = json.loads(policy.read_bytes().decode("utf-8"))
    replacement["rules"] = replacement["rules"][:1]
    policy.write_bytes(canonical_bytes(replacement))

    response = _exchange(path, _telemetry("telemetry-frozen"))
    assert response["status"] == 503, response
    assert response["body"] == {
        "schema_version": "houndd.read-response.v1",
        "request_id": "telemetry-frozen",
        "ok": False,
        "outcome": "unavailable",
        "record_ids": [],
        "entry_ids": [],
        "usage": {"requests": 0, "bytes": 0, "cost": 0},
        "error": UNAVAILABLE_ERROR,
    }, response


def test_b7_telemetry_snapshot_is_free_of_credentials_phi_and_snippets(live) -> None:
    """Retain a redacted snapshot plus a consistency report as evidence artifacts."""

    path, _state_root, expected_a, expected_b = live

    snapshot_a = _snapshot(_exchange(path, _telemetry("evidence-a", owner_id="reader-a", policy_id="policy-a")))
    snapshot_b = _snapshot(_exchange(path, _telemetry("evidence-b", owner_id="reader-b", policy_id="policy-b")))

    # The closed shape carries no URL, snippet, credential, or record body: it
    # is exactly the eleven top-level keys the schema declares, and every
    # leaf is a count, a rate, a sum, a timestamp, or a boolean.
    forbidden_substrings = ("example.test", "EXA_API_KEY", "FIRECRAWL", "caregiver source bytes", "body_base64")
    for snapshot in (snapshot_a, snapshot_b):
        blob = json.dumps(snapshot)
        for needle in forbidden_substrings:
            assert needle not in blob, (needle, blob)

    def _stable(value):
        """Normalize per-run identifiers so the retained artifact is deterministic."""
        import re as _re
        if isinstance(value, dict):
            return {key: _stable(item) for key, item in value.items()}
        if isinstance(value, list):
            return [_stable(item) for item in value]
        if isinstance(value, str):
            if _re.fullmatch(r"[0-9a-f]{64}", value):
                return "<sha256>"
            if _re.match(r"\d{4}-\d{2}-\d{2}T", value):
                return "<timestamp>"
        return value

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    (EVIDENCE_DIR / "telemetry-snapshot.json").write_text(json.dumps({"policy-a": _stable(snapshot_a), "policy-b": _stable(snapshot_b)}, indent=2, sort_keys=True) + "\n")
    consistency = {
        "policy-a": {"expected": expected_a, "observed": {key: snapshot_a[key] for key in expected_a}},
        "policy-b": {"expected": expected_b, "observed": {key: snapshot_b[key] for key in expected_b}},
        "consistent": all(snapshot_a[key] == value for key, value in expected_a.items()) and all(snapshot_b[key] == value for key, value in expected_b.items()),
    }
    (EVIDENCE_DIR / "consistency-report.json").write_text(json.dumps(consistency, indent=2, sort_keys=True) + "\n")
    assert consistency["consistent"] is True


def test_b7_telemetry_route_reports_the_recovery_verdict_it_aggregates_over(live) -> None:
    """``recovery.journal_valid`` mirrors B6's verify verdict when a snapshot exists."""

    path, state, _a, _b = live
    assert verify_store(state, projection=False)["valid"] is True
    snapshot = _snapshot(_exchange(path, _telemetry("recovery-ok", owner_id="reader-a", policy_id="policy-a")))
    assert snapshot["recovery"]["journal_valid"] is True


def test_b7_telemetry_maps_a_broken_snapshot_to_unavailable_like_query_and_entry_do(live) -> None:
    """Telemetry aggregates real event data, so a broken snapshot outranks shape.

    ``journal.verify`` deliberately answers even a broken store (B6): it is a
    diagnostic that must never itself be an outage. Telemetry is not that
    route -- it needs the same verified event snapshot ``journal.query``,
    ``journal.get``, and ``record.get`` need to compute a real count, so a
    journal too broken to snapshot is unavailable for telemetry exactly as it
    is for those routes, not a false-but-answered verdict.
    """

    path, state, _a, _b = live
    events = state / "journal" / "events.jsonl"
    events.write_bytes(events.read_bytes().replace(b'"sequence":0', b'"sequence":7'))

    response = _exchange(path, _telemetry("recovery-tampered", owner_id="reader-a", policy_id="policy-a"))
    assert response["status"] == 503, response
    assert response["body"]["error"] == UNAVAILABLE_ERROR, response
