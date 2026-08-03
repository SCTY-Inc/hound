"""Slice 3D authorized read routes: one journal entry or one stored object."""

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
from houndd.contracts import canonical_bytes, canonical_hash
from houndd.service import HounddService


PRINCIPAL = f"linux-uid:{os.getuid()}"
WRITE_CAPABILITIES = ("ingest.search", "ingest.url", "ingest.file", "import.record")
READ_CAPABILITIES = ("journal.get", "record.get")
SEARCH_CONTENT = canonical_bytes({
    "schema_version": "houndd.search-content.v1",
    "leads": [{"schema_version": "hound.lead.v1", "url": "https://example.test/a", "title": "A"}],
    "provider": "exa",
    "query": "caregiver respite",
    "limit": 5,
    "retrieved_at": "2026-08-03T00:00:00Z",
})
URL_CONTENT = b"# Respite care\n\nEligibility details."
LEGACY_CONTENT = b"legacy caregiver intake record"
# Large enough that its base64 content alone exceeds the fixed wire bound,
# while the file record that names it stays comfortably inside it.
LARGE_CONTENT = (b"caregiver benefit corpus " * 36_000)[:900_000]
LEADS = ({"url": "https://example.test/a", "title": "A", "native_id": "exa-1"},)
GENERIC_404 = {
    "schema_version": "houndd.read-response.v1",
    "ok": False,
    "outcome": "not_found",
    "record_ids": [],
    "entry_ids": [],
    "usage": {"requests": 0, "bytes": 0, "cost": 0},
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
    # A resolvable scope that is granted a different policy partition: it must
    # learn exactly as little as a principal with no rule at all.
    rules += [
        {
            "subject": PRINCIPAL,
            "claim_selector": {"owner_id": "stranger", "capability": capability, "run_id": None},
            "policy_id": "stranger-policy",
            "event_producer_selectors": [{"owner_id": "stranger", "capability": capability, "run_id": None}],
            "readable_tiers": ["public"],
            "allowed_output_tiers": ["public"],
        }
        for capability in READ_CAPABILITIES
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
        "ingest.url": lambda _payload: AdapterResult("ingest.url", "completed", URL_CONTENT, "text/markdown", "2026-08-03T00:00:00Z", 1, 0),
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


def _commit(*, operation: str, payload: dict[str, Any], request_id: str) -> dict[str, Any]:
    paths = {
        "ingest.search": "/v1/ingest/search",
        "ingest.url": "/v1/ingest/url",
        "ingest.file": "/v1/ingest/file",
        "import.record": "/v1/import-record",
    }
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


def _read(
    *,
    path: str,
    operation: str,
    payload: dict[str, Any],
    request_id: str,
    owner_id: str = "reader",
    policy_id: str = "write-policy",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "schema_version": "houndd.read-request.v1",
        "request_id": request_id,
        "producer": {"owner_id": owner_id, "capability": operation, "run_id": "client-run"},
        "requested_access": "public",
        "policy_id": policy_id,
        "operation": {"name": operation, "payload": payload},
    }
    if extra is not None:
        body.update(extra)
    return {"wire_version": "houndd.uds.v1", "method": "GET", "path": path, "body": body}


def _entry(entry_id: str, *, request_id: str = "entry-request", **overrides: Any) -> dict[str, Any]:
    return _read(path="/v1/journal/entry", operation="journal.get", payload={"entry_id": entry_id}, request_id=request_id, **overrides)


def _record(record_id: str, *, include_content: bool | None = None, request_id: str = "record-request", **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {"record_id": record_id}
    if include_content is not None:
        payload["include_content"] = include_content
    return _read(path="/v1/record", operation="record.get", payload=payload, request_id=request_id, **overrides)


def _not_found(response: dict[str, Any], request_id: str) -> bool:
    return response["status"] == 404 and response["body"] == {**GENERIC_404, "request_id": request_id}


def _result(response: dict[str, Any]) -> dict[str, Any]:
    assert response["status"] == 200, response
    body = response["body"]
    assert body["ok"] is True and body["outcome"] == "completed" and "error" not in body
    assert len(body["result"]) == 1
    return body["result"][0]


@pytest.fixture
def live(tmp_path: Path):
    """One provisioned service with the four committed operations behind it."""

    source_path = tmp_path / "large-source.bin"
    source_path.write_bytes(LARGE_CONTENT)
    large_digest = hashlib.sha256(LARGE_CONTENT).hexdigest()
    legacy_digest = hashlib.sha256(LEGACY_CONTENT).hexdigest()
    state = _state(tmp_path, (large_digest, legacy_digest))
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    path = runtime / "houndd.sock"
    service = HounddService(state_root=state, socket_path=path, adapter_host=_host())
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 5
        while not path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        committed = {
            "search": _exchange(path, _commit(operation="ingest.search", payload={"query": "caregiver respite", "limit": 5}, request_id="commit-search")),
            "url": _exchange(path, _commit(operation="ingest.url", payload={"url": "https://example.test/a", "lineage": {"kind": "direct"}}, request_id="commit-url")),
            "file": _exchange(path, _commit(
                operation="ingest.file",
                payload={
                    "source": {"kind": "path", "path": os.fspath(source_path), "sha256": large_digest, "byte_length": len(LARGE_CONTENT)},
                    "media_type": "application/octet-stream",
                },
                request_id="commit-file",
            )),
            "import": _exchange(path, _commit(
                operation="import.record",
                payload={
                    "source": {"kind": "bytes", "body_base64": base64.b64encode(LEGACY_CONTENT).decode("ascii"), "sha256": legacy_digest, "byte_length": len(LEGACY_CONTENT)},
                    "record_id": "legacy-1",
                },
                request_id="commit-import",
            )),
        }
        for name, response in committed.items():
            assert response["status"] == 200 and response["body"]["outcome"] == "completed", (name, response)
        ids = {name: (response["body"]["record_ids"], response["body"]["entry_ids"][0]) for name, response in committed.items()}
        yield path, ids
    finally:
        service.close()
        thread.join(timeout=5)


def test_slice3d_search_record_read_returns_exact_record_and_staged_content(live) -> None:
    path, ids = live
    (record_id,), _entry_id = ids["search"]

    plain = _result(_exchange(path, _record(record_id)))
    assert set(plain) == {"schema", "record_id", "body_base64", "byte_length"}
    assert plain["schema"] == "houndd.search-record.v1" and plain["record_id"] == record_id
    body = base64.b64decode(plain["body_base64"].encode("ascii"), validate=True)
    assert plain["byte_length"] == len(body) and hashlib.sha256(body).hexdigest() == record_id
    assert json.loads(body.decode("utf-8"))["query"] == "caregiver respite"

    full = _result(_exchange(path, _record(record_id, include_content=True)))
    assert set(full) == {"schema", "record_id", "body_base64", "byte_length", "content_base64", "content_sha256", "content_byte_length"}
    assert base64.b64decode(full["content_base64"].encode("ascii"), validate=True) == SEARCH_CONTENT
    assert full["content_sha256"] == hashlib.sha256(SEARCH_CONTENT).hexdigest()
    assert full["content_byte_length"] == len(SEARCH_CONTENT)
    assert full["body_base64"] == plain["body_base64"]

    response = _exchange(path, _record(record_id, include_content=True))
    assert response["body"]["record_ids"] == [record_id] and response["body"]["entry_ids"] == []
    assert response["body"]["usage"] == {"requests": 0, "bytes": 0, "cost": 0}
    assert "cursor" not in response["body"] and "projection" not in response["body"]


def test_slice3d_extract_record_read_returns_its_markdown_blob(live) -> None:
    path, ids = live
    (record_id,), _entry_id = ids["url"]

    result = _result(_exchange(path, _record(record_id, include_content=True)))
    assert result["schema"] == "houndd.url-record.v1"
    assert base64.b64decode(result["content_base64"].encode("ascii"), validate=True) == URL_CONTENT
    assert result["content_sha256"] == hashlib.sha256(URL_CONTENT).hexdigest()
    assert result["content_byte_length"] == len(URL_CONTENT)
    record = json.loads(base64.b64decode(result["body_base64"].encode("ascii"), validate=True).decode("utf-8"))
    assert record["url"] == "https://example.test/a" and record["content_sha256"] == result["content_sha256"]


def test_slice3d_completed_import_reads_outcome_record_and_raw_legacy_object(live) -> None:
    path, ids = live
    (legacy_id, outcome_id), _entry_id = ids["import"]
    assert legacy_id == "legacy-1"

    # A completed import stages no blob: its raw bytes are the legacy object,
    # which is read separately rather than repeated inside the outcome record.
    outcome = _result(_exchange(path, _record(outcome_id, include_content=True)))
    assert set(outcome) == {"schema", "record_id", "body_base64", "byte_length"}
    assert outcome["schema"] == "houndd.import-outcome.v1"
    legacy = json.loads(base64.b64decode(outcome["body_base64"].encode("ascii"), validate=True).decode("utf-8"))["legacy"]
    assert legacy["record_id"] == legacy_id and legacy["sha256"] == hashlib.sha256(LEGACY_CONTENT).hexdigest()

    raw = _result(_exchange(path, _record(legacy_id, include_content=True)))
    assert set(raw) == {"schema", "record_id", "body_base64", "byte_length"}
    assert raw["schema"] == "raw" and raw["record_id"] == legacy_id
    assert base64.b64decode(raw["body_base64"].encode("ascii"), validate=True) == LEGACY_CONTENT
    assert raw["byte_length"] == len(LEGACY_CONTENT)


def test_slice3d_entry_read_returns_the_one_canonical_event(live) -> None:
    path, ids = live
    (record_id,), entry_id = ids["search"]

    response = _exchange(path, _entry(entry_id))
    event = _result(response)
    assert event["entry_id"] == entry_id and event["artifact"]["record_id"] == record_id
    assert event["schema_version"] == "houndd.journal.v1"
    assert event["entry_id"] == canonical_hash({key: value for key, value in event.items() if key != "entry_id"})
    assert response["body"]["entry_ids"] == [entry_id] and response["body"]["record_ids"] == [record_id]
    assert "cursor" not in response["body"] and "projection" not in response["body"]


def test_slice3d_unauthorized_and_absent_reads_are_one_generic_result(live, monkeypatch: pytest.MonkeyPatch) -> None:
    path, ids = live
    (record_id,), entry_id = ids["search"]
    absent_record = "f" * 64
    absent_entry = "e" * 64
    # Nothing below may resolve far enough to read a stored object at all.
    reads: list[str] = []
    monkeypatch.setattr("houndd.store.RecordStore.read", lambda _self, record: reads.append(record))

    denials = {
        "no-rule": _exchange(path, _record(record_id, request_id="no-rule", policy_id="absent-policy")),
        "other-partition": _exchange(path, _record(record_id, request_id="other-partition", owner_id="stranger", policy_id="stranger-policy")),
        "absent": _exchange(path, _record(absent_record, request_id="absent")),
        "content-denied": _exchange(path, _record(record_id, include_content=True, request_id="content-denied", owner_id="stranger", policy_id="stranger-policy")),
    }
    for name, response in denials.items():
        assert _not_found(response, name), (name, response)

    entry_denials = {
        "entry-no-rule": _exchange(path, _entry(entry_id, request_id="entry-no-rule", policy_id="absent-policy")),
        "entry-other-partition": _exchange(path, _entry(entry_id, request_id="entry-other-partition", owner_id="stranger", policy_id="stranger-policy")),
        "entry-absent": _exchange(path, _entry(absent_entry, request_id="entry-absent")),
    }
    for name, response in entry_denials.items():
        assert _not_found(response, name), (name, response)
    assert reads == []


def test_slice3d_read_envelopes_reject_unknown_fields_and_commit_idempotency(live) -> None:
    path, ids = live
    (record_id,), entry_id = ids["search"]

    invalid = {
        "unknown-record-field": _record(record_id, request_id="unknown-record-field"),
        "unknown-entry-field": _entry(entry_id, request_id="unknown-entry-field"),
        "wrong-include-type": _record(record_id, request_id="wrong-include-type"),
        "idempotent-read": _record(record_id, request_id="idempotent-read", extra={"idempotency_key": "not-permitted"}),
        "capability-mismatch": _record(record_id, request_id="capability-mismatch"),
        "wrong-route": _read(path="/v1/journal", operation="record.get", payload={"record_id": record_id}, request_id="wrong-route"),
    }
    invalid["unknown-record-field"]["body"]["operation"]["payload"]["view"] = "intake-ledger.v1"
    invalid["unknown-entry-field"]["body"]["operation"]["payload"]["limit"] = 10
    invalid["wrong-include-type"]["body"]["operation"]["payload"]["include_content"] = "true"
    invalid["capability-mismatch"]["body"]["producer"]["capability"] = "journal.query"

    for name, frame in invalid.items():
        response = _exchange(path, frame)
        assert response["status"] == 400, (name, response)
        assert response["body"]["ok"] is False and response["body"]["outcome"] == "invalid", (name, response)
        assert response["body"]["error"] == {"code": "invalid_request", "retryable": False, "message": "request is invalid"}, (name, response)
        assert response["body"]["record_ids"] == [] and response["body"]["entry_ids"] == [], (name, response)


def test_slice3d_oversize_content_refuses_rather_than_returning_partial_bytes(live) -> None:
    path, ids = live
    (record_id,), _entry_id = ids["file"]

    plain = _result(_exchange(path, _record(record_id)))
    assert plain["schema"] == "houndd.file-record.v1"
    record = json.loads(base64.b64decode(plain["body_base64"].encode("ascii"), validate=True).decode("utf-8"))
    assert record["source"]["sha256"] == hashlib.sha256(LARGE_CONTENT).hexdigest()
    assert record["source"]["byte_length"] == len(LARGE_CONTENT)

    response = _exchange(path, _record(record_id, include_content=True, request_id="oversize"))
    assert response["status"] == 400
    assert response["body"] == {
        "schema_version": "houndd.read-response.v1",
        "request_id": "oversize",
        "ok": False,
        "outcome": "invalid",
        "record_ids": [],
        "entry_ids": [],
        "usage": {"requests": 0, "bytes": 0, "cost": 0},
        "error": {"code": "content_too_large", "retryable": False, "message": "record content is too large"},
    }
