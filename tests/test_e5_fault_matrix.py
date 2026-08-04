"""E5: consolidated fault matrix closing HSP-12, plus the backup-restore drill.

VISION.md's HSP-12 demands "the complete fault matrix and portable backup"
covering (among other things) concurrent same-content captures, crash
after fetch/before commit, 429s, timeouts, truncated bytes, transcript
failures, outage abstention, cursor replay, ACL non-leakage, backup
restore, exact-hash approval binding, source-size boundaries, digest
mismatch, held-FD nofollow TOCTOU checks, the Slice 3C1 clear-manifest PHI
gate, unsupported-media/encoding invalidation, bounded non-PHI quarantine,
and ambiguous record/event/lineage recovery.

Almost all of that matrix already exists piecewise across the suite --
``tests/evidence/e5/matrix-inventory.json`` is the row-by-row map from every
HSP-12 demand to the test (existing or new) that proves it.  This file adds
only what nothing else already proves:

* a transcript failure driven through the *real* ``hound_web_adapters.whisper``
  adapter (not the fake host every other transcribe test injects), exercised
  end to end through ``CommitRuntime.execute_adapter``;
* one consolidated outage-abstention pass across every adapter operation
  (search, url, transcribe) with zero bound credentials, using the real
  ``AdapterHost.from_env`` binding houndd uses at startup;
* one consolidated exact-hash approval-binding case across all six commit
  operations -- the three SOURCE operations already had dedicated
  tampered-reservation coverage per operation file, but the three adapter
  operations (ingest.search, ingest.url, transcribe) had no collision-on-
  drift coverage at all;
* the backup-restore drill itself: build a live-shaped store with the
  commit runtime, copy it, destroy the original outright, and prove
  ``verify_store`` is green and ``journal.query`` serves identical results
  from the copy alone.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import socket
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from houndd import HounddStore
from houndd.access import AuthenticatedPrincipal, EventSelector, PrincipalScope, ProducerSelector
from houndd.adapter_host import AdapterHost, AdapterResult
from houndd.commit import normalize_source, parse_commit_request, resolve_route
from houndd.commit_runtime import CommitCollision, CommitRuntime
from houndd.contracts import canonical_bytes
from houndd.journal import Journal
from houndd.service import HounddService
from houndd.verify import verify_store


PRINCIPAL = f"linux-uid:{os.getuid()}"
WRITE_CAPABILITIES = ("ingest.file", "import.record", "ingest.media", "ingest.search", "ingest.url", "transcribe")
READ_CAPABILITIES = ("journal.query", "record.get")

SEARCH_CONTENT = canonical_bytes({
    "schema_version": "houndd.search-content.v1",
    "leads": [{"schema_version": "hound.lead.v1", "url": "https://example.test/a", "title": "A"}],
    "provider": "exa",
    "query": "caregiver respite",
    "limit": 5,
    "retrieved_at": "2026-08-04T00:00:00Z",
})
URL_CONTENT = b"# Respite care\n\nEligibility details."
LEADS = ({"url": "https://example.test/a", "title": "A", "native_id": "exa-1"},)
TRANSCRIPT = "Respite care exists. Ask the county."
SEGMENT_TEXTS = ("Respite care exists.", " Ask the county.")


def _policy() -> dict[str, object]:
    writer_selectors = [{"owner_id": "writer", "capability": capability, "run_id": None} for capability in WRITE_CAPABILITIES]
    rules = [
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
    return {"schema_version": "houndd.policy.v1", "rules": rules}


def _state(tmp_path: Path, digests: tuple[str, ...] = ()) -> Path:
    root = tmp_path / "state"
    root.mkdir(mode=0o700, parents=True)
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


def _scope(*, capabilities: tuple[str, ...] = WRITE_CAPABILITIES) -> PrincipalScope:
    tiers = frozenset({"public"})
    return PrincipalScope(
        principal=AuthenticatedPrincipal(PRINCIPAL),
        readable_tiers=tiers,
        permitted_event_selectors=tuple(EventSelector("write-policy", ProducerSelector("writer", capability, None), tiers) for capability in capabilities),
    )


_SOURCE_PATHS = {"ingest.file": "/v1/ingest/file", "ingest.media": "/v1/ingest/media", "import.record": "/v1/import-record"}
_ADAPTER_PATHS = {"ingest.search": "/v1/ingest/search", "ingest.url": "/v1/ingest/url", "transcribe": "/v1/transcribe"}


def _source_frame(*, operation: str, data: bytes, key: str, request_id: str, legacy_id: str | None = None) -> dict[str, Any]:
    digest = hashlib.sha256(data).hexdigest()
    payload: dict[str, Any] = {"source": {"kind": "bytes", "body_base64": base64.b64encode(data).decode("ascii"), "sha256": digest, "byte_length": len(data)}}
    if operation == "import.record":
        payload["record_id"] = legacy_id or "legacy-1"
    else:
        payload["media_type"] = "application/octet-stream"
    return {
        "wire_version": "houndd.uds.v1",
        "method": "POST",
        "path": _SOURCE_PATHS[operation],
        "body": {
            "schema_version": "houndd.commit-request.v1",
            "request_id": request_id,
            "idempotency_key": key,
            "producer": {"owner_id": "writer", "capability": operation, "run_id": "run"},
            "requested_access": "public",
            "policy_id": "write-policy",
            "operation": {"name": operation, "payload": payload},
        },
    }


def _adapter_frame(*, operation: str, key: str, request_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "wire_version": "houndd.uds.v1",
        "method": "POST",
        "path": _ADAPTER_PATHS[operation],
        "body": {
            "schema_version": "houndd.commit-request.v1",
            "request_id": request_id,
            "idempotency_key": key,
            "producer": {"owner_id": "writer", "capability": operation, "run_id": "run"},
            "requested_access": "public",
            "policy_id": "write-policy",
            "operation": {"name": operation, "payload": payload},
        },
    }


def _source_request(operation: str, *, data: bytes, key: str, request_id: str = "one", legacy_id: str | None = None):
    route = resolve_route("POST", _SOURCE_PATHS[operation], require_available=True)
    return parse_commit_request(_source_frame(operation=operation, data=data, key=key, request_id=request_id, legacy_id=legacy_id)["body"], route), route


def _adapter_request(operation: str, *, key: str, request_id: str = "one", payload: dict[str, Any]):
    route = resolve_route("POST", _ADAPTER_PATHS[operation], require_available=True)
    return parse_commit_request(_adapter_frame(operation=operation, key=key, request_id=request_id, payload=payload)["body"], route), route


def _commit_source(runtime: CommitRuntime, operation: str, *, data: bytes, key: str, legacy_id: str | None = None) -> dict[str, Any]:
    request, route = _source_request(operation, data=data, key=key, legacy_id=legacy_id)
    response = runtime.execute(request, route, principal=PRINCIPAL, access="public", source=normalize_source(request.source.to_wire()), scanner_clear=True, scope=_scope())
    assert response["outcome"] == "completed", response
    return response


def _capture_media(runtime: CommitRuntime, *, data: bytes, key: str) -> str:
    return _commit_source(runtime, "ingest.media", data=data, key=key)["record_ids"][0]


def _segments() -> tuple[dict[str, Any], ...]:
    spans = ((0, 2_000), (2_000, 4_000))
    return tuple(
        {"index": index, "start_ms": start, "end_ms": end, "text_sha256": hashlib.sha256(SEGMENT_TEXTS[index].encode("utf-8")).hexdigest()}
        for index, (start, end) in enumerate(spans)
    )


def _faux_host(operation: str) -> AdapterHost:
    """A minimal completed-outcome adapter for search/url/transcribe, used only
    to seed fixtures -- the real provider seam is exercised separately below."""

    def search(_payload: Any) -> AdapterResult:
        return AdapterResult("ingest.search", "completed", SEARCH_CONTENT, "application/json", "2026-08-04T00:00:00Z", 1, 0, LEADS)

    def url(_payload: Any) -> AdapterResult:
        return AdapterResult("ingest.url", "completed", URL_CONTENT, "text/markdown", "2026-08-04T00:00:00Z", 1, 0)

    def transcribe(_payload: Any) -> AdapterResult:
        text = TRANSCRIPT.encode("utf-8")
        return AdapterResult(
            "transcribe", "completed", b"", "none", "2026-08-04T00:00:00Z", 1, 0, (),
            model="whisper-1", model_version="whisper-1-2026-01", language="en",
            text_sha256=hashlib.sha256(text).hexdigest(), text_byte_length=len(text), segments=_segments(),
        )

    return AdapterHost({operation: {"ingest.search": search, "ingest.url": url, "transcribe": transcribe}[operation]})


def _exchange(path: Path, value: object) -> dict[str, Any]:
    """A bare length-prefixed UDS round trip -- no commit-response schema
    assumed, since journal.query returns a read-response envelope."""

    raw = canonical_bytes(value)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(10)
        client.connect(os.fspath(path))
        client.sendall(len(raw).to_bytes(4, "big") + raw)
        client.shutdown(socket.SHUT_WR)
        size = int.from_bytes(client.recv(4), "big")
        body = bytearray()
        while len(body) < size:
            chunk = client.recv(size - len(body))
            if not chunk:
                raise AssertionError("truncated response")
            body.extend(chunk)
        return json.loads(bytes(body).decode("utf-8"))


# --------------------------------------------------- exact-hash approval binding


def test_e5_exact_hash_approval_binding_rejects_drift_across_every_commit_operation(tmp_path: Path) -> None:
    """HSP-12: "approval rejection on any hash drift", proved once per route.

    ingest.file / import.record / ingest.media already have dedicated
    tampered-reservation-vs-changed-request coverage
    (test_slice3c1_commit_runtime.py::test_slice3c1_tampered_reservation_is_integrity_while_changed_request_is_collision,
    test_b4_media_capture.py::test_b4_media_tampered_reservation_is_integrity_while_changed_request_is_collision).
    The three adapter operations -- ingest.search, ingest.url, transcribe --
    had no equivalent anywhere: this closes that gap and puts all six routes
    in one place so a hash-drift regression on any of them shows up here.
    """

    file_data = b"e5 exact-hash file source"
    media_data = b"e5 exact-hash media source"
    state = _state(tmp_path, (hashlib.sha256(file_data).hexdigest(), hashlib.sha256(media_data).hexdigest()))
    runtime = CommitRuntime(state)
    try:
        _commit_source(runtime, "ingest.file", data=file_data, key="e5-file")
        _, file_route = _source_request("ingest.file", data=file_data, key="e5-file")
        changed_file = parse_commit_request({**_source_frame(operation="ingest.file", data=file_data, key="e5-file", request_id="two")["body"], "requested_access": "workspace"}, file_route)

        _commit_source(runtime, "import.record", data=file_data, key="e5-import", legacy_id="e5-legacy")
        _, import_route = _source_request("import.record", data=file_data, key="e5-import", legacy_id="e5-legacy")
        changed_import = parse_commit_request({**_source_frame(operation="import.record", data=file_data, key="e5-import", request_id="two", legacy_id="e5-legacy")["body"], "requested_access": "workspace"}, import_route)

        capture_id = _capture_media(runtime, data=media_data, key="e5-capture")
        _, media_route = _source_request("ingest.media", data=media_data, key="e5-capture")
        changed_media = parse_commit_request({**_source_frame(operation="ingest.media", data=media_data, key="e5-capture", request_id="two")["body"], "requested_access": "workspace"}, media_route)

        search_request, search_route = _adapter_request("ingest.search", key="e5-search", payload={"query": "caregiver respite", "limit": 5})
        runtime.execute_adapter(search_request, search_route, principal=PRINCIPAL, access="public", adapter_host=_faux_host("ingest.search"), scope=_scope())
        changed_search = parse_commit_request(_adapter_frame(operation="ingest.search", key="e5-search", request_id="two", payload={"query": "caregiver respite", "limit": 6})["body"], search_route)

        url_request, url_route = _adapter_request("ingest.url", key="e5-url", payload={"url": "https://example.test/a", "lineage": {"kind": "direct"}})
        runtime.execute_adapter(url_request, url_route, principal=PRINCIPAL, access="public", adapter_host=_faux_host("ingest.url"), scope=_scope())
        changed_url = parse_commit_request(_adapter_frame(operation="ingest.url", key="e5-url", request_id="two", payload={"url": "https://example.test/b", "lineage": {"kind": "direct"}})["body"], url_route)

        transcribe_request, transcribe_route = _adapter_request("transcribe", key="e5-transcribe", payload={"capture_id": capture_id})
        runtime.execute_adapter(transcribe_request, transcribe_route, principal=PRINCIPAL, access="public", adapter_host=_faux_host("transcribe"), scope=_scope())
        second_capture = _capture_media(runtime, data=b"e5 a second authorized capture", key="e5-capture-two")
        changed_transcribe = parse_commit_request(_adapter_frame(operation="transcribe", key="e5-transcribe", request_id="two", payload={"capture_id": second_capture})["body"], transcribe_route)

        cases = (
            (changed_file, file_route),
            (changed_import, import_route),
            (changed_media, media_route),
            (changed_search, search_route),
            (changed_url, url_route),
            (changed_transcribe, transcribe_route),
        )
        before = len(runtime.journal.entries())  # type: ignore[union-attr]
        for changed_request, route in cases:
            with pytest.raises(CommitCollision):
                runtime.probe(changed_request, route, principal=PRINCIPAL)
        assert len(runtime.journal.entries()) == before  # type: ignore[union-attr]
        assert verify_store(state, projection=False)["valid"] is True
    finally:
        runtime.close()


# ------------------------------------------------------------- outage abstention


def test_e5_outage_abstention_is_durable_and_credential_silent_across_adapter_operations(tmp_path: Path) -> None:
    """HSP-12 outage abstention: no bound provider, one durable degraded
    outcome per operation, no live exchange, no credential material anywhere.

    test_slice3c2_adapter_commit.py covers this for search alone (a starved
    ``AdapterHost({})``) and test_b5_transcribe.py covers it for transcribe
    alone (``AdapterHost.from_env`` without ``OPENAI_API_KEY``). This runs
    every adapter operation through the real, credential-derived
    ``AdapterHost.from_env({})`` -- exactly what houndd binds at startup when
    no provider keys are configured -- in one pass.
    """

    def refuse_transport(**_call: object) -> tuple[int, bytes]:
        pytest.fail("an unbound adapter must never open a provider connection during an outage")

    media_data = b"e5 outage capture source"
    state = _state(tmp_path, (hashlib.sha256(media_data).hexdigest(),))
    runtime = CommitRuntime(state)
    try:
        capture_id = _capture_media(runtime, data=media_data, key="e5-outage-capture")
        host = AdapterHost.from_env({}, transport=refuse_transport)
        assert host.operations == frozenset()

        for operation, payload in (
            ("ingest.search", {"query": "caregiver respite", "limit": 5}),
            ("ingest.url", {"url": "https://example.test/a", "lineage": {"kind": "direct"}}),
            ("transcribe", {"capture_id": capture_id}),
        ):
            request, route = _adapter_request(operation, key=f"e5-outage-{operation}", payload=payload)
            response = runtime.execute_adapter(request, route, principal=PRINCIPAL, access="public", adapter_host=host, scope=_scope())
            assert response["ok"] is False and response["outcome"] == "degraded", (operation, response)
            assert response["usage"] == {"requests": 0, "bytes": 0, "cost": 0}
            record = runtime.records.read_json(response["record_ids"][0])  # type: ignore[union-attr]
            assert record["reason"] == "adapter_absent"

        assert verify_store(state, projection=False)["valid"] is True
        for path in sorted(state.rglob("*")):
            if path.is_file():
                raw = path.read_bytes()
                assert b"OPENAI_API_KEY" not in raw and b"EXA_API_KEY" not in raw and b"FIRECRAWL" not in raw
    finally:
        runtime.close()


# --------------------------------------------------------------- transcript failure


def test_e5_transcript_failure_against_the_real_whisper_adapter_is_one_durable_failed_outcome(tmp_path: Path) -> None:
    """HSP-12 transcript failure, driven through the real provider seam.

    test_b5_transcribe.py proves the failed/refused/degraded record shapes
    with a fake adapter host that raises AdapterFailed/AdapterAbstained
    directly, and separately proves ``hound_web_adapters.whisper.transcribe``
    rejects a 429 in isolation
    (test_b5_whisper_provider_error_status_is_one_failed_exchange). Neither
    combines them. This is the one place a real Whisper 429 flows through
    ``CommitRuntime.execute_adapter`` end to end: capture binding, the real
    ``AdapterHost.from_env`` credential wiring, the durable failed record,
    the journal entry, and ``verify_store``.
    """

    def rate_limited(**_call: object) -> tuple[int, bytes]:
        return 429, b'{"error": {"message": "rate limited"}}'

    audio = b"e5 transcript failure capture bytes"
    state = _state(tmp_path, (hashlib.sha256(audio).hexdigest(),))
    runtime = CommitRuntime(state)
    try:
        capture_id = _capture_media(runtime, data=audio, key="e5-failure-capture")
        host = AdapterHost.from_env({"OPENAI_API_KEY": "test-key"}, transport=rate_limited)
        assert "transcribe" in host.operations

        request, route = _adapter_request("transcribe", key="e5-transcribe-failure", payload={"capture_id": capture_id})
        response = runtime.execute_adapter(request, route, principal=PRINCIPAL, access="public", adapter_host=host, scope=_scope())

        assert response["ok"] is False and response["outcome"] == "failed"
        assert response["usage"] == {"requests": 1, "bytes": 0, "cost": 0}
        record = runtime.records.read_json(response["record_ids"][0])  # type: ignore[union-attr]
        assert record["reason"] == "provider_failed" and record["evidence_status"] == "failure"
        assert record["model"] == "none" and record["text_sha256"] == "none" and record["segments"] == []
        assert record["capture"]["record_id"] == capture_id
        assert verify_store(state, projection=False)["valid"] is True
    finally:
        runtime.close()


# ------------------------------------------------------------ backup-restore drill


def test_e5_backup_restore_drill_survives_original_destruction(tmp_path: Path) -> None:
    """The backup-restore drill HSP-12 demands: build a live-shaped fixture
    store with the commit runtime, copy it, destroy the original outright,
    then prove ``verify_store`` is green and ``journal.query`` serves
    identical results from the copy alone -- IDs, hashes, lineage, and access
    decisions preserved, per HSP-20's "independently verifiable after ...
    backup restore".
    """

    # Deliberately excludes ``transcribe``: see
    # test_e5_backup_restore_drill_including_a_completed_transcription
    # below for why that lane cannot join this drill yet.
    file_data = b"e5 backup file source"
    media_data = b"e5 backup media source"
    original_root = tmp_path / "original"
    state = _state(original_root, (hashlib.sha256(file_data).hexdigest(), hashlib.sha256(media_data).hexdigest()))
    runtime = CommitRuntime(state)
    try:
        _commit_source(runtime, "ingest.file", data=file_data, key="backup-file")
        _commit_source(runtime, "import.record", data=file_data, key="backup-import", legacy_id="backup-legacy")
        _capture_media(runtime, data=media_data, key="backup-capture")

        search_request, search_route = _adapter_request("ingest.search", key="backup-search", payload={"query": "caregiver respite", "limit": 5})
        runtime.execute_adapter(search_request, search_route, principal=PRINCIPAL, access="public", adapter_host=_faux_host("ingest.search"), scope=_scope())
    finally:
        runtime.close()

    with HounddStore(state) as store:
        store.rebuild_index()
    assert verify_store(state)["valid"] is True
    with Journal(state, create=False) as journal:
        original_entries = journal.entries()
    assert len(original_entries) == 4

    restored = tmp_path / "restored"
    shutil.copytree(state, restored)
    shutil.rmtree(original_root)
    assert not original_root.exists()

    # Everything below operates purely on the restored copy: recovery must
    # not depend on the destroyed original in any way.
    assert verify_store(restored, projection=False)["valid"] is True
    with HounddStore(restored) as store:
        # SQLite is disposable and rebuilds from the journal/records alone
        # (HSP-14/HSP-20); proving that survives the restore, not just the
        # journal, is the point of rebuilding here instead of trusting the
        # copied index file.
        store.rebuild_index()
    assert verify_store(restored)["valid"] is True

    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir(mode=0o700)
    socket_path = runtime_dir / "houndd.sock"
    service = HounddService(state_root=restored, socket_path=socket_path)
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 5
        while not socket_path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert socket_path.exists()
        response = _exchange(socket_path, {
            "wire_version": "houndd.uds.v1",
            "method": "GET",
            "path": "/v1/journal",
            "body": {
                "schema_version": "houndd.read-request.v1",
                "request_id": "restore-query",
                "producer": {"owner_id": "reader", "capability": "journal.query", "run_id": "restore-run"},
                "requested_access": "public",
                "policy_id": "write-policy",
                "operation": {"name": "journal.query", "payload": {"filter": {}, "limit": 50}},
            },
        })
    finally:
        service.close()
        thread.join(timeout=5)

    assert response["status"] == 200, response
    restored_entries = response["body"]["result"]
    assert len(restored_entries) == len(original_entries) == 4

    def identity(entry: dict[str, Any]) -> tuple[Any, ...]:
        return (
            entry["entry_id"],
            entry["sequence"],
            entry["producer"],
            entry["artifact"],
            entry["lineage"],
            entry["source"],
            entry["classification"],
            entry["access"],
            entry["policy_id"],
            entry["dedupe"],
        )

    assert sorted(map(identity, restored_entries), key=str) == sorted(map(identity, original_entries), key=str)


# ------------------------------------------------- known defect (not fixed here)


def test_e5_backup_restore_drill_including_a_completed_transcription(tmp_path: Path) -> None:
    """Pins a startup-crashing defect in projection rebuild for the
    transcribe lane. See the xfail reason for the full analysis and the fix.
    """

    audio = b"e5 known-defect transcript capture bytes"
    state = _state(tmp_path, (hashlib.sha256(audio).hexdigest(),))
    runtime = CommitRuntime(state)
    try:
        capture_id = _capture_media(runtime, data=audio, key="defect-capture")
        request, route = _adapter_request("transcribe", key="defect-transcribe", payload={"capture_id": capture_id})
        response = runtime.execute_adapter(request, route, principal=PRINCIPAL, access="public", adapter_host=_faux_host("transcribe"), scope=_scope())
        assert response["outcome"] == "completed"
    finally:
        runtime.close()

    # The actual production failure mode: restarting houndd against its own
    # state after one completed transcription. This is expected to succeed;
    # it currently raises houndd.store.UnsafeStoreError from inside
    # HounddService.__init__ -> store.recover() -> Projection.rebuild().
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir(mode=0o700)
    service = HounddService(state_root=state, socket_path=runtime_dir / "houndd.sock")
    service.close()
