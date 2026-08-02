"""Slice 3C1B durable POST integration: two local operations only."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import threading
import time

import pytest

from houndd import HounddStore
from houndd.contracts import canonical_bytes, canonical_hash
from houndd.service import HounddService
from houndd.access import AuthenticatedPrincipal
from houndd.commit import make_commit_response, parse_commit_request, resolve_route, normalize_source
from houndd.commit_runtime import CommitRuntime, CommitCollision, CommitIntegrityError
from houndd.verify import verify_store
from hound_research.commit_client import CommitClientError, exchange, exit_code, strict_response


def _policy() -> dict[str, object]:
    return {
        "schema_version": "houndd.policy.v1",
        "rules": [{
            "subject": f"linux-uid:{os.getuid()}",
            "claim_selector": {"owner_id": "writer", "capability": "ingest.file", "run_id": None},
            "policy_id": "write-policy",
            "event_producer_selectors": [{"owner_id": "writer", "capability": "ingest.file", "run_id": None}],
            "readable_tiers": ["public"],
            "allowed_output_tiers": ["public"],
        }, {
            "subject": f"linux-uid:{os.getuid()}",
            "claim_selector": {"owner_id": "writer", "capability": "import.record", "run_id": None},
            "policy_id": "write-policy",
            "event_producer_selectors": [{"owner_id": "writer", "capability": "import.record", "run_id": None}],
            "readable_tiers": ["public"],
            "allowed_output_tiers": ["public"],
        }],
    }


def _state(tmp_path: Path, data: bytes) -> Path:
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    HounddStore(root).close()
    service = root / "service"
    service.mkdir(mode=0o700)
    (service / "policy.json").write_bytes(canonical_bytes(_policy()))
    (service / "policy.json").chmod(0o600)
    digest = hashlib.sha256(data).hexdigest()
    (service / "phi-clear.json").write_bytes(canonical_bytes({
        "schema_version": "houndd.phi-clear.v1",
        "entries": [{"sha256": digest, "media_type": "application/octet-stream", "encoding": "identity"}],
    }))
    (service / "phi-clear.json").chmod(0o600)
    return root


def _frame(*, operation: str, data: bytes, key: str, request_id: str, legacy_id: str | None = None) -> dict[str, object]:
    digest = hashlib.sha256(data).hexdigest()
    payload: dict[str, object] = {
        "source": {"kind": "bytes", "body_base64": base64.b64encode(data).decode("ascii"), "sha256": digest, "byte_length": len(data)},
    }
    path = "/v1/ingest/file"
    if operation == "ingest.file":
        payload["media_type"] = "application/octet-stream"
    else:
        path = "/v1/import-record"
        payload["record_id"] = legacy_id or "legacy-1"
    return {
        "wire_version": "houndd.uds.v1",
        "method": "POST",
        "path": path,
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


def test_slice3c1_file_commit_replay_and_import_occurrence(tmp_path: Path) -> None:
    data = b"local certified source"
    state = _state(tmp_path, data)
    principal = f"linux-uid:{os.getuid()}"
    file_route = resolve_route("POST", "/v1/ingest/file", require_available=True)
    file_request = parse_commit_request(_frame(operation="ingest.file", data=data, key="file-key", request_id="one")["body"], file_route)
    source = normalize_source(file_request.source.to_wire())
    runtime = CommitRuntime(state)
    try:
        first = runtime.execute(file_request, file_route, principal=principal, access="public", source=source, scanner_clear=True)
        replay = runtime.probe(file_request, file_route, principal=principal)
        assert replay.response_template is not None
        assert replay.response_template["record_ids"] == first["record_ids"]
        assert len(runtime.journal.entries()) == 1

        import_route = resolve_route("POST", "/v1/import-record", require_available=True)
        import_request = parse_commit_request(_frame(operation="import.record", data=data, key="import-key", request_id="three", legacy_id="legacy-id")["body"], import_route)
        imported = runtime.execute(import_request, import_route, principal=principal, access="public", source=source, scanner_clear=True)
        assert imported["record_ids"][0] == "legacy-id"
        assert len(imported["record_ids"]) == 2 and len(imported["entry_ids"]) == 1
        assert verify_store(state, projection=False)["valid"] is True
    finally:
        runtime.close()


def test_slice3c1_refusal_and_reserved_route_do_not_create_state(tmp_path: Path) -> None:
    data = b"not certified"
    state = _state(tmp_path, b"different certified source")
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    service = HounddService(state_root=state, socket_path=runtime / "houndd.sock")
    principal = AuthenticatedPrincipal(f"linux-uid:{os.getuid()}")
    try:
        refusal = service._dispatch(principal, _frame(operation="ingest.file", data=data, key="refused", request_id="one"))
        assert refusal["status"] == 503
        assert refusal["body"]["error"]["code"] == "unavailable"
        reserved = _frame(operation="ingest.file", data=data, key="reserved", request_id="two")
        reserved["path"] = "/v1/ingest/search"
        reserved["body"]["operation"]["name"] = "ingest.search"  # type: ignore[index]
        reserved["body"]["producer"]["capability"] = "ingest.search"  # type: ignore[index]
        denied = service._dispatch(principal, reserved)
        assert denied["status"] == 400
        assert not service.store.journal.entries()  # type: ignore[union-attr]
        assert not (state / "commit3c1").exists()
    finally:
        service.close()


def test_slice3c1_prepared_record_recovers_once_and_collision_never_reads_source(tmp_path: Path) -> None:
    data = b"certified recovery input"
    state = _state(tmp_path, data)
    route = resolve_route("POST", "/v1/ingest/file", require_available=True)
    wire = _frame(operation="ingest.file", data=data, key="recovery-key", request_id="one")
    request = parse_commit_request(wire["body"], route)
    source = normalize_source(request.source.to_wire())

    def crash(phase: str) -> None:
        if phase == "after_record":
            raise RuntimeError("simulated process death")

    runtime = CommitRuntime(state, fault_hook=crash)
    try:
        with pytest.raises(RuntimeError):
            runtime.execute(request, route, principal=f"linux-uid:{os.getuid()}", access="public", source=source, scanner_clear=True)
    finally:
        runtime.close()
    recovered = CommitRuntime(state)
    try:
        assert recovered.reconcile() and recovered.journal.high_watermark() == 0
        replay = recovered.probe(request, route, principal=f"linux-uid:{os.getuid()}")
        assert replay.response_template is not None
        changed = _frame(operation="ingest.file", data=data, key="recovery-key", request_id="two")
        changed["body"]["requested_access"] = "workspace"  # type: ignore[index]
        changed_request = parse_commit_request(changed["body"], route)
        with pytest.raises(CommitCollision):
            recovered.probe(changed_request, route, principal=f"linux-uid:{os.getuid()}")
    finally:
        recovered.close()


def test_slice3c1_real_uds_post_and_strict_client_exit_mapping(tmp_path: Path) -> None:
    data = b"certified socket source"
    state = _state(tmp_path, data)
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    path = runtime / "houndd.sock"
    service = HounddService(state_root=state, socket_path=path)
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    try:
        for _ in range(50):
            if path.exists():
                break
            time.sleep(0.01)
        response = exchange(path, _frame(operation="ingest.file", data=data, key="socket-key", request_id="socket-request"))
        assert response["status"] == 503
        assert response["body"]["schema_version"] == "houndd.commit-response.v1"
        assert exit_code(response) == 5
    finally:
        service.close()
        thread.join(timeout=2)


def test_slice3c1_client_accepts_every_durable_noncompleted_outcome() -> None:
    for outcome in ("failed", "partial", "degraded", "refused", "interrupted"):
        body = make_commit_response(
            "request",
            ok=False,
            outcome=outcome,
            record_ids=["record"],
            entry_ids=["entry"],
            usage={"requests": 0, "bytes": 1, "cost": 0},
            error={"code": "operation_failed", "retryable": False, "message": "operation failed"},
        )
        raw = canonical_bytes({"wire_version": "houndd.uds.v1", "status": 200, "body": body})
        response = strict_response(raw, request_id="request")
        assert exit_code(response) == 4


def test_slice3c1_recoverable_post_frame_error_uses_commit_schema(tmp_path: Path) -> None:
    data = b"certified socket source"
    state = _state(tmp_path, data)
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    path = runtime / "houndd.sock"
    service = HounddService(state_root=state, socket_path=path)
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    try:
        raw = b'{"body": {"request_id":"post-frame"},"method":"POST","path":"/v1/ingest/file","wire_version":"houndd.uds.v1"}'
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.connect(os.fspath(path))
            connection.sendall(len(raw).to_bytes(4, "big") + raw)
            connection.shutdown(socket.SHUT_WR)
            size = int.from_bytes(connection.recv(4), "big")
            response = json.loads(connection.recv(size))
        assert response["status"] == 400
        assert response["body"]["schema_version"] == "houndd.commit-response.v1"
        assert response["body"]["request_id"] == "post-frame"
    finally:
        service.close()
        thread.join(timeout=2)


def test_slice3c1_legacy_conflict_preflight_creates_no_attempt(tmp_path: Path) -> None:
    state = _state(tmp_path, b"new")
    runtime = CommitRuntime(state)
    route = resolve_route("POST", "/v1/import-record", require_available=True)
    request = parse_commit_request(_frame(operation="import.record", data=b"new", key="key", request_id="request", legacy_id="legacy-id")["body"], route)
    source = normalize_source(request.source.to_wire())
    try:
        runtime.records.put_bytes("legacy-id", b"old")  # type: ignore[union-attr]
        with pytest.raises(CommitCollision):
            runtime.execute(request, route, principal=f"linux-uid:{os.getuid()}", access="public", source=source, scanner_clear=True)
        assert not list((state / "commit3c1" / "reservations").iterdir())
        assert not list((state / "commit3c1" / "open").iterdir())
    finally:
        runtime.close()


def test_slice3c1_inventory_is_startup_only_and_pair_tampering_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = b"inventory"
    state = _state(tmp_path, data)
    runtime = CommitRuntime(state)
    route = resolve_route("POST", "/v1/ingest/file", require_available=True)
    request = parse_commit_request(_frame(operation="ingest.file", data=data, key="key", request_id="one")["body"], route)
    other = parse_commit_request(_frame(operation="ingest.file", data=data, key="other", request_id="two")["body"], route)
    source = normalize_source(request.source.to_wire())
    try:
        runtime.execute(request, route, principal=f"linux-uid:{os.getuid()}", access="public", source=source, scanner_clear=True)
        monkeypatch.setattr(runtime, "_validate_inventory", lambda: (_ for _ in ()).throw(AssertionError("history rescan")))
        assert runtime.probe(other, route, principal=f"linux-uid:{os.getuid()}").response_template is None
    finally:
        runtime.close()

    marker_path = next((state / "commit3c1" / "open").iterdir())
    marker = json.loads(marker_path.read_bytes())
    marker["access"] = "workspace"
    marker_path.write_bytes(canonical_bytes(marker))
    with pytest.raises(CommitIntegrityError):
        CommitRuntime(state)


def test_slice3c1_verifier_rejects_orphan_legacy_manifest(tmp_path: Path) -> None:
    state = _state(tmp_path, b"source")
    runtime = CommitRuntime(state)
    runtime.close()
    (state / "legacy" / "orphan.json").write_bytes(canonical_bytes({"record_id": "orphan", "sha256": "0" * 64, "byte_length": 0}))
    report = verify_store(state, projection=False)
    assert report["valid"] is False
    assert any("orphan legacy manifest" in failure for failure in report["failures"])


def test_slice3c1_verifier_requires_canonical_transaction_tree(tmp_path: Path) -> None:
    state = _state(tmp_path, b"source")
    shutil.rmtree(state / "transactions")
    report = verify_store(state, projection=False)
    assert report["valid"] is False
    assert not (state / "transactions").exists()


def test_slice3c1_import_graph_requires_manifest_when_legacy_id_is_digest(tmp_path: Path) -> None:
    data = b"content-addressed legacy identity"
    digest = hashlib.sha256(data).hexdigest()
    state = _state(tmp_path, data)
    route = resolve_route("POST", "/v1/import-record", require_available=True)
    request = parse_commit_request(
        _frame(operation="import.record", data=data, key="digest-key", request_id="one", legacy_id=digest)["body"],
        route,
    )
    source = normalize_source(request.source.to_wire())
    runtime = CommitRuntime(state)
    try:
        runtime.execute(
            request,
            route,
            principal=f"linux-uid:{os.getuid()}",
            access="public",
            source=source,
            scanner_clear=True,
        )
    finally:
        runtime.close()
    (state / "legacy" / f"{digest}.json").unlink()

    assert verify_store(state, projection=False)["valid"] is False
    with pytest.raises(CommitIntegrityError):
        CommitRuntime(state)


def test_slice3c1_pair_validation_rejects_unbound_route_payload_and_scalar_subtypes(tmp_path: Path) -> None:
    class HostileStr(str):
        pass

    data = b"pair binding"
    state = _state(tmp_path, data)
    route = resolve_route("POST", "/v1/ingest/file", require_available=True)
    request = parse_commit_request(_frame(operation="ingest.file", data=data, key="key", request_id="one")["body"], route)
    source = normalize_source(request.source.to_wire())
    runtime = CommitRuntime(state)
    try:
        runtime.execute(request, route, principal=f"linux-uid:{os.getuid()}", access="public", source=source, scanner_clear=True)
        reservation = json.loads(next((state / "commit3c1" / "reservations").iterdir()).read_bytes())
        marker = json.loads(next((state / "commit3c1" / "open").iterdir()).read_bytes())

        def forged_pair(mutator):
            forged_reservation = copy.deepcopy(reservation)
            forged_marker = copy.deepcopy(marker)
            canonical = forged_reservation["canonical_request"]
            mutator(canonical)
            request_hash = canonical_hash(canonical)
            attempt_id = runtime._attempt_id(
                forged_reservation["principal"],
                forged_reservation["capability"],
                forged_reservation["idempotency_key"],
                request_hash,
            )
            body = forged_marker["record_body"]
            body["attempt_id"] = attempt_id
            body["request_hash"] = request_hash
            record_id = canonical_hash(body)
            envelope = runtime._event(
                request,
                access=forged_marker["access"],
                record_id=record_id,
                record_hash=record_id,
                lineage=forged_marker["lineage"],
                sequence=forged_marker["envelope"]["sequence"],
                appended_at=forged_marker["envelope"]["appended_at"],
            )
            forged_reservation.update({"request_hash": request_hash, "attempt_id": attempt_id, "response": {
                **forged_reservation["response"],
                "record_ids": [record_id],
                "entry_ids": [envelope["entry_id"]],
            }})
            forged_marker.update({
                "attempt_id": attempt_id,
                "request_hash": request_hash,
                "canonical_request": canonical,
                "producer": canonical["producer"],
                "record_id": record_id,
                "record_body": body,
                "envelope": envelope,
            })
            return forged_reservation, forged_marker, attempt_id

        attacks = (
            lambda canonical: canonical["route"].update(path="/v1/unbound"),
            lambda canonical: canonical["operation"]["payload"].update(media_type="text/plain"),
            lambda canonical: canonical["producer"].update(owner_id=HostileStr("writer")),
        )
        for attack in attacks:
            forged_reservation, forged_marker, attempt_id = forged_pair(attack)
            with pytest.raises(CommitIntegrityError):
                runtime._validate_pair_values(
                    f"{forged_reservation['scope_id']}.json",
                    forged_reservation,
                    f"{attempt_id}.json",
                    forged_marker,
                )
    finally:
        runtime.close()


def test_slice3c1_client_requires_one_entry_and_nonempty_records_for_durable_200() -> None:
    for outcome, ok in (("completed", True), ("failed", False)):
        error = None if ok else {"code": "operation_failed", "retryable": False, "message": "operation failed"}
        for record_ids, entry_ids in (([], ["entry"]), (["record"], []), (["record"], ["one", "two"])):
            body = make_commit_response(
                "request",
                ok=ok,
                outcome=outcome,
                record_ids=record_ids,
                entry_ids=entry_ids,
                usage={"requests": 0, "bytes": 1, "cost": 0},
                error=error,
            )
            with pytest.raises(CommitClientError):
                strict_response(
                    canonical_bytes({"wire_version": "houndd.uds.v1", "status": 200, "body": body}),
                    request_id="request",
                )
