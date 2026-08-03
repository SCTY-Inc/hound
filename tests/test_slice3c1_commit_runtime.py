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
import subprocess
import sys
import threading
import time

import pytest

from houndd import HounddStore
from houndd.contracts import canonical_bytes, canonical_hash, make_journal_envelope
from houndd.service import HounddService
from houndd.access import AuthenticatedPrincipal, EventSelector, PrincipalScope, ProducerSelector
from houndd.commit import make_commit_response, parse_commit_request, resolve_route, normalize_source
from houndd.commit_runtime import CommitRuntime, CommitCollision, CommitIntegrityError
from houndd.verify import verify_store
from hound_research import cli as research_cli
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


def _scope(capability: str) -> PrincipalScope:
    """The read scope the service resolves for one writer capability."""

    tiers = frozenset({"public"})
    return PrincipalScope(
        principal=AuthenticatedPrincipal(f"linux-uid:{os.getuid()}"),
        readable_tiers=tiers,
        permitted_event_selectors=(EventSelector("write-policy", ProducerSelector("writer", capability, None), tiers),),
    )


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
        assert refusal["status"] == 400
        assert refusal["body"]["error"]["code"] == "source_refused"
        reserved = _frame(operation="ingest.file", data=data, key="reserved", request_id="two")
        reserved["path"] = "/v1/ingest/search"
        reserved["body"]["operation"]["name"] = "ingest.search"  # type: ignore[index]
        reserved["body"]["producer"]["capability"] = "ingest.search"  # type: ignore[index]
        denied = service._dispatch(principal, reserved)
        assert denied["status"] == 400
        assert not service.store.journal.entries()  # type: ignore[union-attr]
        assert not list((state / "commit3c1" / "reservations").iterdir())
        assert not list((state / "commit3c1" / "open").iterdir())
    finally:
        service.close()


@pytest.mark.parametrize(("operation", "legacy_id"), (("ingest.file", None), ("import.record", "recovery-legacy")))
def test_slice3c1_prepared_record_recovers_once_and_collision_never_reads_source(tmp_path: Path, operation: str, legacy_id: str | None) -> None:
    data = b"certified recovery input"
    state = _state(tmp_path, data)
    route = resolve_route("POST", "/v1/import-record" if operation == "import.record" else "/v1/ingest/file", require_available=True)
    wire = _frame(operation=operation, data=data, key="recovery-key", request_id="one", legacy_id=legacy_id)
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
        changed = _frame(operation=operation, data=data, key="recovery-key", request_id="two", legacy_id=legacy_id)
        changed["body"]["requested_access"] = "workspace"  # type: ignore[index]
        changed_request = parse_commit_request(changed["body"], route)
        with pytest.raises(CommitCollision):
            recovered.probe(changed_request, route, principal=f"linux-uid:{os.getuid()}")
    finally:
        recovered.close()


def test_slice3c1_tampered_reservation_is_integrity_while_changed_request_is_collision(tmp_path: Path) -> None:
    """A rewritten reservation is never judged as a caller-side key collision."""

    data = b"tampered reservation"
    state = _state(tmp_path, data)
    principal = f"linux-uid:{os.getuid()}"
    route = resolve_route("POST", "/v1/ingest/file", require_available=True)
    request = parse_commit_request(_frame(operation="ingest.file", data=data, key="tamper-key", request_id="one")["body"], route)
    changed = _frame(operation="ingest.file", data=data, key="tamper-key", request_id="two")
    changed["body"]["requested_access"] = "workspace"  # type: ignore[index]
    changed_request = parse_commit_request(changed["body"], route)
    runtime = CommitRuntime(state)
    try:
        runtime.execute(request, route, principal=principal, access="public", source=normalize_source(request.source.to_wire()), scanner_clear=True)
        with pytest.raises(CommitCollision):
            runtime.probe(changed_request, route, principal=principal)
        reservation_path = next((state / "commit3c1" / "reservations").iterdir())
        reservation = json.loads(reservation_path.read_bytes())
        reservation["canonical_request"]["policy_id"] = "tampered-policy"
        reservation_path.write_bytes(canonical_bytes(reservation))
        with pytest.raises(CommitIntegrityError):
            runtime.probe(request, route, principal=principal)
        with pytest.raises(CommitIntegrityError):
            runtime.execute(request, route, principal=principal, access="public", source=normalize_source(request.source.to_wire()), scanner_clear=True)
        assert len(runtime.journal.entries()) == 1  # type: ignore[union-attr]
    finally:
        runtime.close()


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
        assert response["status"] == 200
        assert response["body"]["schema_version"] == "houndd.commit-response.v1"
        assert response["body"]["outcome"] == "completed"
        assert len(response["body"]["record_ids"]) == len(response["body"]["entry_ids"]) == 1
        assert exit_code(response) == 0
    finally:
        service.close()
        thread.join(timeout=2)


def test_slice3c1_real_subprocess_uds_commits_exact_journal_and_projection_rows(tmp_path: Path) -> None:
    data = b"subprocess certified source"
    state = _state(tmp_path, data)
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    path = runtime / "houndd.sock"
    process = subprocess.Popen(
        [sys.executable, "-m", "houndd.cli", "serve", "--state", os.fspath(state), "--socket", os.fspath(path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 5
        while not path.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        assert process.poll() is None, process.stderr.read()
        file_response = exchange(path, _frame(operation="ingest.file", data=data, key="subprocess-file", request_id="file"))
        import_response = exchange(path, _frame(operation="import.record", data=data, key="subprocess-import", request_id="import", legacy_id="legacy-subprocess"))
        assert (file_response["status"], import_response["status"]) == (200, 200)
        assert len(file_response["body"]["record_ids"]) == 1
        assert import_response["body"]["record_ids"][0] == "legacy-subprocess"
        assert len(import_response["body"]["record_ids"]) == 2
    finally:
        process.terminate()
        process.wait(timeout=5)
    with HounddStore(state) as store:
        store.rebuild_index()
        events = store.journal.entries()
        rows = store.projection.rows()
    assert [event["artifact"]["schema"] for event in events] == ["houndd.file-record.v1", "houndd.import-outcome.v1"]
    assert [row["record_id"] for row in rows] == [file_response["body"]["record_ids"][0], import_response["body"]["record_ids"][1]]


@pytest.mark.parametrize(
    ("status", "body", "expected_exit"),
    (
        (200, {"ok": False, "outcome": "interrupted", "record_ids": ["outcome"], "entry_ids": ["entry"], "error": {"code": "operation_failed", "retryable": False, "message": "operation failed"}}, 4),
        (400, {"ok": False, "outcome": "invalid", "record_ids": [], "entry_ids": [], "error": {"code": "invalid_request", "retryable": False, "message": "invalid request"}}, 2),
        (404, {"ok": False, "outcome": "invalid", "record_ids": [], "entry_ids": []}, 3),
        (503, {"ok": False, "outcome": "unavailable", "record_ids": [], "entry_ids": [], "error": {"code": "unavailable", "retryable": True, "message": "service unavailable"}}, 5),
    ),
)
def test_slice3c1_fake_server_validates_responses_and_cli_exit_matrix(tmp_path: Path, capsys: pytest.CaptureFixture[str], status: int, body: dict[str, object], expected_exit: int) -> None:
    socket_path = tmp_path / f"fake-{status}.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(os.fspath(socket_path))
    server.listen(1)
    response = make_commit_response(
        "fake-request",
        ok=body["ok"],  # type: ignore[arg-type]
        outcome=body["outcome"],  # type: ignore[arg-type]
        record_ids=body["record_ids"],  # type: ignore[arg-type]
        entry_ids=body["entry_ids"],  # type: ignore[arg-type]
        usage={"requests": 0, "bytes": 0, "cost": 0},
        error=body.get("error"),  # type: ignore[arg-type]
    )
    raw = canonical_bytes({"wire_version": "houndd.uds.v1", "status": status, "body": response})

    def fake_server() -> None:
        connection, _ = server.accept()
        with connection:
            while connection.recv(4096):
                pass
            connection.sendall(len(raw).to_bytes(4, "big") + raw)
        server.close()

    thread = threading.Thread(target=fake_server)
    thread.start()
    source = tmp_path / "declared-source"
    code = research_cli.main([
        "ingest", "file", "--socket", os.fspath(socket_path), "--owner-id", "writer", "--run-id", "run", "--policy-id", "write-policy",
        "--idempotency-key", f"fake-{status}", "--request-id", "fake-request", "--path", os.fspath(source), "--sha256", "0" * 64, "--byte-length", "0",
    ])
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert code == expected_exit
    assert json.loads(capsys.readouterr().out)["schema_version"] == "houndd.commit-response.v1"


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


@pytest.mark.parametrize("operation", ("ingest.file", "import.record"))
def test_slice3c1_verifier_rejects_duplicate_or_forged_outcome_event(tmp_path: Path, operation: str) -> None:
    data = b"verifier source"
    state = _state(tmp_path, data)
    route = resolve_route("POST", "/v1/import-record" if operation == "import.record" else "/v1/ingest/file", require_available=True)
    request = parse_commit_request(
        _frame(operation=operation, data=data, key=f"verify-{operation}", request_id="one", legacy_id="legacy-verify")["body"],
        route,
    )
    runtime = CommitRuntime(state)
    try:
        runtime.execute(
            request,
            route,
            principal=f"linux-uid:{os.getuid()}",
            access="public",
            source=normalize_source(request.source.to_wire()),
            scanner_clear=True,
        )
        original = runtime.journal.entries()[0]  # type: ignore[union-attr]
        source = original["source"]
        dedupe = original["dedupe"]
        usage = original["usage"]
        if operation == "ingest.file":
            forged_digest = runtime.records.blob(b"forged blob")  # type: ignore[union-attr]
            source = {"provider": "local", "native_id": forged_digest, "canonical_url": "none"}
            dedupe = {"object_key": f"file:{forged_digest}", "content_sha256": forged_digest}
            usage = {"requests": 0, "bytes": len(b"forged blob"), "cost": 0}
        runtime.journal.append(make_journal_envelope(  # type: ignore[union-attr]
            sequence=1,
            appended_at="2026-08-03T00:00:01Z",
            producer=original["producer"],
            artifact=original["artifact"],
            lineage=original["lineage"],
            source=source,
            classification=original["classification"],
            access=original["access"],
            policy_id=original["policy_id"],
            dedupe=dedupe,
            usage=usage,
        ))
    finally:
        runtime.close()

    report = verify_store(state, projection=False)
    assert report["valid"] is False
    assert any("Slice 3C1" in failure or "file outcome" in failure or "import outcome" in failure for failure in report["failures"])


@pytest.mark.parametrize("operation", ("ingest.file", "import.record"))
def test_slice3c1_verifier_rejects_outcome_event_schema_relabeling(tmp_path: Path, operation: str) -> None:
    data = b"outcome schema relabeling"
    state = _state(tmp_path, data)
    route = resolve_route("POST", "/v1/import-record" if operation == "import.record" else "/v1/ingest/file", require_available=True)
    request = parse_commit_request(
        _frame(operation=operation, data=data, key=f"relabel-{operation}", request_id="one", legacy_id="legacy-relabel")["body"],
        route,
    )
    runtime = CommitRuntime(state)
    try:
        runtime.execute(
            request,
            route,
            principal=f"linux-uid:{os.getuid()}",
            access="public",
            source=normalize_source(request.source.to_wire()),
            scanner_clear=True,
        )
        original = runtime.journal.entries()[0]  # type: ignore[union-attr]
        if operation == "import.record":
            runtime.records.blob(data)  # type: ignore[union-attr]
        artifact = {**original["artifact"], "kind": "opaque", "schema": "opaque.record.v1"}
        runtime.journal.append(make_journal_envelope(  # type: ignore[union-attr]
            sequence=1,
            appended_at="2026-08-03T00:00:01Z",
            producer=original["producer"],
            artifact=artifact,
            lineage=original["lineage"],
            source=original["source"],
            classification=original["classification"],
            access=original["access"],
            policy_id=original["policy_id"],
            dedupe=original["dedupe"],
            usage=original["usage"],
        ))
    finally:
        runtime.close()

    report = verify_store(state, projection=False)
    assert report["valid"] is False
    assert any("schema does not bind" in failure for failure in report["failures"])


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


def test_slice3c1_open_import_recovery_is_outcome_only_and_replays_without_raw_object(tmp_path: Path) -> None:
    data = b"interrupted import source"
    state = _state(tmp_path, data)
    route = resolve_route("POST", "/v1/import-record", require_available=True)
    request = parse_commit_request(
        _frame(operation="import.record", data=data, key="interrupted-import", request_id="one", legacy_id="legacy-interrupted")["body"],
        route,
    )
    source = normalize_source(request.source.to_wire())

    def crash(phase: str) -> None:
        if phase == "after_open":
            raise RuntimeError("simulated process death")

    runtime = CommitRuntime(state, fault_hook=crash)
    try:
        with pytest.raises(RuntimeError):
            runtime.execute(request, route, principal=f"linux-uid:{os.getuid()}", access="public", source=source, scanner_clear=True)
    finally:
        runtime.close()

    recovered = CommitRuntime(state)
    try:
        assert recovered.reconcile() == [{"attempt_id": recovered._pair(request, route, f"linux-uid:{os.getuid()}")[1], "outcome": "interrupted"}]
        replay = recovered.probe(request, route, principal=f"linux-uid:{os.getuid()}")
        assert replay.response_template is not None
        assert replay.response_template["outcome"] == "interrupted"
        assert len(replay.response_template["record_ids"]) == len(replay.response_template["entry_ids"]) == 1
        assert not recovered.records.has("legacy-interrupted")  # type: ignore[union-attr]
        assert verify_store(state, projection=False)["valid"] is True
    finally:
        recovered.close()


def test_slice3c1_open_file_recovery_has_one_interrupted_outcome_and_no_blob(tmp_path: Path) -> None:
    data = b"interrupted file source"
    state = _state(tmp_path, data)
    route = resolve_route("POST", "/v1/ingest/file", require_available=True)
    request = parse_commit_request(_frame(operation="ingest.file", data=data, key="interrupted-file", request_id="one")["body"], route)
    source = normalize_source(request.source.to_wire())

    def crash(phase: str) -> None:
        if phase == "after_open":
            raise RuntimeError("simulated process death")

    runtime = CommitRuntime(state, fault_hook=crash)
    try:
        with pytest.raises(RuntimeError):
            runtime.execute(request, route, principal=f"linux-uid:{os.getuid()}", access="public", source=source, scanner_clear=True)
    finally:
        runtime.close()

    recovered = CommitRuntime(state)
    try:
        assert recovered.reconcile()
        replay = recovered.probe(request, route, principal=f"linux-uid:{os.getuid()}")
        assert replay.response_template is not None
        assert replay.response_template["outcome"] == "interrupted"
        assert len(replay.response_template["record_ids"]) == len(replay.response_template["entry_ids"]) == 1
        assert not list((state / "blobs").iterdir())
        assert verify_store(state, projection=False)["valid"] is True
    finally:
        recovered.close()


def test_slice3c1_open_recovery_reuses_one_interrupted_event_after_append_crash(tmp_path: Path) -> None:
    """An interrupted open import must not mint a second event after restart."""

    data = b"open recovery journal crash"
    state = _state(tmp_path, data)
    route = resolve_route("POST", "/v1/import-record", require_available=True)
    request = parse_commit_request(
        _frame(operation="import.record", data=data, key="open-journal-crash", request_id="one", legacy_id="legacy-open-crash")["body"],
        route,
    )
    principal = f"linux-uid:{os.getuid()}"

    runtime = CommitRuntime(state, fault_hook=lambda phase: (_ for _ in ()).throw(RuntimeError("initial crash")) if phase == "after_open" else None)
    try:
        with pytest.raises(RuntimeError, match="initial crash"):
            runtime.execute(request, route, principal=principal, access="public", source=normalize_source(request.source.to_wire()), scanner_clear=True)
    finally:
        runtime.close()

    recovering = CommitRuntime(state)
    try:
        assert recovering.journal is not None
        append = recovering.journal.append

        def append_then_crash(envelope: dict[str, object]) -> dict[str, object]:
            append(envelope)  # type: ignore[arg-type]
            raise RuntimeError("crash after recovery append")

        recovering.journal.append = append_then_crash  # type: ignore[method-assign]
        with pytest.raises(RuntimeError, match="crash after recovery append"):
            recovering.reconcile()
    finally:
        recovering.close()

    recovered = CommitRuntime(state)
    try:
        assert recovered.reconcile()
        assert len(recovered.journal.entries()) == 1  # type: ignore[union-attr]
        replay = recovered.probe(request, route, principal=principal)
        assert replay.response_template is not None
        assert replay.response_template["outcome"] == "interrupted"
        assert verify_store(state, projection=False)["valid"] is True
    finally:
        recovered.close()


def test_slice3c1_prepared_recovery_replaces_an_outgrown_event_position(tmp_path: Path) -> None:
    """A journal that advanced past the planned sequence must not wedge recovery."""

    data = b"prepared recovery after journal advance"
    state = _state(tmp_path, data)
    principal = f"linux-uid:{os.getuid()}"
    route = resolve_route("POST", "/v1/ingest/file", require_available=True)
    request = parse_commit_request(_frame(operation="ingest.file", data=data, key="outgrown", request_id="one")["body"], route)

    runtime = CommitRuntime(state, fault_hook=lambda phase: (_ for _ in ()).throw(RuntimeError("record crash")) if phase == "after_record" else None)
    try:
        with pytest.raises(RuntimeError, match="record crash"):
            runtime.execute(request, route, principal=principal, access="public", source=normalize_source(request.source.to_wire()), scanner_clear=True)
    finally:
        runtime.close()

    recovered = CommitRuntime(state)
    try:
        recovered.journal.append(make_journal_envelope(  # type: ignore[union-attr]
            sequence=recovered.journal.high_watermark() + 1,  # type: ignore[union-attr]
            appended_at="2026-08-03T00:00:00Z",
            producer={"owner_id": "writer", "capability": "import.record", "run_id": "unrelated"},
            artifact={"kind": "import", "schema": "legacy.record.v1", "record_id": "unrelated", "hash": "a" * 64, "authorized_uri": "houndd://record/unrelated"},
            lineage={"relation": "none", "record_id": "none", "lead_id": "none"},
            source={"provider": "legacy", "native_id": "unrelated", "canonical_url": "none"},
            classification={"outcome": "completed", "evidence_status": "clear"},
            access="public",
            policy_id="write-policy",
            dedupe={"object_key": "legacy:unrelated", "content_sha256": "a" * 64},
            usage={"requests": 0, "bytes": 0, "cost": 0},
        ))
        assert recovered.reconcile() == [{"attempt_id": recovered._pair(request, route, principal)[1], "outcome": "completed"}]
        entries = recovered.journal.entries()  # type: ignore[union-attr]
        assert [entry["artifact"]["schema"] for entry in entries] == ["legacy.record.v1", "houndd.file-record.v1"]
        replay = recovered.probe(request, route, principal=principal)
        assert replay.response_template is not None
        assert replay.response_template["outcome"] == "completed"
        assert replay.response_template["entry_ids"] == [entries[1]["entry_id"]]
        assert replay.response_template["record_ids"] == [entries[1]["artifact"]["record_id"]]
    finally:
        recovered.close()
    CommitRuntime(state).close()


def test_slice3c1_resequenced_recovery_survives_a_crash_between_its_metadata_writes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Re-placing an outgrown event leaves only recoverable metadata states."""

    data = b"resequence crash"
    state = _state(tmp_path, data)
    principal = f"linux-uid:{os.getuid()}"
    route = resolve_route("POST", "/v1/ingest/file", require_available=True)
    request = parse_commit_request(_frame(operation="ingest.file", data=data, key="resequence", request_id="one")["body"], route)

    runtime = CommitRuntime(state, fault_hook=lambda phase: (_ for _ in ()).throw(RuntimeError("record crash")) if phase == "after_record" else None)
    try:
        with pytest.raises(RuntimeError, match="record crash"):
            runtime.execute(request, route, principal=principal, access="public", source=normalize_source(request.source.to_wire()), scanner_clear=True)
    finally:
        runtime.close()

    crashing = CommitRuntime(state)
    try:
        crashing.journal.append(make_journal_envelope(  # type: ignore[union-attr]
            sequence=crashing.journal.high_watermark() + 1,  # type: ignore[union-attr]
            appended_at="2026-08-03T00:00:00Z",
            producer={"owner_id": "writer", "capability": "import.record", "run_id": "unrelated"},
            artifact={"kind": "import", "schema": "legacy.record.v1", "record_id": "unrelated", "hash": "a" * 64, "authorized_uri": "houndd://record/unrelated"},
            lineage={"relation": "none", "record_id": "none", "lead_id": "none"},
            source={"provider": "legacy", "native_id": "unrelated", "canonical_url": "none"},
            classification={"outcome": "completed", "evidence_status": "clear"},
            access="public",
            policy_id="write-policy",
            dedupe={"object_key": "legacy:unrelated", "content_sha256": "a" * 64},
            usage={"requests": 0, "bytes": 0, "cost": 0},
        ))
        monkeypatch.setattr(crashing, "_prepare_pair", lambda *_: (_ for _ in ()).throw(RuntimeError("crash after demotion")))
        with pytest.raises(RuntimeError, match="crash after demotion"):
            crashing.reconcile()
    finally:
        crashing.close()

    recovered = CommitRuntime(state)
    try:
        assert recovered.reconcile() == [{"attempt_id": recovered._pair(request, route, principal)[1], "outcome": "completed"}]
        entries = recovered.journal.entries()  # type: ignore[union-attr]
        assert [entry["artifact"]["schema"] for entry in entries] == ["legacy.record.v1", "houndd.file-record.v1"]
        replay = recovered.probe(request, route, principal=principal)
        assert replay.response_template is not None
        assert replay.response_template["entry_ids"] == [entries[1]["entry_id"]]
    finally:
        recovered.close()


def test_slice3c1_prepared_import_checks_legacy_bytes_before_recovery_append(tmp_path: Path) -> None:
    data = b"prepared import missing raw bytes"
    state = _state(tmp_path, data)
    route = resolve_route("POST", "/v1/import-record", require_available=True)
    request = parse_commit_request(
        _frame(operation="import.record", data=data, key="missing-raw", request_id="one", legacy_id="legacy-missing")["body"],
        route,
    )

    runtime = CommitRuntime(state, fault_hook=lambda phase: (_ for _ in ()).throw(RuntimeError("record crash")) if phase == "after_record" else None)
    try:
        with pytest.raises(RuntimeError, match="record crash"):
            runtime.execute(request, route, principal=f"linux-uid:{os.getuid()}", access="public", source=normalize_source(request.source.to_wire()), scanner_clear=True)
    finally:
        runtime.close()

    (state / "records" / "legacy-missing.bin").unlink()
    recovered = CommitRuntime(state)
    try:
        with pytest.raises(CommitIntegrityError):
            recovered.reconcile()
        assert recovered.journal.entries() == []  # type: ignore[union-attr]
    finally:
        recovered.close()


@pytest.mark.parametrize("operation", ("ingest.file", "import.record"))
def test_slice3c1_recovery_completes_a_source_stage_left_before_outcome_record(tmp_path: Path, operation: str) -> None:
    data = b"source stage before outcome record"
    state = _state(tmp_path, data)
    route = resolve_route("POST", "/v1/import-record" if operation == "import.record" else "/v1/ingest/file", require_available=True)
    request = parse_commit_request(
        _frame(operation=operation, data=data, key=f"stage-{operation}", request_id="one", legacy_id="legacy-stage")["body"],
        route,
    )
    principal = f"linux-uid:{os.getuid()}"
    runtime = CommitRuntime(state)
    try:
        assert runtime.records is not None
        if operation == "ingest.file":
            publish = runtime.records.blob

            def publish_then_crash(value: bytes) -> str:
                publish(value)
                raise RuntimeError("crash after source stage")

            runtime.records.blob = publish_then_crash  # type: ignore[method-assign]
        else:
            publish = runtime.records.put_bytes

            def publish_then_crash(record_id: str, value: bytes, *, expected_sha256: str | None = None):
                publish(record_id, value, expected_sha256=expected_sha256)
                raise RuntimeError("crash after source stage")

            runtime.records.put_bytes = publish_then_crash  # type: ignore[method-assign]
        with pytest.raises(RuntimeError, match="crash after source stage"):
            runtime.execute(request, route, principal=principal, access="public", source=normalize_source(request.source.to_wire()), scanner_clear=True)
    finally:
        runtime.close()

    recovered = CommitRuntime(state)
    try:
        assert recovered.reconcile()
        replay = recovered.probe(request, route, principal=principal)
        assert replay.response_template is not None
        assert replay.response_template["outcome"] == "completed"
        assert len(recovered.journal.entries()) == 1  # type: ignore[union-attr]
        assert verify_store(state, projection=False)["valid"] is True
    finally:
        recovered.close()


@pytest.mark.parametrize("phase", ("prepared", "complete"))
def test_slice3c1_recovery_accepts_only_ordered_private_metadata_transitions(tmp_path: Path, phase: str) -> None:
    data = b"private metadata transition"
    state = _state(tmp_path, data)
    route = resolve_route("POST", "/v1/ingest/file", require_available=True)
    request = parse_commit_request(_frame(operation="ingest.file", data=data, key=f"transition-{phase}", request_id="one")["body"], route)
    runtime = CommitRuntime(state)
    try:
        write = runtime._write

        def write_then_crash(*parts: str, value: dict[str, object]) -> None:
            write(*parts, value=value)  # type: ignore[arg-type]
            if parts[:3] == ("commit3c1", "open", f"{runtime._pair(request, route, f'linux-uid:{os.getuid()}')[1]}.json") and value.get("status") == phase:
                raise RuntimeError(f"crash after marker {phase}")

        runtime._write = write_then_crash  # type: ignore[method-assign]
        with pytest.raises(RuntimeError, match=f"crash after marker {phase}"):
            runtime.execute(request, route, principal=f"linux-uid:{os.getuid()}", access="public", source=normalize_source(request.source.to_wire()), scanner_clear=True)
    finally:
        runtime.close()

    recovered = CommitRuntime(state)
    try:
        assert recovered.reconcile()
        assert len(recovered.journal.entries()) == 1  # type: ignore[union-attr]
        assert verify_store(state, projection=False)["valid"] is True
    finally:
        recovered.close()


def test_slice3c1_service_replays_before_source_and_rejects_changed_binding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import houndd.service as service_module

    data = b"replay before source"
    state = _state(tmp_path, data)
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    service = HounddService(state_root=state, socket_path=runtime / "houndd.sock")
    principal = AuthenticatedPrincipal(f"linux-uid:{os.getuid()}")
    first = _frame(operation="ingest.file", data=data, key="same-key", request_id="one")
    try:
        completed = service._dispatch(principal, first)
        assert completed["status"] == 200
        monkeypatch.setattr(service_module, "normalize_source", lambda _value: (_ for _ in ()).throw(AssertionError("source reread")))
        replay = _frame(operation="ingest.file", data=data, key="same-key", request_id="two")
        repeated = service._dispatch(principal, replay)
        assert repeated["status"] == 200
        assert repeated["body"]["record_ids"] == completed["body"]["record_ids"]
        changed = _frame(operation="ingest.file", data=data, key="same-key", request_id="three")
        changed["body"]["operation"]["payload"]["source"]["sha256"] = "0" * 64  # type: ignore[index]
        collision = service._dispatch(principal, changed)
        assert collision["status"] == 400
        assert collision["body"]["error"]["code"] == "request_conflict"
        assert len(service.store.journal.entries()) == 1  # type: ignore[union-attr]
    finally:
        service.close()


def test_slice3c1_final_replay_precedes_phi_manifest_io(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import houndd.service as service_module

    data = b"replay ignores later manifest loss"
    state = _state(tmp_path, data)
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    service = HounddService(state_root=state, socket_path=runtime / "houndd.sock")
    principal = AuthenticatedPrincipal(f"linux-uid:{os.getuid()}")
    frame = _frame(operation="ingest.file", data=data, key="replay-before-manifest", request_id="one")
    try:
        first = service._dispatch(principal, frame)
        assert first["status"] == 200
        (state / "service" / "phi-clear.json").unlink()
        monkeypatch.setattr(service_module, "normalize_source", lambda _value: (_ for _ in ()).throw(AssertionError("source reread")))
        replay = _frame(operation="ingest.file", data=data, key="replay-before-manifest", request_id="two")
        repeated = service._dispatch(principal, replay)
        assert repeated["status"] == 200
        assert repeated["body"]["record_ids"] == first["body"]["record_ids"]
    finally:
        service.close()


def test_slice3c1_manifest_change_during_normalization_fails_before_reservation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import houndd.service as service_module

    data = b"manifest changes while source is normalized"
    state = _state(tmp_path, data)
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    service = HounddService(state_root=state, socket_path=runtime / "houndd.sock")
    principal = AuthenticatedPrincipal(f"linux-uid:{os.getuid()}")
    normalize = service_module.normalize_source
    manifest = state / "service" / "phi-clear.json"

    def replace_manifest(value: object):
        source = normalize(value)  # type: ignore[arg-type]
        replacement = manifest.with_name("replacement.json")
        replacement.write_bytes(canonical_bytes({"schema_version": "houndd.phi-clear.v1", "entries": []}))
        replacement.chmod(0o600)
        os.replace(replacement, manifest)
        return source

    monkeypatch.setattr(service_module, "normalize_source", replace_manifest)
    try:
        response = service._dispatch(principal, _frame(operation="ingest.file", data=data, key="manifest-race", request_id="one"))
        assert response["status"] == 503
        assert not list((state / "commit3c1" / "reservations").iterdir())
        assert service.store.journal.entries() == []  # type: ignore[union-attr]
    finally:
        service.close()


def test_slice3c1_manifest_change_before_reservation_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = b"manifest changes inside acceptance lock"
    state = _state(tmp_path, data)
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    service = HounddService(state_root=state, socket_path=runtime / "houndd.sock")
    principal = AuthenticatedPrincipal(f"linux-uid:{os.getuid()}")
    manifest = state / "service" / "phi-clear.json"
    assert service.commit_runtime is not None
    lineage = service.commit_runtime._lineage

    def replace_manifest(*args: object) -> dict[str, str]:
        result = lineage(*args)  # type: ignore[arg-type]
        replacement = manifest.with_name("replacement.json")
        replacement.write_bytes(canonical_bytes({"schema_version": "houndd.phi-clear.v1", "entries": []}))
        replacement.chmod(0o600)
        os.replace(replacement, manifest)
        return result

    monkeypatch.setattr(service.commit_runtime, "_lineage", replace_manifest)
    try:
        response = service._dispatch(principal, _frame(operation="ingest.file", data=data, key="manifest-final-check", request_id="one"))
        assert response["status"] == 503
        assert not list((state / "commit3c1" / "reservations").iterdir())
        assert service.store.journal.entries() == []  # type: ignore[union-attr]
    finally:
        service.close()


@pytest.mark.parametrize("state_change", ("absent", "unsafe"))
def test_slice3c1_unavailable_phi_manifest_never_reads_source_or_creates_attempt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, state_change: str) -> None:
    import houndd.service as service_module

    data = b"manifest boundary"
    state = _state(tmp_path, data)
    manifest = state / "service" / "phi-clear.json"
    if state_change == "absent":
        manifest.unlink()
    else:
        manifest.chmod(0o644)
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    service = HounddService(state_root=state, socket_path=runtime / "houndd.sock")
    principal = AuthenticatedPrincipal(f"linux-uid:{os.getuid()}")
    monkeypatch.setattr(service_module, "normalize_source", lambda _value: (_ for _ in ()).throw(AssertionError("source read")))
    try:
        response = service._dispatch(principal, _frame(operation="ingest.file", data=data, key=f"manifest-{state_change}", request_id="one"))
        assert response["status"] == 503
        assert not list((state / "commit3c1" / "reservations").iterdir())
    finally:
        service.close()


def test_slice3c1_replaced_phi_manifest_and_forked_service_fail_before_source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import houndd.service as service_module

    data = b"frozen manifest boundary"
    state = _state(tmp_path, data)
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    service = HounddService(state_root=state, socket_path=runtime / "houndd.sock")
    principal = AuthenticatedPrincipal(f"linux-uid:{os.getuid()}")
    manifest = state / "service" / "phi-clear.json"
    replacement = state / "service" / "replacement.json"
    replacement.write_bytes(manifest.read_bytes())
    replacement.chmod(0o600)
    os.replace(replacement, manifest)
    monkeypatch.setattr(service_module, "normalize_source", lambda _value: (_ for _ in ()).throw(AssertionError("source read")))
    try:
        replaced = service._dispatch(principal, _frame(operation="ingest.file", data=data, key="replaced", request_id="one"))
        assert replaced["status"] == 503
        service._owner_pid = -1
        forked = service._dispatch(principal, _frame(operation="ingest.file", data=data, key="forked", request_id="two"))
        assert forked["status"] == 503
        assert not list((state / "commit3c1" / "reservations").iterdir())
    finally:
        service.close()


def test_slice3c1_authorization_denial_never_reads_source_or_creates_attempt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import houndd.service as service_module

    data = b"authorization boundary"
    state = _state(tmp_path, data)
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    service = HounddService(state_root=state, socket_path=runtime / "houndd.sock")
    monkeypatch.setattr(service_module, "normalize_source", lambda _value: (_ for _ in ()).throw(AssertionError("source read")))
    try:
        response = service._dispatch(AuthenticatedPrincipal("linux-uid:999999"), _frame(operation="ingest.file", data=data, key="denied", request_id="one"))
        assert response["status"] == 404
        assert response["body"]["record_ids"] == response["body"]["entry_ids"] == []
        assert not list((state / "commit3c1" / "reservations").iterdir())
    finally:
        service.close()


def test_slice3c1_recovery_rejects_partial_pair_and_event_without_record(tmp_path: Path) -> None:
    data = b"recovery integrity"
    route = resolve_route("POST", "/v1/ingest/file", require_available=True)
    principal = f"linux-uid:{os.getuid()}"

    partial_root = tmp_path / "partial"
    partial_root.mkdir()
    partial_state = _state(partial_root, data)
    partial_request = parse_commit_request(_frame(operation="ingest.file", data=data, key="partial", request_id="one")["body"], route)
    partial_runtime = CommitRuntime(partial_state, fault_hook=lambda phase: (_ for _ in ()).throw(RuntimeError("stop")) if phase == "after_open" else None)
    try:
        with pytest.raises(RuntimeError):
            partial_runtime.execute(partial_request, route, principal=principal, access="public", source=normalize_source(partial_request.source.to_wire()), scanner_clear=True)
    finally:
        partial_runtime.close()
    next((partial_state / "commit3c1" / "open").iterdir()).unlink()
    with pytest.raises(CommitIntegrityError):
        CommitRuntime(partial_state)

    event_root = tmp_path / "event"
    event_root.mkdir()
    event_state = _state(event_root, data)
    event_request = parse_commit_request(_frame(operation="ingest.file", data=data, key="event", request_id="two")["body"], route)
    event_runtime = CommitRuntime(event_state, fault_hook=lambda phase: (_ for _ in ()).throw(RuntimeError("stop")) if phase == "after_journal" else None)
    try:
        with pytest.raises(RuntimeError):
            event_runtime.execute(event_request, route, principal=principal, access="public", source=normalize_source(event_request.source.to_wire()), scanner_clear=True)
    finally:
        event_runtime.close()
    marker = json.loads(next((event_state / "commit3c1" / "open").iterdir()).read_bytes())
    (event_state / "records" / f"{marker['record_id']}.bin").unlink()
    recovered = CommitRuntime(event_state)
    try:
        with pytest.raises(CommitIntegrityError):
            recovered.reconcile()
    finally:
        recovered.close()


def test_slice3c1_unscoped_import_lineage_selects_no_existing_event(tmp_path: Path) -> None:
    """No scope authorizes no event, so lineage selection can only be none."""

    data = b"unscoped lineage"
    state = _state(tmp_path, data)
    runtime = CommitRuntime(state)
    route = resolve_route("POST", "/v1/import-record", require_available=True)
    request = parse_commit_request(_frame(operation="import.record", data=data, key="unscoped", request_id="one", legacy_id="legacy-unscoped")["body"], route)
    try:
        runtime.journal.append(make_journal_envelope(  # type: ignore[union-attr]
            sequence=0,
            appended_at="2026-08-03T00:00:00Z",
            producer={"owner_id": "writer", "capability": "import.record", "run_id": "prior"},
            artifact={"kind": "import", "schema": "legacy.record.v1", "record_id": "prior", "hash": "a" * 64, "authorized_uri": "houndd://record/prior"},
            lineage={"relation": "derived_from", "record_id": "restricted-parent", "lead_id": "restricted-lead"},
            source={"provider": "legacy", "native_id": "legacy-unscoped", "canonical_url": "none"},
            classification={"outcome": "completed", "evidence_status": "clear"},
            access="restricted",
            policy_id="write-policy",
            dedupe={"object_key": "prior", "content_sha256": "a" * 64},
            usage={"requests": 0, "bytes": 0, "cost": 0},
        ))
        runtime.execute(request, route, principal=f"linux-uid:{os.getuid()}", access="public", source=normalize_source(request.source.to_wire()), scanner_clear=True)
        committed = runtime.journal.entries()[-1]  # type: ignore[union-attr]
        assert committed["lineage"] == {"relation": "none", "record_id": "legacy-unscoped", "lead_id": "none"}
    finally:
        runtime.close()


def test_slice3c1_ambiguous_authorized_import_lineage_rejects_before_reservation(tmp_path: Path) -> None:
    data = b"ambiguous lineage"
    state = _state(tmp_path, data)
    runtime = CommitRuntime(state)
    route = resolve_route("POST", "/v1/import-record", require_available=True)
    request = parse_commit_request(_frame(operation="import.record", data=data, key="ambiguous", request_id="one", legacy_id="legacy-ambiguous")["body"], route)
    scope = _scope("import.record")
    try:
        for sequence, lineage in enumerate((
            {"relation": "none", "record_id": "legacy-ambiguous", "lead_id": "none"},
            {"relation": "derived_from", "record_id": "other", "lead_id": "lead"},
        )):
            runtime.journal.append(make_journal_envelope(
                sequence=sequence,
                appended_at=f"2026-08-03T00:00:0{sequence}Z",
                producer={"owner_id": "writer", "capability": "import.record", "run_id": "prior"},
                artifact={"kind": "import", "schema": "legacy.record.v1", "record_id": f"prior-{sequence}", "hash": "a" * 64, "authorized_uri": f"houndd://record/prior-{sequence}"},
                lineage=lineage,
                source={"provider": "legacy", "native_id": "legacy-ambiguous", "canonical_url": "none"},
                classification={"outcome": "completed", "evidence_status": "clear"},
                access="public",
                policy_id="write-policy",
                dedupe={"object_key": f"prior-{sequence}", "content_sha256": "a" * 64},
                usage={"requests": 0, "bytes": 0, "cost": 0},
            ))
        with pytest.raises(CommitIntegrityError):
            runtime.execute(request, route, principal=f"linux-uid:{os.getuid()}", access="public", source=normalize_source(request.source.to_wire()), scanner_clear=True, scope=scope)
        assert not list((state / "commit3c1" / "reservations").iterdir())
    finally:
        runtime.close()


def test_slice3c1_public_cli_is_socket_only_and_maps_commit_exits(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    data = b"cli certified source"
    state = _state(tmp_path, data)
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    socket_path = runtime / "houndd.sock"
    source_path = tmp_path / "source.bin"
    source_path.write_bytes(data)
    service = HounddService(state_root=state, socket_path=socket_path)
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    try:
        common = [
            "--socket", os.fspath(socket_path),
            "--owner-id", "writer", "--run-id", "run", "--policy-id", "write-policy",
            "--requested-access", "public",
        ]
        source = [
            "--path", os.fspath(source_path), "--sha256", hashlib.sha256(data).hexdigest(), "--byte-length", str(len(data)),
        ]
        assert research_cli.main(["ingest", "file", *common, "--idempotency-key", "cli-key", "--request-id", "cli-request", *source]) == 0
        completed = json.loads(capsys.readouterr().out)
        assert completed["outcome"] == "completed"
        assert research_cli.main(["import-record", *common, "--record-id", "legacy-cli", "--idempotency-key", "cli-import", "--request-id", "cli-import-request", *source]) == 0
        imported = json.loads(capsys.readouterr().out)
        assert len(imported["record_ids"]) == 2 and len(imported["entry_ids"]) == 1
    finally:
        service.close()
        thread.join(timeout=2)
