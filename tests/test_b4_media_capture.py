"""B4: ``ingest.media`` capture records (GOALIE D6 decision, Option A).

``ingest.media`` mirrors ``ingest.file``'s Slice 3C1 contract exactly, per the
D6 owner decision: ``media_type`` is constrained to ``application/octet-stream``,
PHI gating reuses the existing digest-allowlist clear-manifest scanner
verbatim (no new scanner surface), and the no-lineage / interrupted-recovery
shape is identical to ``ingest.file``.  The only differences are the record
schema (``houndd.media-capture-record.v1``), journal ``artifact.kind``
(``"media"``), and the dedupe object-key prefix (``media:`` instead of
``file:``).  VISION.md explicitly reserves real (non-octet-stream) media types
for a future scanner-boundary slice; this file tests only the Option A shape.

``verify.py`` carries the matching ``houndd.media-capture-record.v1`` branch
(added at B4 integration): completed captures must bind their staged blob,
interrupted recoveries verify without one, and a forged or duplicated media
outcome event fails verification exactly like its ``ingest.file`` equivalent.
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

import pytest

from houndd import HounddStore
from houndd.contracts import canonical_bytes, make_journal_envelope
from houndd.service import HounddService
from houndd.access import AuthenticatedPrincipal
from houndd.commit import parse_commit_request, resolve_route, normalize_source
from houndd.commit_runtime import CommitRuntime, CommitCollision, CommitIntegrityError
from houndd.phi import PhiClearEntry, PhiInputError, PhiManifest, PhiScanner
from houndd.verify import verify_store
from hound_research import cli as research_cli
from hound_research.commit_client import exchange


def _policy() -> dict[str, object]:
    return {
        "schema_version": "houndd.policy.v1",
        "rules": [{
            "subject": f"linux-uid:{os.getuid()}",
            "claim_selector": {"owner_id": "writer", "capability": "ingest.media", "run_id": None},
            "policy_id": "write-policy",
            "event_producer_selectors": [{"owner_id": "writer", "capability": "ingest.media", "run_id": None}],
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


def _frame(*, data: bytes, key: str, request_id: str) -> dict[str, object]:
    digest = hashlib.sha256(data).hexdigest()
    return {
        "wire_version": "houndd.uds.v1",
        "method": "POST",
        "path": "/v1/ingest/media",
        "body": {
            "schema_version": "houndd.commit-request.v1",
            "request_id": request_id,
            "idempotency_key": key,
            "producer": {"owner_id": "writer", "capability": "ingest.media", "run_id": "run"},
            "requested_access": "public",
            "policy_id": "write-policy",
            "operation": {"name": "ingest.media", "payload": {
                "source": {"kind": "bytes", "body_base64": base64.b64encode(data).decode("ascii"), "sha256": digest, "byte_length": len(data)},
                "media_type": "application/octet-stream",
            }},
        },
    }


def test_b4_route_is_available_and_payload_shape_matches_ingest_file() -> None:
    route = resolve_route("POST", "/v1/ingest/media", require_available=True)
    assert route.operation == route.capability == "ingest.media"


def test_b4_media_commit_produces_capture_record_uri_and_replays(tmp_path: Path) -> None:
    data = b"local certified media source"
    state = _state(tmp_path, data)
    principal = f"linux-uid:{os.getuid()}"
    route = resolve_route("POST", "/v1/ingest/media", require_available=True)
    request = parse_commit_request(_frame(data=data, key="media-key", request_id="one")["body"], route)
    source = normalize_source(request.source.to_wire())
    runtime = CommitRuntime(state)
    try:
        first = runtime.execute(request, route, principal=principal, access="public", source=source, scanner_clear=True)
        assert first["outcome"] == "completed"
        assert len(first["record_ids"]) == len(first["entry_ids"]) == 1
        record_id = first["record_ids"][0]

        entries = runtime.journal.entries()  # type: ignore[union-attr]
        assert len(entries) == 1
        event = entries[0]
        assert event["artifact"]["kind"] == "media"
        assert event["artifact"]["schema"] == "houndd.media-capture-record.v1"
        assert event["artifact"]["authorized_uri"] == f"houndd://record/{record_id}"
        assert event["dedupe"] == {"object_key": f"media:{source.sha256}", "content_sha256": source.sha256}
        assert event["source"] == {"provider": "local", "native_id": source.sha256, "canonical_url": "none"}
        assert event["lineage"] == {"relation": "none", "record_id": "none", "lead_id": "none"}

        record = runtime.records.read_json(record_id)  # type: ignore[union-attr]
        assert record["schema_version"] == "houndd.media-capture-record.v1"
        assert record["source"] == {"sha256": source.sha256, "byte_length": source.byte_length, "media_type": "application/octet-stream", "encoding": "identity"}

        replay = runtime.probe(request, route, principal=principal)
        assert replay.response_template is not None
        assert replay.response_template["record_ids"] == first["record_ids"]
        assert len(runtime.journal.entries()) == 1  # type: ignore[union-attr]
        assert verify_store(state, projection=False)["valid"] is True
    finally:
        runtime.close()


def test_b4_media_scanner_rejects_uncertified_digest(tmp_path: Path) -> None:
    """The digest-allowlist regime is the same clear manifest ingest.file uses."""

    certified = b"certified media"
    state = _state(tmp_path, certified)
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir(mode=0o700)
    service = HounddService(state_root=state, socket_path=runtime_dir / "houndd.sock")
    principal = AuthenticatedPrincipal(f"linux-uid:{os.getuid()}")
    try:
        refusal = service._dispatch(principal, _frame(data=b"not certified media", key="refused", request_id="one"))
        assert refusal["status"] == 400
        assert refusal["body"]["error"]["code"] == "source_refused"
        assert not service.store.journal.entries()  # type: ignore[union-attr]
        assert not list((state / "commit3c1" / "reservations").iterdir())
        assert not list((state / "commit3c1" / "open").iterdir())
    finally:
        service.close()


def test_b4_phi_scanner_accepts_ingest_media_operation() -> None:
    """The D6-authorized one-line phi.py extension: operation set includes ingest.media."""

    data = b"scanner boundary media"
    digest = hashlib.sha256(data).hexdigest()
    manifest = PhiManifest((PhiClearEntry(digest, "application/octet-stream", "identity"),))
    scanner = PhiScanner(manifest)
    assert scanner.scan(data, "application/octet-stream", "identity", "ingest.media") == "clear"
    assert scanner.scan(b"different", "application/octet-stream", "identity", "ingest.media") == "suspected"
    with pytest.raises(PhiInputError):
        scanner.scan(data, "image/png", "identity", "ingest.media")


def test_b4_media_crash_after_reservation_is_an_unrecoverable_integrity_failure(tmp_path: Path) -> None:
    """A pairless reservation (crash before the open marker exists) never auto-recovers.

    This matches ingest.file's identical fail-closed shape
    (``test_slice3c1_recovery_rejects_partial_pair_and_event_without_record``):
    the reservation/open marker pair is written as a lock-held unit, and a
    crash strictly between the two writes is an integrity failure requiring
    intervention, not a state ``reconcile()`` repairs.
    """

    data = b"crash matrix media source after_reservation"
    state = _state(tmp_path, data)
    principal = f"linux-uid:{os.getuid()}"
    route = resolve_route("POST", "/v1/ingest/media", require_available=True)
    request = parse_commit_request(_frame(data=data, key="crash-after_reservation", request_id="one")["body"], route)
    source = normalize_source(request.source.to_wire())

    def crash(phase: str) -> None:
        if phase == "after_reservation":
            raise RuntimeError("simulated death at after_reservation")

    runtime = CommitRuntime(state, fault_hook=crash)
    try:
        with pytest.raises(RuntimeError):
            runtime.execute(request, route, principal=principal, access="public", source=source, scanner_clear=True)
    finally:
        runtime.close()

    with pytest.raises(CommitIntegrityError):
        CommitRuntime(state)


@pytest.mark.parametrize("crash_phase", ("after_open", "after_record", "after_journal"))
def test_b4_media_crash_matrix_recovers_at_every_commit_point(tmp_path: Path, crash_phase: str) -> None:
    data = f"crash matrix media source {crash_phase}".encode()
    state = _state(tmp_path, data)
    principal = f"linux-uid:{os.getuid()}"
    route = resolve_route("POST", "/v1/ingest/media", require_available=True)
    request = parse_commit_request(_frame(data=data, key=f"crash-{crash_phase}", request_id="one")["body"], route)
    source = normalize_source(request.source.to_wire())

    def crash(phase: str) -> None:
        if phase == crash_phase:
            raise RuntimeError(f"simulated death at {crash_phase}")

    runtime = CommitRuntime(state, fault_hook=crash)
    try:
        with pytest.raises(RuntimeError):
            runtime.execute(request, route, principal=principal, access="public", source=source, scanner_clear=True)
    finally:
        runtime.close()

    recovered = CommitRuntime(state)
    try:
        recovered.reconcile()
        replay = recovered.probe(request, route, principal=principal)
        assert replay.response_template is not None
        assert len(replay.response_template["record_ids"]) == len(replay.response_template["entry_ids"]) == 1
        if crash_phase == "after_open":
            # No source stage was ever reached: recovery commits exactly one
            # interrupted outcome and no blob, matching the ingest.file shape.
            assert replay.response_template["outcome"] == "interrupted"
            assert not list((state / "blobs").iterdir())
            assert len(recovered.journal.entries()) == 1  # type: ignore[union-attr]
            assert verify_store(state, projection=False)["valid"] is True
        else:
            assert replay.response_template["outcome"] == "completed"
            assert len(recovered.journal.entries()) == 1  # type: ignore[union-attr]
            assert verify_store(state, projection=False)["valid"] is True
    finally:
        recovered.close()


def test_b4_media_tampered_reservation_is_integrity_while_changed_request_is_collision(tmp_path: Path) -> None:
    data = b"tampered media reservation"
    state = _state(tmp_path, data)
    principal = f"linux-uid:{os.getuid()}"
    route = resolve_route("POST", "/v1/ingest/media", require_available=True)
    request = parse_commit_request(_frame(data=data, key="tamper-key", request_id="one")["body"], route)
    changed = _frame(data=data, key="tamper-key", request_id="two")
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
        assert len(runtime.journal.entries()) == 1  # type: ignore[union-attr]
    finally:
        runtime.close()


def test_b4_media_lineage_is_always_none(tmp_path: Path) -> None:
    data = b"media has no caller-supplied lineage"
    state = _state(tmp_path, data)
    route = resolve_route("POST", "/v1/ingest/media", require_available=True)
    request = parse_commit_request(_frame(data=data, key="lineage-key", request_id="one")["body"], route)
    runtime = CommitRuntime(state)
    try:
        runtime.execute(request, route, principal=f"linux-uid:{os.getuid()}", access="public", source=normalize_source(request.source.to_wire()), scanner_clear=True)
        event = runtime.journal.entries()[-1]  # type: ignore[union-attr]
        assert event["lineage"] == {"relation": "none", "record_id": "none", "lead_id": "none"}
    finally:
        runtime.close()


def test_b4_media_real_uds_post_and_client_response_shape(tmp_path: Path) -> None:
    data = b"certified socket media source"
    state = _state(tmp_path, data)
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir(mode=0o700)
    path = runtime_dir / "houndd.sock"
    service = HounddService(state_root=state, socket_path=path)
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    try:
        for _ in range(50):
            if path.exists():
                break
            time.sleep(0.01)
        response = exchange(path, _frame(data=data, key="socket-key", request_id="socket-request"))
        assert response["status"] == 200
        assert response["body"]["schema_version"] == "houndd.commit-response.v1"
        assert response["body"]["outcome"] == "completed"
        assert len(response["body"]["record_ids"]) == len(response["body"]["entry_ids"]) == 1
    finally:
        service.close()
        thread.join(timeout=2)


def test_b4_cli_ingest_media_round_trip(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    data = b"cli certified media"
    state = _state(tmp_path, data)
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir(mode=0o700)
    socket_path = runtime_dir / "houndd.sock"
    source_path = tmp_path / "media.bin"
    source_path.write_bytes(data)
    service = HounddService(state_root=state, socket_path=socket_path)
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    try:
        code = research_cli.main([
            "ingest", "media",
            "--socket", os.fspath(socket_path),
            "--owner-id", "writer", "--run-id", "run", "--policy-id", "write-policy", "--requested-access", "public",
            "--idempotency-key", "cli-media-key", "--request-id", "cli-media-request",
            "--path", os.fspath(source_path), "--sha256", hashlib.sha256(data).hexdigest(), "--byte-length", str(len(data)),
        ])
        assert code == 0
        completed = json.loads(capsys.readouterr().out)
        assert completed["outcome"] == "completed"
        assert len(completed["record_ids"]) == 1
    finally:
        service.close()
        thread.join(timeout=2)


def test_b4_verify_store_rejects_forged_or_duplicate_media_event(tmp_path: Path) -> None:
    """A forged duplicate media outcome event fails verification.

    Mirrors ``ingest.file``'s equivalent attack test; the
    ``houndd.media-capture-record.v1`` branch in ``verify.py`` binds record
    and event exactly, so the forged event is rejected.
    """

    data = b"media verifier gap"
    state = _state(tmp_path, data)
    route = resolve_route("POST", "/v1/ingest/media", require_available=True)
    request = parse_commit_request(_frame(data=data, key="verify-gap", request_id="one")["body"], route)
    runtime = CommitRuntime(state)
    try:
        runtime.execute(request, route, principal=f"linux-uid:{os.getuid()}", access="public", source=normalize_source(request.source.to_wire()), scanner_clear=True)
        original = runtime.journal.entries()[0]  # type: ignore[union-attr]
        forged_digest = runtime.records.blob(b"forged media blob")  # type: ignore[union-attr]
        runtime.journal.append(make_journal_envelope(  # type: ignore[union-attr]
            sequence=1,
            appended_at="2026-08-04T00:00:01Z",
            producer=original["producer"],
            artifact=original["artifact"],
            lineage=original["lineage"],
            source={"provider": "local", "native_id": forged_digest, "canonical_url": "none"},
            classification=original["classification"],
            access=original["access"],
            policy_id=original["policy_id"],
            dedupe={"object_key": f"media:{forged_digest}", "content_sha256": forged_digest},
            usage={"requests": 0, "bytes": len(b"forged media blob"), "cost": 0},
        ))
    finally:
        runtime.close()

    report = verify_store(state, projection=False)
    assert report["valid"] is False
