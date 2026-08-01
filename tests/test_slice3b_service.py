"""Slice 3B UDS service contracts, including hostile framing and lifecycle edges."""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import time

import pytest

from houndd import HounddStore
from houndd.contracts import canonical_bytes, make_journal_envelope
from houndd.service import FrameError, MAX_FRAME_BYTES, read_frame


def _policy(uid: int) -> dict[str, object]:
    return {
        "schema_version": "houndd.policy.v1",
        "rules": [{
            "subject": f"linux-uid:{uid}",
            "claim_selector": {"owner_id": "reader", "capability": "journal.query", "run_id": None},
            "policy_id": "policy-reader",
            "event_producer_selectors": [{"owner_id": "writer", "capability": "capture", "run_id": None}],
            "readable_tiers": ["public", "workspace"],
            "allowed_output_tiers": ["restricted"],
        }],
    }


def _event(sequence: int = 0, *, digest: str = "a" * 64) -> dict[str, object]:
    return make_journal_envelope(
        sequence=sequence,
        appended_at="2026-08-01T00:00:00Z",
        producer={"owner_id": "writer", "capability": "capture", "run_id": "run"},
        artifact={"kind": "capture", "schema": "houndd.capture.v1", "record_id": "record", "hash": digest, "authorized_uri": "houndd://record"},
        lineage={"relation": "none", "record_id": "record", "lead_id": "none"},
        source={"provider": "fixture", "native_id": "fixture", "canonical_url": "https://fixture.test/"},
        classification={"outcome": "completed", "evidence_status": "evidence"},
        access="public",
        policy_id="policy-reader",
        dedupe={"object_key": "fixture", "content_sha256": digest},
        usage={},
    )


def _valid_state(root: Path) -> Path:
    import hashlib

    root.mkdir(mode=0o700)
    service = root / "service"
    service.mkdir(mode=0o700)
    policy = service / "policy.json"
    policy.write_bytes(canonical_bytes(_policy(os.getuid())))
    policy.chmod(0o600)
    digest = hashlib.sha256(b"fixture").hexdigest()
    event = _event(digest=digest)
    with HounddStore(root) as store:
        store.records.put_bytes("record", b"fixture", expected_sha256=digest)
        assert store.records.blob(b"fixture") == digest
        store.journal.append(event)
        store.rebuild_index()
    return root


def _request(*, access: str = "workspace", policy_id: str = "policy-reader", filter_value: dict[str, object] | None = None, operation: str = "journal.query") -> dict[str, object]:
    return {
        "schema_version": "houndd.read-request.v1",
        "request_id": "request-1",
        "producer": {"owner_id": "reader", "capability": operation, "run_id": "client-run"},
        "requested_access": access,
        "policy_id": policy_id,
        "operation": {"name": operation, "payload": {"filter": filter_value or {}, "limit": 10}},
    }


def _frame(value: object) -> bytes:
    raw = canonical_bytes(value)
    return len(raw).to_bytes(4, "big") + raw


def _read_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise AssertionError("truncated response")
        data.extend(part)
    return bytes(data)


def _exchange(path: Path, raw: bytes, *, half_close: bool = True) -> dict[str, object] | None:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(2)
        client.connect(os.fspath(path))
        client.sendall(raw)
        if half_close:
            client.shutdown(socket.SHUT_WR)
        try:
            header = _read_exact(client, 4)
        except (AssertionError, ConnectionError, OSError):
            return None
        size = int.from_bytes(header, "big")
        return json.loads(_read_exact(client, size).decode("utf-8"))


@pytest.fixture
def running_service(tmp_path: Path):
    state = _valid_state(tmp_path / "state")
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
    assert sock.exists()
    try:
        yield state, sock, process
    finally:
        process.terminate()
        process.wait(timeout=5)


def test_slice3b_subprocess_peer_query_strict_frame_and_permissions(running_service) -> None:
    _state, sock, _process = running_service
    response = _exchange(sock, _frame({"wire_version": "houndd.uds.v1", "method": "GET", "path": "/v1/journal", "body": _request()}))
    assert response is not None
    assert response["wire_version"] == "houndd.uds.v1"
    assert response["status"] == 200
    body = response["body"]
    assert body["schema_version"] == "houndd.read-response.v1"
    assert body["entry_ids"] and body["record_ids"] == ["record"]
    assert stat.S_IMODE(sock.stat().st_mode) == 0o600


@pytest.mark.parametrize(
    "raw",
    [
        b"\0\0\0\0",
        (1_048_577).to_bytes(4, "big"),
        b"\0\0\0\x03{}",
        _frame({"wire_version": "houndd.uds.v1", "method": "GET", "path": "/v1/journal?x=1", "body": _request()}),
        _frame({"wire_version": "houndd.uds.v1", "method": "GET", "path": "/v1/journal", "body": _request()}) + b"x",
    ],
)
def test_slice3b_rejects_bad_frame_or_raw_path_without_leaking(running_service, raw: bytes) -> None:
    _state, sock, _process = running_service
    response = _exchange(sock, raw)
    assert response is None or response["status"] == 400


def test_slice3b_policy_ceiling_and_replacement_fail_closed(running_service) -> None:
    state, sock, _process = running_service
    denied = _exchange(sock, _frame({"wire_version": "houndd.uds.v1", "method": "GET", "path": "/v1/journal", "body": _request(access="public", filter_value={"access": ["workspace"]})}))
    assert denied is not None and denied["status"] == 404
    assert denied["body"]["entry_ids"] == denied["body"]["record_ids"] == []
    policy = state / "service" / "policy.json"
    policy.write_bytes(canonical_bytes(_policy(os.getuid())))
    policy.chmod(0o600)
    unavailable = _exchange(sock, _frame({"wire_version": "houndd.uds.v1", "method": "GET", "path": "/v1/ready", "body": _request(operation="service.ready")}))
    assert unavailable is not None and unavailable["status"] == 503


def test_slice3b_cli_query_maps_service_statuses(running_service) -> None:
    _state, sock, _process = running_service
    command = [
        sys.executable, "-m", "hound_research.cli", "journal", "query", "--socket", os.fspath(sock),
        "--owner-id", "reader", "--run-id", "client-run", "--policy-id", "policy-reader", "--filter-json", "{}",
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["schema_version"] == "houndd.read-response.v1"


def test_slice3b_cli_exit_matrix_has_no_direct_fallback(running_service, tmp_path: Path) -> None:
    _state, sock, _process = running_service
    base = [sys.executable, "-m", "hound_research.cli", "journal", "query", "--socket", os.fspath(sock), "--owner-id", "reader", "--run-id", "client-run", "--policy-id"]
    denied = subprocess.run([*base, "wrong", "--filter-json", "{}"], capture_output=True, text=True, check=False)
    invalid = subprocess.run([*base, "policy-reader", "--filter-json", '{"lane":["x"]}'], capture_output=True, text=True, check=False)
    absent = subprocess.run([*base, "policy-reader", "--socket", os.fspath(tmp_path / "absent.sock"), "--filter-json", "{}"], capture_output=True, text=True, check=False)
    assert (denied.returncode, invalid.returncode, absent.returncode) == (3, 2, 5)
    assert all(result.returncode != 4 for result in (denied, invalid, absent))


def test_slice3b_body_limit_is_explicit_and_checked_before_parse() -> None:
    def frame_for(body: dict[str, object]) -> bytes:
        value = {"wire_version": "houndd.uds.v1", "method": "GET", "path": "/v1/journal", "body": body}
        raw = canonical_bytes(value)
        return len(raw).to_bytes(4, "big") + raw

    prefix = len(canonical_bytes({"payload": ""}))
    exact_body = {"payload": "a" * (MAX_FRAME_BYTES - prefix)}
    assert len(canonical_bytes(exact_body)) == MAX_FRAME_BYTES
    class BufferedConnection:
        def __init__(self, raw: bytes) -> None:
            self.raw = raw

        def recv(self, size: int) -> bytes:
            result, self.raw = self.raw[:size], self.raw[size:]
            return result

    for body, accepted in ((exact_body, True), ({"payload": exact_body["payload"] + "a"}, False)):
        connection = BufferedConnection(frame_for(body))
        if accepted:
            assert read_frame(connection)["body"] == body
        else:
            with pytest.raises(FrameError):
                read_frame(connection)
