"""Slice 3C1 authz/status gaps: lineage-scope ceiling, PolicyError mapping,
filter_not_available wire code, and unsigned SO_PEERCRED decoding."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import threading
import time

from houndd import HounddStore
from houndd.access import AuthenticatedPrincipal
from houndd.commit import parse_commit_request, resolve_route
from houndd.contracts import canonical_bytes, make_journal_envelope
from houndd.service import HounddService
from hound_research.commit_client import exchange, exit_code


def _writer_policy(*, readable_tiers: list[str], allowed_output_tiers: list[str], policy_id: str = "lineage-policy") -> dict[str, object]:
    return {
        "schema_version": "houndd.policy.v1",
        "rules": [{
            "subject": f"linux-uid:{os.getuid()}",
            "claim_selector": {"owner_id": None, "capability": "ingest.file", "run_id": None},
            "policy_id": policy_id,
            "event_producer_selectors": [{"owner_id": None, "capability": None, "run_id": None}],
            "readable_tiers": readable_tiers,
            "allowed_output_tiers": allowed_output_tiers,
        }],
    }


def _state(tmp_path: Path, policy: dict[str, object], data: bytes) -> Path:
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    HounddStore(root).close()
    service = root / "service"
    service.mkdir(mode=0o700)
    (service / "policy.json").write_bytes(canonical_bytes(policy))
    (service / "policy.json").chmod(0o600)
    digest = hashlib.sha256(data).hexdigest()
    (service / "phi-clear.json").write_bytes(canonical_bytes({
        "schema_version": "houndd.phi-clear.v1",
        "entries": [{"sha256": digest, "media_type": "application/octet-stream", "encoding": "identity"}],
    }))
    (service / "phi-clear.json").chmod(0o600)
    return root


def _commit_frame(*, data: bytes, request_id: str, policy_id: str, requested_access: str) -> dict[str, object]:
    digest = hashlib.sha256(data).hexdigest()
    return {
        "wire_version": "houndd.uds.v1",
        "method": "POST",
        "path": "/v1/ingest/file",
        "body": {
            "schema_version": "houndd.commit-request.v1",
            "request_id": request_id,
            "idempotency_key": request_id,
            "producer": {"owner_id": "writer", "capability": "ingest.file", "run_id": "run"},
            "requested_access": requested_access,
            "policy_id": policy_id,
            "operation": {
                "name": "ingest.file",
                "payload": {
                    "source": {"kind": "bytes", "body_base64": base64.b64encode(data).decode("ascii"), "sha256": digest, "byte_length": len(data)},
                    "media_type": "application/octet-stream",
                },
            },
        },
    }


def test_slice3c1_lineage_scope_clamps_readable_tiers_to_disclosure_ceiling(tmp_path: Path) -> None:
    data = b"lineage scope fixture"
    policy = _writer_policy(readable_tiers=["public", "workspace", "restricted"], allowed_output_tiers=["public", "workspace", "restricted"])
    state = _state(tmp_path, policy, data)
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    service = HounddService(state_root=state, socket_path=runtime / "houndd.sock")
    try:
        frame = _commit_frame(data=data, request_id="lineage-1", policy_id="lineage-policy", requested_access="public")
        route = resolve_route("POST", "/v1/ingest/file", require_available=True)
        request = parse_commit_request(frame["body"], route)
        principal = AuthenticatedPrincipal(f"linux-uid:{os.getuid()}")
        authorized = service._commit_scope(principal, request)
        assert authorized is not None
        access, scope = authorized
        assert access == "public"
        assert scope.readable_tiers == frozenset({"public"})
        assert all(selector.readable_tiers <= frozenset({"public"}) for selector in scope.permitted_event_selectors)
    finally:
        service.close()


def test_slice3c1_policy_replacement_during_commit_yields_503_not_eof(tmp_path: Path) -> None:
    data = b"policy replacement fixture"
    policy = _writer_policy(readable_tiers=["public"], allowed_output_tiers=["public"])
    state = _state(tmp_path, policy, data)
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
        (state / "service" / "policy.json").write_bytes(canonical_bytes(policy))
        (state / "service" / "policy.json").chmod(0o600)
        frame = _commit_frame(data=data, request_id="replaced-policy", policy_id="lineage-policy", requested_access="public")
        response = exchange(path, frame)
        assert response["status"] == 503
        assert response["body"]["error"]["code"] == "unavailable"
        assert exit_code(response) == 5
    finally:
        service.close()
        thread.join(timeout=2)


def _read_policy() -> dict[str, object]:
    return {
        "schema_version": "houndd.policy.v1",
        "rules": [{
            "subject": f"linux-uid:{os.getuid()}",
            "claim_selector": {"owner_id": "reader", "capability": "journal.query", "run_id": None},
            "policy_id": "policy-reader",
            "event_producer_selectors": [{"owner_id": "writer", "capability": "capture", "run_id": None}],
            "readable_tiers": ["public", "workspace"],
            "allowed_output_tiers": ["restricted"],
        }],
    }


def _read_request_frame(*, filter_value: dict[str, object]) -> dict[str, object]:
    return {
        "wire_version": "houndd.uds.v1",
        "method": "GET",
        "path": "/v1/journal",
        "body": {
            "schema_version": "houndd.read-request.v1",
            "request_id": "filter-request",
            "producer": {"owner_id": "reader", "capability": "journal.query", "run_id": "client-run"},
            "requested_access": "workspace",
            "policy_id": "policy-reader",
            "operation": {"name": "journal.query", "payload": {"filter": filter_value, "limit": 10}},
        },
    }


def _read_exact(connection: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        part = connection.recv(size - len(data))
        if not part:
            raise AssertionError("truncated response")
        data.extend(part)
    return bytes(data)


def _read_exchange(path: Path, frame: dict[str, object]) -> dict[str, object]:
    raw = canonical_bytes(frame)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(2)
        client.connect(os.fspath(path))
        client.sendall(len(raw).to_bytes(4, "big") + raw)
        client.shutdown(socket.SHUT_WR)
        size = int.from_bytes(_read_exact(client, 4), "big")
        return json.loads(_read_exact(client, size).decode("utf-8"))


def test_slice3c1_journal_query_lane_filter_returns_filter_not_available(tmp_path: Path) -> None:
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    service_dir = root / "service"
    service_dir.mkdir(mode=0o700)
    (service_dir / "policy.json").write_bytes(canonical_bytes(_read_policy()))
    (service_dir / "policy.json").chmod(0o600)
    with HounddStore(root) as store:
        store.rebuild_index()
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    path = runtime / "houndd.sock"
    service = HounddService(state_root=root, socket_path=path)
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    try:
        for _ in range(50):
            if path.exists():
                break
            time.sleep(0.01)
        response = _read_exchange(path, _read_request_frame(filter_value={"lane": ["x"]}))
        assert response["status"] == 400
        assert response["body"]["error"]["code"] == "filter_not_available"
    finally:
        service.close()
        thread.join(timeout=2)


class _FakePeerCredConnection:
    """Stands in for the accepted socket's ``getsockopt`` only."""

    def __init__(self, raw: bytes) -> None:
        self._raw = raw

    def getsockopt(self, level: int, optname: int, buflen: int) -> bytes:
        assert level == socket.SOL_SOCKET
        assert optname == socket.SO_PEERCRED
        return self._raw[:buflen]


def test_slice3c1_principal_decodes_uid_above_signed_int32_range() -> None:
    uid = 3_000_000_000
    raw = struct.pack("iII", 1, uid, 1)
    connection = _FakePeerCredConnection(raw)
    principal = HounddService._principal(connection)  # type: ignore[arg-type]
    assert principal.subject == f"linux-uid:{uid}"
