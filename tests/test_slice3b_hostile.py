"""Adversarial, live Slice 3B checks kept separate from the happy-path pack."""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import shutil
import threading
import time

import pytest

from houndd.contracts import canonical_bytes
from houndd.access import AuthenticatedPrincipal
from houndd.service import HounddService, ServiceError, parse_read_request, read_frame

from tests.test_slice3b_service import _exchange, _frame, _request, _valid_state, running_service


def _response(*, status: int, request_id: str = "request-1", **body_values: object) -> bytes:
    body: dict[str, object] = {
        "schema_version": "houndd.read-response.v1",
        "request_id": request_id,
        "ok": status == 200,
        "outcome": {200: "completed", 400: "invalid", 404: "not_found", 503: "unavailable"}[status],
        "record_ids": [],
        "entry_ids": [],
        "usage": {"requests": 0, "bytes": 0, "cost": 0},
    }
    if status == 200:
        body["result"] = []
    if status in {400, 503}:
        body["error"] = {"code": "invalid_request" if status == 400 else "service_unavailable", "retryable": status == 503, "message": "safe"}
    body.update(body_values)
    value = {"wire_version": "houndd.uds.v1", "status": status, "body": body}
    return canonical_bytes(value)


@pytest.mark.parametrize(
    "raw",
    [
        # Duplicate field, noncanonical whitespace, trailing bytes, and a
        # second length-prefixed frame each preserve precisely one valid ID.
        b'{"body":{"extra":1,"extra":2,"request_id":"request-1"},"method":"GET","path":"/v1/journal","wire_version":"houndd.uds.v1"}',
        b'{"body": {"request_id":"request-1"},"method":"GET","path":"/v1/journal","wire_version":"houndd.uds.v1"}',
        canonical_bytes({"wire_version": "houndd.uds.v1", "method": "GET", "path": "/v1/journal", "body": _request()}) + b" ",
        canonical_bytes({"wire_version": "houndd.uds.v1", "method": "GET", "path": "/v1/journal", "body": _request()}),
    ],
)
def test_recoverable_id_framing_failures_get_exactly_one_400(running_service, raw: bytes) -> None:
    _state, sock, _process = running_service
    payload = len(raw).to_bytes(4, "big") + raw
    if raw == canonical_bytes({"wire_version": "houndd.uds.v1", "method": "GET", "path": "/v1/journal", "body": _request()}):
        payload += _frame({"wire_version": "houndd.uds.v1", "method": "GET", "path": "/v1/journal", "body": _request()})
    response = _exchange(sock, payload)
    assert response is not None
    assert response["status"] == 400
    assert response["body"]["request_id"] == "request-1"
    assert response["body"]["ok"] is False


def test_preexisting_socket_is_never_replaced_or_cleaned_up(tmp_path: Path) -> None:
    state = _valid_state(tmp_path / "state")
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    path = runtime / "occupied.sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as occupant:
        occupant.bind(os.fspath(path))
        before = path.lstat()
        with pytest.raises(ServiceError, match="already occupied"):
            HounddService(state_root=state, socket_path=path)
        after = path.lstat()
        assert (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino)
        assert stat.S_ISSOCK(after.st_mode)


def test_shutdown_never_unlinks_a_replacement_socket(running_service, tmp_path: Path) -> None:
    _state, path, process = running_service
    displaced = tmp_path / "displaced.sock"
    path.rename(displaced)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as replacement:
        replacement.bind(os.fspath(path))
        expected = path.lstat()
        process.terminate()
        process.wait(timeout=5)
        observed = path.lstat()
        assert (observed.st_dev, observed.st_ino) == (expected.st_dev, expected.st_ino)
        assert stat.S_ISSOCK(observed.st_mode)


def test_policy_service_rename_to_symlink_fails_closed(running_service, tmp_path: Path) -> None:
    state, sock, _process = running_service
    service = state / "service"
    parked = tmp_path / "parked-service"
    outside = tmp_path / "outside-service"
    outside.mkdir(mode=0o700)
    (outside / "policy.json").write_bytes(canonical_bytes({"schema_version": "houndd.policy.v1", "rules": []}))
    (outside / "policy.json").chmod(0o600)
    service.rename(parked)
    service.symlink_to(outside, target_is_directory=True)
    response = _exchange(sock, _frame({"wire_version": "houndd.uds.v1", "method": "GET", "path": "/v1/ready", "body": _request(operation="service.ready")}))
    assert response is not None and response["status"] == 503


def test_policy_id_selects_exactly_one_rule_without_cross_policy_union(tmp_path: Path) -> None:
    state = _valid_state(tmp_path / "state")
    policy = state / "service" / "policy.json"
    value = json.loads(policy.read_text(encoding="utf-8"))
    second = dict(value["rules"][0])
    second["policy_id"] = "policy-second"
    second["readable_tiers"] = ["restricted"]
    value["rules"].append(second)
    policy.write_bytes(canonical_bytes(value))
    policy.chmod(0o600)
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    service = HounddService(state_root=state, socket_path=runtime / "houndd.sock")
    try:
        request = parse_read_request(_request(policy_id="policy-second", access="restricted"))
        scope = service._scope(AuthenticatedPrincipal(f"linux-uid:{os.getuid()}"), request)
        assert scope is not None
        assert scope.readable_tiers == frozenset({"restricted"})
        assert scope.permitted_policy_ids == frozenset({"policy-second"})
    finally:
        service.close()


def test_unauthorized_dispatch_never_reaches_journal_or_cursor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import houndd.service as service_module

    state = _valid_state(tmp_path / "state")
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    service = HounddService(state_root=state, socket_path=runtime / "houndd.sock")
    try:
        monkeypatch.setattr(service_module.DurableJournalQueryAdapter, "execute", lambda *_args, **_kwargs: pytest.fail("unauthorized request reached journal"))
        frame = {"wire_version": "houndd.uds.v1", "method": "GET", "path": "/v1/journal", "body": _request(policy_id="wrong")}
        response = service._dispatch(AuthenticatedPrincipal(f"linux-uid:{os.getuid()}"), frame)
        assert response["status"] == 404
        assert response["body"] == {"schema_version": "houndd.read-response.v1", "request_id": "request-1", "ok": False, "outcome": "not_found", "record_ids": [], "entry_ids": [], "usage": {"requests": 0, "bytes": 0, "cost": 0}}
    finally:
        service.close()


def test_fragmented_reader_is_linear_and_requires_eof() -> None:
    body = {"payload": "x" * 128_000}
    value = {"wire_version": "houndd.uds.v1", "method": "GET", "path": "/v1/journal", "body": body}
    raw = _frame(value)

    class OneByteConnection:
        def __init__(self, data: bytes) -> None:
            self.data = data
            self.calls = 0

        def recv(self, _size: int) -> bytes:
            self.calls += 1
            result, self.data = self.data[:1], self.data[1:]
            return result

    connection = OneByteConnection(raw)
    assert read_frame(connection) == value
    # One read per input byte plus the final EOF probe is an explicit linear
    # upper bound; a repeated immutable-bytes concatenation implementation
    # would be observably quadratic under this fixture.
    assert connection.calls == len(raw) + 1


def test_service_startup_recovers_and_verifies_before_identity_or_bind(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import houndd.service as service_module

    state = _valid_state(tmp_path / "state")
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    order: list[str] = []
    recover = service_module.HounddStore.recover
    verify = service_module.HounddStore.verify
    policy = service_module.load_frozen_policy
    identity = service_module.ServiceIdentity
    bind = service_module.HounddService._bind
    monkeypatch.setattr(service_module.HounddStore, "recover", lambda self: (order.append("recover"), recover(self))[1])
    monkeypatch.setattr(service_module.HounddStore, "verify", lambda self: (order.append("verify"), verify(self))[1])
    monkeypatch.setattr(service_module, "load_frozen_policy", lambda root: (order.append("policy"), policy(root))[1])
    monkeypatch.setattr(service_module, "ServiceIdentity", lambda *args, **kwargs: (order.append("identity"), identity(*args, **kwargs))[1])
    monkeypatch.setattr(service_module.HounddService, "_bind", lambda self: (order.append("bind"), bind(self))[1])
    service = HounddService(state_root=state, socket_path=runtime / "houndd.sock")
    try:
        assert order == ["recover", "verify", "policy", "identity", "bind"]
    finally:
        service.close()


def test_peer_credentials_are_certified_before_any_frame_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import houndd.service as service_module

    state = _valid_state(tmp_path / "state")
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    service = HounddService(state_root=state, socket_path=runtime / "houndd.sock")
    order: list[str] = []
    original_read = service_module.read_frame
    monkeypatch.setattr(service, "_principal", lambda _connection: (order.append("peer"), AuthenticatedPrincipal(f"linux-uid:{os.getuid()}"))[1])
    monkeypatch.setattr(service_module, "read_frame", lambda connection: (order.append("frame"), original_read(connection))[1])
    thread = threading.Thread(target=service.serve_forever)
    thread.start()
    try:
        response = _exchange(service.socket_path, _frame({"wire_version": "houndd.uds.v1", "method": "GET", "path": "/v1/journal", "body": _request()}))
        assert response is not None and response["status"] == 200
        assert order[:2] == ["peer", "frame"]
    finally:
        service.close()
        thread.join(timeout=5)
    assert not thread.is_alive()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="Linux fork semantics required")
def test_forked_child_cannot_serve_or_unlink_parent_socket(tmp_path: Path) -> None:
    state = _valid_state(tmp_path / "state")
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    service = HounddService(state_root=state, socket_path=runtime / "houndd.sock")
    before = service.socket_path.lstat()
    reader, writer = os.pipe()
    child = os.fork()
    if child == 0:  # pragma: no cover - child result is asserted by parent
        os.close(reader)
        try:
            service.serve_forever()
        except ServiceError:
            os.write(writer, b"blocked")
        finally:
            os.close(writer)
        os._exit(0)
    os.close(writer)
    try:
        assert os.read(reader, 32) == b"blocked"
        assert os.waitpid(child, 0)[1] == 0
        after = service.socket_path.lstat()
        assert (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino)
    finally:
        os.close(reader)
        service.close()


def test_service_open_close_is_fd_flat_and_removes_only_its_socket(tmp_path: Path) -> None:
    state = _valid_state(tmp_path / "state")
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    baseline = sorted(os.listdir("/proc/self/fd"))
    for index in range(3):
        path = runtime / f"houndd-{index}.sock"
        service = HounddService(state_root=state, socket_path=path)
        service.close()
        assert not path.exists()
    assert sorted(os.listdir("/proc/self/fd")) == baseline


def test_xdg_default_refuses_missing_or_relative_runtime_and_explicit_socket_lifecycle(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from houndd.cli import _default_socket

    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    with pytest.raises(ServiceError):
        _default_socket()
    monkeypatch.setenv("XDG_RUNTIME_DIR", "relative")
    with pytest.raises(ServiceError):
        _default_socket()
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", os.fspath(runtime))
    assert _default_socket() == runtime / "hound" / "houndd.sock"


def test_cursor_hwm_restart_key_and_principal_isolation(tmp_path: Path) -> None:
    from houndd.cursor import CursorRejected
    from houndd.query_contracts import QueryRequest, parse_query_filter
    from houndd.service_identity import ServiceIdentity
    from houndd.snapshot import DurableJournalQueryAdapter
    from tests.test_hsp08_durable_query import _event, _scope, _store

    root = tmp_path / "store"
    journal, identity, adapter, _events = _store(root)
    try:
        first = adapter.execute(QueryRequest(parse_query_filter({}), limit=1), _scope())
        assert first.next_cursor is not None
        token = first.next_cursor
        journal.append(_event(5, when="2026-08-01T00:00:00Z", run_id="after-hwm"))
        resumed = adapter.execute(QueryRequest(parse_query_filter({}), limit=100, cursor=token), _scope())
        assert all(item.event["sequence"] != 5 for item in resumed.items)
        old_kid = identity.state.active_kid
        identity.close()
        identity = ServiceIdentity(root, create=True)
        adapter = DurableJournalQueryAdapter(journal, identity, nonce_source=lambda size: b"N" * size)
        assert adapter.execute(QueryRequest(parse_query_filter({}), limit=100, cursor=token), _scope()).items
        with pytest.raises(CursorRejected):
            adapter.execute(QueryRequest(parse_query_filter({}), limit=100, cursor=token), _scope("other-principal"))
        identity.rotate_cursor_key()
        identity.retire_cursor_key(old_kid)
        with pytest.raises(CursorRejected):
            adapter.execute(QueryRequest(parse_query_filter({}), limit=100, cursor=token), _scope())
    finally:
        identity.close()
        journal.close()


def test_fake_server_canonical_but_semantically_invalid_reply_exits_five(tmp_path: Path) -> None:
    path = tmp_path / "fake.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(os.fspath(path))
    server.listen(1)
    malformed = _response(status=200, ok=False)

    def fake_server() -> None:
        connection, _ = server.accept()
        with connection:
            while connection.recv(4096):
                pass
            connection.sendall(len(malformed).to_bytes(4, "big") + malformed)
        server.close()

    thread = threading.Thread(target=fake_server)
    thread.start()
    result = subprocess.run([sys.executable, "-m", "hound_research.cli", "journal", "query", "--socket", os.fspath(path), "--owner-id", "reader", "--run-id", "run", "--policy-id", "policy-reader"], capture_output=True, text=True, check=False)
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert result.returncode == 5


def test_socket_client_import_scan_and_isolated_wheel(tmp_path: Path) -> None:
    import ast

    source = (Path(__file__).parents[1] / "src" / "hound_research" / "journal_client.py").read_text(encoding="utf-8")
    imports = {
        node.module for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ImportFrom) and node.module
    }
    assert not {"hound_research.source", "hound_research.web", "hound_research.evidence", "requests", "http.client"} & imports
    service_source = (Path(__file__).parents[1] / "src" / "houndd" / "service.py").read_text(encoding="utf-8")
    assert "AF_INET" not in service_source and "SOCK_DGRAM" not in service_source
    uv = shutil.which("uv")
    assert uv is not None
    dist = tmp_path / "dist"
    subprocess.run([uv, "build", "--out-dir", os.fspath(dist)], cwd=Path(__file__).parents[1], check=True, capture_output=True, text=True, timeout=60)
    wheel = next(dist.glob("*.whl"))
    environment = tmp_path / "wheel-env"
    subprocess.run([uv, "venv", "--python", sys.executable, os.fspath(environment)], check=True, capture_output=True, text=True, timeout=60)
    python = environment / "bin" / "python"
    subprocess.run([uv, "pip", "install", "--python", os.fspath(python), os.fspath(wheel)], check=True, capture_output=True, text=True, timeout=60)
    check = subprocess.run([os.fspath(python), "-I", "-c", "import hound_research.journal_client as m; print(m.__file__)"], cwd=tmp_path, check=True, capture_output=True, text=True, timeout=30)
    assert os.fspath(environment) in check.stdout.strip()


@pytest.mark.parametrize(
    "status,body_values",
    [
        (200, {"ok": False}),
        (400, {"result": []}),
        (404, {"cursor": "cursor"}),
        (503, {"error": {"code": "service_unavailable", "retryable": False, "message": "safe"}}),
        (200, {"request_id": "other"}),
        (200, {"usage": {"requests": "0", "bytes": 0, "cost": 0}}),
    ],
)
def test_socket_only_client_rejects_semantically_invalid_canonical_responses(status: int, body_values: dict[str, object]) -> None:
    # This deliberately imports the dedicated client rather than the legacy
    # command module: its import surface is part of the boundary proof.
    from hound_research.journal_client import JournalClientError, strict_response

    with pytest.raises(JournalClientError):
        strict_response(_response(status=status, **body_values), request_id="request-1")


def test_socket_only_client_accepts_exact_response_and_has_no_legacy_imports() -> None:
    import ast
    import inspect
    from hound_research.journal_client import strict_response

    source = inspect.getsource(__import__("hound_research.journal_client", fromlist=["*"]))
    imports = {node.module for node in ast.walk(ast.parse(source)) if isinstance(node, ast.ImportFrom) and node.module}
    assert not {"hound_research.source", "hound_research.web", "hound_research.evidence"} & imports
    assert strict_response(_response(status=200), request_id="request-1")["status"] == 200
