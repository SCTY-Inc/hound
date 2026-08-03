"""Client-side tests for the hound-research journal.get and record.get read
routes: byte-exact request frames, decode-to file contents, exit-code
mapping, and malformed-argument rejection against a stub houndd, with no
live daemon and no network."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import stat
import threading
from pathlib import Path
from typing import Any

from hound_research import cli as research_cli
from houndd.contracts import canonical_bytes


def run_research_cli(*args: str):
    from io import StringIO
    from contextlib import redirect_stderr, redirect_stdout

    stdout = StringIO()
    stderr = StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = research_cli.main(list(args))
    return code, stdout.getvalue(), stderr.getvalue()


def _read_exact(connection: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            raise AssertionError("stub houndd connection closed before a full frame arrived")
        data.extend(chunk)
    return bytes(data)


class StubHoundd:
    """Accepts exactly one length-prefixed houndd.uds.v1 frame and returns one canned response."""

    def __init__(self, socket_path: Path, response_frame: dict[str, Any]) -> None:
        self.socket_path = socket_path
        self.request_frame: dict[str, Any] | None = None
        self._response_frame = response_frame
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(os.fspath(socket_path))
        self._server.listen(1)
        self._server.settimeout(5)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        connection, _ = self._server.accept()
        with connection:
            connection.settimeout(5)
            length = int.from_bytes(_read_exact(connection, 4), "big")
            raw = _read_exact(connection, length)
            self.request_frame = json.loads(raw.decode("utf-8"))
            encoded = canonical_bytes(self._response_frame)
            connection.sendall(len(encoded).to_bytes(4, "big") + encoded)

    def join(self) -> None:
        self._thread.join(timeout=5)
        self._server.close()


def _envelope_args(socket_path: Path, *, request_id: str | None = None) -> list[str]:
    args = [
        "--socket", str(socket_path),
        "--owner-id", "writer",
        "--run-id", "run-1",
        "--policy-id", "policy-1",
        "--requested-access", "public",
    ]
    if request_id is not None:
        args += ["--request-id", request_id]
    return args


def _read_error_frame(*, request_id: str, status: int, outcome: str, code: str, retryable: bool, message: str = "error") -> dict[str, Any]:
    body = {
        "schema_version": "houndd.read-response.v1",
        "request_id": request_id,
        "ok": False,
        "outcome": outcome,
        "record_ids": [],
        "entry_ids": [],
        "usage": {"requests": 0, "bytes": 0, "cost": 0},
    }
    if status != 404:
        body["error"] = {"code": code, "retryable": retryable, "message": message}
    return {"wire_version": "houndd.uds.v1", "status": status, "body": body}


# --- journal get --------------------------------------------------------------


def _journal_event(*, entry_id: str = "entry-1", record_id: str = "rec-1") -> dict[str, Any]:
    return {
        "entry_id": entry_id,
        "appended_at": "2026-08-03T00:00:00Z",
        "producer": {"owner_id": "writer", "capability": "ingest.file", "run_id": "run-1"},
        "operation": {"capability": "ingest.file", "artifact_kind": "file"},
        "source": {"provider": "local"},
        "classification": {"outcome": "completed", "evidence_status": "clear"},
        "artifact": {"record_id": record_id},
        "lineage": {"relation": "none", "record_id": "none", "lead_id": "none"},
        "access": "public",
    }


def _journal_get_response(*, request_id: str, event: dict[str, Any]) -> dict[str, Any]:
    body = {
        "schema_version": "houndd.read-response.v1",
        "request_id": request_id,
        "ok": True,
        "outcome": "completed",
        "record_ids": [event["artifact"]["record_id"]],
        "entry_ids": [event["entry_id"]],
        "usage": {"requests": 0, "bytes": 0, "cost": 0},
        "result": [event],
    }
    return {"wire_version": "houndd.uds.v1", "status": 200, "body": body}


def test_journal_get_sends_exact_request_frame_and_prints_the_event(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    event = _journal_event()
    stub = StubHoundd(socket_path, _journal_get_response(request_id="req-1", event=event))

    code, stdout, stderr = run_research_cli(
        "journal", "get",
        *_envelope_args(socket_path, request_id="req-1"),
        "--entry-id", "entry-1",
    )
    stub.join()

    assert stub.request_frame == {
        "wire_version": "houndd.uds.v1",
        "method": "GET",
        "path": "/v1/journal/entry",
        "body": {
            "schema_version": "houndd.read-request.v1",
            "request_id": "req-1",
            "producer": {"owner_id": "writer", "capability": "journal.get", "run_id": "run-1"},
            "requested_access": "public",
            "policy_id": "policy-1",
            "operation": {"name": "journal.get", "payload": {"entry_id": "entry-1"}},
        },
    }
    assert code == 0, stderr
    assert json.loads(stdout) == event


def test_journal_get_default_request_id(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    event = _journal_event()
    stub = StubHoundd(socket_path, _journal_get_response(request_id="hound-research-journal-get", event=event))

    code, _, stderr = run_research_cli("journal", "get", *_envelope_args(socket_path), "--entry-id", "entry-1")
    stub.join()

    assert code == 0, stderr
    assert stub.request_frame["body"]["request_id"] == "hound-research-journal-get"


def test_journal_get_404_is_exit_3(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(socket_path, _read_error_frame(request_id="req-1", status=404, outcome="not_found", code="not_found", retryable=False))

    code, stdout, stderr = run_research_cli(
        "journal", "get", *_envelope_args(socket_path, request_id="req-1"), "--entry-id", "entry-1",
    )
    stub.join()

    assert code == 3, stderr
    assert stdout == ""
    assert json.loads(stderr)["schema_version"] == "hound.error.v1"


def test_journal_get_unavailable_is_exit_5(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(
        socket_path,
        _read_error_frame(request_id="req-1", status=503, outcome="unavailable", code="unavailable", retryable=True),
    )

    code, stdout, stderr = run_research_cli(
        "journal", "get", *_envelope_args(socket_path, request_id="req-1"), "--entry-id", "entry-1",
    )
    stub.join()

    assert code == 5, stderr
    assert stdout == ""


def test_journal_get_invalid_request_is_exit_2(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(
        socket_path,
        _read_error_frame(request_id="req-1", status=400, outcome="invalid", code="invalid_request", retryable=False),
    )

    code, stdout, stderr = run_research_cli(
        "journal", "get", *_envelope_args(socket_path, request_id="req-1"), "--entry-id", "entry-1",
    )
    stub.join()

    assert code == 2, stderr
    assert stdout == ""


def test_journal_get_missing_entry_id_is_rejected_before_any_connection(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"  # never bound: no stub server is started

    code, stdout, stderr = run_research_cli("journal", "get", *_envelope_args(socket_path))

    assert code == 2
    assert stdout == ""
    assert json.loads(stderr)["schema_version"] == "hound.error.v1"


def test_journal_get_invalid_requested_access_is_exit_2(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"  # never bound: no stub server is started

    code, stdout, stderr = run_research_cli(
        "journal", "get",
        "--socket", str(socket_path),
        "--owner-id", "writer",
        "--run-id", "run-1",
        "--policy-id", "policy-1",
        "--requested-access", "not-a-real-tier",
        "--entry-id", "entry-1",
    )

    assert code == 2
    assert stdout == ""


# --- record get -----------------------------------------------------------


def _record_result(*, record_id: str = "rec-1", body: bytes = b"hello world", content: bytes | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema": "hound.record.v1",
        "record_id": record_id,
        "body_base64": base64.b64encode(body).decode("ascii"),
        "byte_length": len(body),
    }
    if content is not None:
        result["content_base64"] = base64.b64encode(content).decode("ascii")
        result["content_sha256"] = hashlib.sha256(content).hexdigest()
        result["content_byte_length"] = len(content)
    return result


def _record_get_response(*, request_id: str, result: dict[str, Any]) -> dict[str, Any]:
    body = {
        "schema_version": "houndd.read-response.v1",
        "request_id": request_id,
        "ok": True,
        "outcome": "completed",
        "record_ids": [result["record_id"]],
        "entry_ids": [],
        "usage": {"requests": 0, "bytes": 0, "cost": 0},
        "result": [result],
    }
    return {"wire_version": "houndd.uds.v1", "status": 200, "body": body}


def test_record_get_sends_exact_request_frame_without_include_content(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    result = _record_result()
    stub = StubHoundd(socket_path, _record_get_response(request_id="req-1", result=result))

    code, stdout, stderr = run_research_cli(
        "record", "get",
        *_envelope_args(socket_path, request_id="req-1"),
        "--record-id", "rec-1",
    )
    stub.join()

    assert stub.request_frame == {
        "wire_version": "houndd.uds.v1",
        "method": "GET",
        "path": "/v1/record",
        "body": {
            "schema_version": "houndd.read-request.v1",
            "request_id": "req-1",
            "producer": {"owner_id": "writer", "capability": "record.get", "run_id": "run-1"},
            "requested_access": "public",
            "policy_id": "policy-1",
            "operation": {"name": "record.get", "payload": {"record_id": "rec-1"}},
        },
    }
    assert code == 0, stderr
    printed = json.loads(stdout)
    assert printed["body_base64"] == "<11 bytes>"
    assert printed["byte_length"] == 11
    assert printed["record_id"] == "rec-1"


def test_record_get_include_content_flag_adds_payload_key(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    result = _record_result(content=b"attached bytes")
    stub = StubHoundd(socket_path, _record_get_response(request_id="req-1", result=result))

    code, stdout, stderr = run_research_cli(
        "record", "get",
        *_envelope_args(socket_path, request_id="req-1"),
        "--record-id", "rec-1",
        "--include-content",
    )
    stub.join()

    assert code == 0, stderr
    assert stub.request_frame["body"]["operation"]["payload"] == {"record_id": "rec-1", "include_content": True}
    printed = json.loads(stdout)
    assert printed["content_base64"] == "<14 bytes>"
    assert printed["content_byte_length"] == 14


def test_record_get_raw_flag_prints_full_base64(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    result = _record_result(body=b"hello world", content=b"attached bytes")
    stub = StubHoundd(socket_path, _record_get_response(request_id="req-1", result=result))

    code, stdout, stderr = run_research_cli(
        "record", "get",
        *_envelope_args(socket_path, request_id="req-1"),
        "--record-id", "rec-1",
        "--include-content",
        "--raw",
    )
    stub.join()

    assert code == 0, stderr
    printed = json.loads(stdout)
    assert printed["body_base64"] == base64.b64encode(b"hello world").decode("ascii")
    assert printed["content_base64"] == base64.b64encode(b"attached bytes").decode("ascii")


def test_record_get_decode_to_writes_exact_bytes_with_0600_perms(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    body_bytes = b"the exact decoded body"
    content_bytes = b"the exact decoded content"
    result = _record_result(body=body_bytes, content=content_bytes)
    stub = StubHoundd(socket_path, _record_get_response(request_id="req-1", result=result))
    destination = tmp_path / "out" / "record.bin"
    destination.parent.mkdir()

    code, stdout, stderr = run_research_cli(
        "record", "get",
        *_envelope_args(socket_path, request_id="req-1"),
        "--record-id", "rec-1",
        "--include-content",
        "--decode-to", str(destination),
    )
    stub.join()

    assert code == 0, stderr
    assert destination.read_bytes() == body_bytes
    content_path = Path(f"{destination}.content")
    assert content_path.read_bytes() == content_bytes
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert stat.S_IMODE(content_path.stat().st_mode) == 0o600
    # stdout stays elided even though the file on disk holds the raw bytes
    printed = json.loads(stdout)
    assert printed["body_base64"] == f"<{len(body_bytes)} bytes>"


def test_record_get_decode_to_without_include_content_writes_only_body(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    body_bytes = b"body only"
    result = _record_result(body=body_bytes)
    stub = StubHoundd(socket_path, _record_get_response(request_id="req-1", result=result))
    destination = tmp_path / "record.bin"

    code, stdout, stderr = run_research_cli(
        "record", "get",
        *_envelope_args(socket_path, request_id="req-1"),
        "--record-id", "rec-1",
        "--decode-to", str(destination),
    )
    stub.join()

    assert code == 0, stderr
    assert destination.read_bytes() == body_bytes
    assert not Path(f"{destination}.content").exists()


def test_record_get_404_is_exit_3(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(socket_path, _read_error_frame(request_id="req-1", status=404, outcome="not_found", code="not_found", retryable=False))

    code, stdout, stderr = run_research_cli(
        "record", "get", *_envelope_args(socket_path, request_id="req-1"), "--record-id", "rec-1",
    )
    stub.join()

    assert code == 3, stderr
    assert stdout == ""


def test_record_get_content_too_large_is_exit_2(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(
        socket_path,
        _read_error_frame(
            request_id="req-1", status=400, outcome="invalid", code="content_too_large", retryable=False,
            message="record content exceeds the frame",
        ),
    )

    code, stdout, stderr = run_research_cli(
        "record", "get",
        *_envelope_args(socket_path, request_id="req-1"),
        "--record-id", "rec-1",
        "--include-content",
    )
    stub.join()

    assert code == 2, stderr
    assert stdout == ""
    assert "content_too_large" in stderr


def test_record_get_unavailable_is_exit_5(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(
        socket_path,
        _read_error_frame(request_id="req-1", status=503, outcome="unavailable", code="unavailable", retryable=True),
    )

    code, stdout, stderr = run_research_cli(
        "record", "get", *_envelope_args(socket_path, request_id="req-1"), "--record-id", "rec-1",
    )
    stub.join()

    assert code == 5, stderr
    assert stdout == ""


def test_record_get_missing_record_id_is_rejected_before_any_connection(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"  # never bound: no stub server is started

    code, stdout, stderr = run_research_cli("record", "get", *_envelope_args(socket_path))

    assert code == 2
    assert stdout == ""
    assert json.loads(stderr)["schema_version"] == "hound.error.v1"


def test_record_get_invalid_requested_access_is_exit_2(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"  # never bound: no stub server is started

    code, stdout, stderr = run_research_cli(
        "record", "get",
        "--socket", str(socket_path),
        "--owner-id", "writer",
        "--run-id", "run-1",
        "--policy-id", "policy-1",
        "--requested-access", "not-a-real-tier",
        "--record-id", "rec-1",
    )

    assert code == 2
    assert stdout == ""


def test_record_get_non_absolute_socket_is_exit_2(tmp_path: Path) -> None:
    code, stdout, stderr = run_research_cli(
        "record", "get",
        "--socket", "relative/houndd.sock",
        "--owner-id", "writer",
        "--run-id", "run-1",
        "--policy-id", "policy-1",
        "--requested-access", "public",
        "--record-id", "rec-1",
    )

    assert code == 2
    assert stdout == ""
