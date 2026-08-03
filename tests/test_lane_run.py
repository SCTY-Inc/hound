"""Tests for the stateless hound-lane-run manifest runner: manifest validation,
deterministic idempotency keys, and summary/exit-code behavior against a stub
houndd. No live daemon, no network, no state files."""

from __future__ import annotations

import json
import os
import socket
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from hound_research import lane_run
from houndd.contracts import canonical_bytes


def run_lane_cli(*args: str):
    from io import StringIO
    from contextlib import redirect_stderr, redirect_stdout

    stdout = StringIO()
    stderr = StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = lane_run.main(list(args))
    return code, stdout.getvalue(), stderr.getvalue()


def _read_exact(connection: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            raise AssertionError("stub houndd connection closed before a full frame arrived")
        data.extend(chunk)
    return bytes(data)


class MultiStubHoundd:
    """Accepts N sequential length-prefixed houndd.uds.v1 frames, one canned response each."""

    def __init__(self, socket_path: Path, response_frames: list[dict[str, Any]]) -> None:
        self.socket_path = socket_path
        self.request_frames: list[dict[str, Any]] = []
        self._response_frames = response_frames
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(os.fspath(socket_path))
        self._server.listen(len(response_frames))
        self._server.settimeout(5)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        for response_frame in self._response_frames:
            connection, _ = self._server.accept()
            with connection:
                connection.settimeout(5)
                length = int.from_bytes(_read_exact(connection, 4), "big")
                raw = _read_exact(connection, length)
                self.request_frames.append(json.loads(raw.decode("utf-8")))
                encoded = canonical_bytes(response_frame)
                connection.sendall(len(encoded).to_bytes(4, "big") + encoded)

    def join(self) -> None:
        self._thread.join(timeout=5)
        self._server.close()


def _commit_response(*, request_id: str, ok: bool, outcome: str, record_ids: list[str], entry_ids: list[str], error: dict[str, Any] | None = None, status: int = 200) -> dict[str, Any]:
    body: dict[str, Any] = {
        "schema_version": "houndd.commit-response.v1",
        "request_id": request_id,
        "ok": ok,
        "outcome": outcome,
        "record_ids": record_ids,
        "entry_ids": entry_ids,
        "usage": {"requests": 1, "bytes": 0, "cost": 0},
    }
    if error is not None:
        body["error"] = error
    return {"wire_version": "houndd.uds.v1", "status": status, "body": body}


def _write_manifest(path: Path, value: dict[str, Any]) -> Path:
    manifest_path = path / "manifest.json"
    manifest_path.write_text(json.dumps(value), encoding="utf-8")
    return manifest_path


def _base_manifest(**overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema_version": "hound.lane-manifest.v1",
        "lane": "benefits-radar",
        "owner_id": "writer",
        "run_id": "run-1",
        "policy_id": "policy-1",
        "requested_access": "public",
        "searches": [{"query": "caregiver respite", "limit": 5}],
    }
    value.update(overrides)
    return value


# --- manifest validation ------------------------------------------------


def test_manifest_missing_schema_version_is_exit_2(tmp_path: Path) -> None:
    value = _base_manifest()
    del value["schema_version"]
    manifest_path = _write_manifest(tmp_path, value)

    code, stdout, stderr = run_lane_cli(str(manifest_path))

    assert code == 2
    assert stdout == ""
    assert json.loads(stderr)["schema_version"] == "hound.error.v1"


def test_manifest_wrong_schema_version_is_exit_2(tmp_path: Path) -> None:
    manifest_path = _write_manifest(tmp_path, _base_manifest(schema_version="wrong.v1"))

    code, _, _ = run_lane_cli(str(manifest_path))

    assert code == 2


def test_manifest_unknown_field_is_rejected(tmp_path: Path) -> None:
    manifest_path = _write_manifest(tmp_path, _base_manifest(unexpected="field"))

    code, _, _ = run_lane_cli(str(manifest_path))

    assert code == 2


def test_manifest_requires_at_least_one_nonempty_array(tmp_path: Path) -> None:
    value = _base_manifest()
    del value["searches"]
    manifest_path = _write_manifest(tmp_path, value)

    code, _, _ = run_lane_cli(str(manifest_path))

    assert code == 2


def test_manifest_empty_arrays_still_invalid(tmp_path: Path) -> None:
    manifest_path = _write_manifest(tmp_path, _base_manifest(searches=[], urls=[]))

    code, _, _ = run_lane_cli(str(manifest_path))

    assert code == 2


def test_manifest_search_entry_requires_exact_fields(tmp_path: Path) -> None:
    manifest_path = _write_manifest(tmp_path, _base_manifest(searches=[{"query": "x"}]))

    code, _, _ = run_lane_cli(str(manifest_path))

    assert code == 2


def test_manifest_url_entry_requires_a_public_url(tmp_path: Path) -> None:
    value = _base_manifest()
    del value["searches"]
    value["urls"] = [{"url": "ftp://example.test/x"}]
    manifest_path = _write_manifest(tmp_path, value)

    code, _, _ = run_lane_cli(str(manifest_path))

    assert code == 2


def test_manifest_url_max_pages_out_of_range_is_rejected(tmp_path: Path) -> None:
    value = _base_manifest()
    del value["searches"]
    value["urls"] = [{"url": "https://example.test/a", "max_pages": 1}]
    manifest_path = _write_manifest(tmp_path, value)

    code, _, _ = run_lane_cli(str(manifest_path))

    assert code == 2


def test_manifest_relative_socket_is_rejected(tmp_path: Path) -> None:
    manifest_path = _write_manifest(tmp_path, _base_manifest(socket="relative/path.sock"))

    code, _, _ = run_lane_cli(str(manifest_path))

    assert code == 2


def test_missing_manifest_file_is_exit_2(tmp_path: Path) -> None:
    code, stdout, stderr = run_lane_cli(str(tmp_path / "does-not-exist.json"))

    assert code == 2
    assert stdout == ""


def test_search_limit_is_clamped_in_manifest_entries(tmp_path: Path) -> None:
    value = _base_manifest(searches=[{"query": "x", "limit": 999}])
    manifest = lane_run.load_manifest(_write_manifest(tmp_path, value))

    assert manifest["entries"] == [{"kind": "search", "query": "x", "limit": 50}]


# --- deterministic idempotency keys --------------------------------------


def test_idempotency_key_is_deterministic_for_same_lane_date_and_entry() -> None:
    entry = {"kind": "search", "query": "caregiver respite", "limit": 5}

    first = lane_run.idempotency_key("benefits-radar", "2026-08-03", entry)
    second = lane_run.idempotency_key("benefits-radar", "2026-08-03", entry)

    assert first == second
    assert first.startswith("lane:benefits-radar:2026-08-03:")
    digest_suffix = first.rsplit(":", 1)[-1]
    assert len(digest_suffix) == 12
    assert all(char in "0123456789abcdef" for char in digest_suffix)


def test_idempotency_key_changes_with_date() -> None:
    entry = {"kind": "search", "query": "x", "limit": 5}

    assert lane_run.idempotency_key("lane", "2026-08-03", entry) != lane_run.idempotency_key("lane", "2026-08-04", entry)


def test_idempotency_key_changes_with_lane() -> None:
    entry = {"kind": "search", "query": "x", "limit": 5}

    assert lane_run.idempotency_key("lane-a", "2026-08-03", entry) != lane_run.idempotency_key("lane-b", "2026-08-03", entry)


def test_idempotency_key_changes_with_entry_content() -> None:
    entry_a = {"kind": "search", "query": "x", "limit": 5}
    entry_b = {"kind": "search", "query": "y", "limit": 5}

    assert lane_run.idempotency_key("lane", "2026-08-03", entry_a) != lane_run.idempotency_key("lane", "2026-08-03", entry_b)


def test_rerunning_the_same_manifest_the_same_day_reuses_idempotency_keys(tmp_path: Path) -> None:
    manifest_path = _write_manifest(tmp_path, _base_manifest())
    now = datetime(2026, 8, 3, 12, 0, 0, tzinfo=timezone.utc)

    socket_a = tmp_path / "a.sock"
    stub_a = MultiStubHoundd(socket_a, [_commit_response(request_id="lane-run:benefits-radar:2026-08-03:0", ok=True, outcome="completed", record_ids=["rec-1"], entry_ids=["entry-1"])])
    exit_a = _run_against_socket(manifest_path, socket_a, now)
    stub_a.join()

    socket_b = tmp_path / "b.sock"
    stub_b = MultiStubHoundd(socket_b, [_commit_response(request_id="lane-run:benefits-radar:2026-08-03:0", ok=True, outcome="completed", record_ids=["rec-1"], entry_ids=["entry-1"])])
    exit_b = _run_against_socket(manifest_path, socket_b, now)
    stub_b.join()

    assert exit_a == 0
    assert exit_b == 0
    key_a = stub_a.request_frames[0]["body"]["idempotency_key"]
    key_b = stub_b.request_frames[0]["body"]["idempotency_key"]
    assert key_a == key_b


def _run_against_socket(manifest_path: Path, socket_path: Path, now: datetime) -> int:
    """Run the manifest with its socket overridden, matching what --socket-in-manifest would do."""

    value = json.loads(manifest_path.read_text(encoding="utf-8"))
    value["socket"] = str(socket_path)
    scoped_path = manifest_path.parent / f"scoped-{socket_path.name}.json"
    scoped_path.write_text(json.dumps(value), encoding="utf-8")
    return lane_run.run(scoped_path, now=now)


# --- end-to-end summary and exit codes -----------------------------------


def test_lane_run_end_to_end_all_completed_is_exit_0(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    value = _base_manifest(urls=[{"url": "https://example.test/article", "max_pages": 3}])
    manifest_path = _write_manifest(tmp_path, value)
    socket_path = tmp_path / "houndd.sock"
    responses = [
        _commit_response(request_id="lane-run:benefits-radar:2026-08-03:0", ok=True, outcome="completed", record_ids=["rec-1"], entry_ids=["entry-1"]),
        _commit_response(request_id="lane-run:benefits-radar:2026-08-03:1", ok=True, outcome="completed", record_ids=["rec-2"], entry_ids=["entry-2"]),
    ]
    stub = MultiStubHoundd(socket_path, responses)

    scoped = json.loads(manifest_path.read_text(encoding="utf-8"))
    scoped["socket"] = str(socket_path)
    manifest_path.write_text(json.dumps(scoped), encoding="utf-8")

    code = lane_run.run(manifest_path, now=datetime(2026, 8, 3, tzinfo=timezone.utc))
    stub.join()
    out = capsys.readouterr().out.strip().splitlines()

    assert code == 0
    assert len(out) == 3  # one summary line per entry, plus a final summary line
    entry_lines = [json.loads(line) for line in out[:2]]
    assert entry_lines[0] == {"entry": {"kind": "search", "query": "caregiver respite", "limit": 5}, "outcome": "completed", "ok": True, "record_ids": ["rec-1"], "entry_ids": ["entry-1"]}
    assert entry_lines[1] == {"entry": {"kind": "url", "url": "https://example.test/article", "max_pages": 3}, "outcome": "completed", "ok": True, "record_ids": ["rec-2"], "entry_ids": ["entry-2"]}
    final = json.loads(out[2])
    assert final == {"schema_version": "hound.lane-run.summary.v1", "lane": "benefits-radar", "entries": 2, "exit_code": 0}

    assert stub.request_frames[0]["body"]["operation"]["payload"] == {"query": "caregiver respite", "limit": 5}
    assert stub.request_frames[1]["body"]["operation"]["payload"] == {"url": "https://example.test/article", "lineage": {"kind": "direct"}, "max_pages": 3}


def test_lane_run_reports_the_worst_exit_code_when_one_entry_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    value = _base_manifest(searches=[{"query": "a", "limit": 5}, {"query": "b", "limit": 5}])
    manifest_path = _write_manifest(tmp_path, value)
    socket_path = tmp_path / "houndd.sock"
    error = {"code": "unavailable", "retryable": True, "message": "service unavailable"}
    responses = [
        _commit_response(request_id="lane-run:benefits-radar:2026-08-03:0", ok=True, outcome="completed", record_ids=["rec-1"], entry_ids=["entry-1"]),
        _commit_response(request_id="lane-run:benefits-radar:2026-08-03:1", ok=False, outcome="unavailable", record_ids=[], entry_ids=[], error=error, status=503),
    ]
    stub = MultiStubHoundd(socket_path, responses)

    scoped = json.loads(manifest_path.read_text(encoding="utf-8"))
    scoped["socket"] = str(socket_path)
    manifest_path.write_text(json.dumps(scoped), encoding="utf-8")

    code = lane_run.run(manifest_path, now=datetime(2026, 8, 3, tzinfo=timezone.utc))
    stub.join()
    out = capsys.readouterr().out.strip().splitlines()

    assert code == 5
    final = json.loads(out[-1])
    assert final["exit_code"] == 5
    assert final["entries"] == 2
