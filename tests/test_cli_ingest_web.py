"""Client-side tests for the Slice 3C2 ingest search/url commands and the
journal query --view flag: exact request-frame shape and exit-code mapping
against a stub houndd, with no live daemon and no network."""

from __future__ import annotations

import json
import os
import socket
import threading
from pathlib import Path
from typing import Any

import pytest

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


def _envelope_args(socket_path: Path, *, request_id: str = "req-1", idempotency_key: str = "key-1") -> list[str]:
    return [
        "--socket", str(socket_path),
        "--owner-id", "writer",
        "--run-id", "run-1",
        "--policy-id", "policy-1",
        "--requested-access", "public",
        "--idempotency-key", idempotency_key,
        "--request-id", request_id,
    ]


# --- ingest search ----------------------------------------------------------


def test_ingest_search_sends_exact_request_frame_and_returns_completed(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(socket_path, _commit_response(request_id="req-1", ok=True, outcome="completed", record_ids=["rec-1"], entry_ids=["entry-1"]))

    code, stdout, stderr = run_research_cli(
        "ingest", "search",
        *_envelope_args(socket_path),
        "--query", "caregiver respite care",
        "--limit", "7",
    )
    stub.join()

    assert stub.request_frame == {
        "wire_version": "houndd.uds.v1",
        "method": "POST",
        "path": "/v1/ingest/search",
        "body": {
            "schema_version": "houndd.commit-request.v1",
            "request_id": "req-1",
            "idempotency_key": "key-1",
            "producer": {"owner_id": "writer", "capability": "ingest.search", "run_id": "run-1"},
            "requested_access": "public",
            "policy_id": "policy-1",
            "operation": {"name": "ingest.search", "payload": {"query": "caregiver respite care", "limit": 7}},
        },
    }
    assert code == 0, stderr
    assert json.loads(stdout)["record_ids"] == ["rec-1"]


@pytest.mark.parametrize("given,expected", [(0, 1), (1, 1), (-5, 1), (50, 50), (51, 50), (999, 50)])
def test_ingest_search_limit_is_clamped_to_1_50(tmp_path: Path, given: int, expected: int) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(socket_path, _commit_response(request_id="req-1", ok=True, outcome="completed", record_ids=["rec-1"], entry_ids=["entry-1"]))

    code, _, stderr = run_research_cli(
        "ingest", "search",
        *_envelope_args(socket_path),
        "--query", "x",
        "--limit", str(given),
    )
    stub.join()

    assert code == 0, stderr
    assert stub.request_frame["body"]["operation"]["payload"]["limit"] == expected


def test_ingest_search_default_limit_is_10(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(socket_path, _commit_response(request_id="req-1", ok=True, outcome="completed", record_ids=["rec-1"], entry_ids=["entry-1"]))

    code, _, stderr = run_research_cli("ingest", "search", *_envelope_args(socket_path), "--query", "x")
    stub.join()

    assert code == 0, stderr
    assert stub.request_frame["body"]["operation"]["payload"] == {"query": "x", "limit": 10}


def test_ingest_search_empty_query_is_rejected_before_any_connection(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"  # never bound: no stub server is started

    code, stdout, stderr = run_research_cli("ingest", "search", *_envelope_args(socket_path), "--query", "")

    assert code == 2
    assert stdout == ""
    assert json.loads(stderr)["schema_version"] == "hound.error.v1"


# --- ingest url --------------------------------------------------------------


def test_ingest_url_defaults_to_direct_lineage(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(socket_path, _commit_response(request_id="req-1", ok=True, outcome="completed", record_ids=["rec-1"], entry_ids=["entry-1"]))

    code, _, stderr = run_research_cli("ingest", "url", *_envelope_args(socket_path), "--url", "https://example.test/article")
    stub.join()

    assert code == 0, stderr
    assert stub.request_frame == {
        "wire_version": "houndd.uds.v1",
        "method": "POST",
        "path": "/v1/ingest/url",
        "body": {
            "schema_version": "houndd.commit-request.v1",
            "request_id": "req-1",
            "idempotency_key": "key-1",
            "producer": {"owner_id": "writer", "capability": "ingest.url", "run_id": "run-1"},
            "requested_access": "public",
            "policy_id": "policy-1",
            "operation": {"name": "ingest.url", "payload": {"url": "https://example.test/article", "lineage": {"kind": "direct"}}},
        },
    }


def test_ingest_url_with_search_lineage_and_max_pages(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(socket_path, _commit_response(request_id="req-1", ok=True, outcome="completed", record_ids=["rec-1"], entry_ids=["entry-1"]))

    code, _, stderr = run_research_cli(
        "ingest", "url",
        *_envelope_args(socket_path),
        "--url", "https://example.test/article",
        "--max-pages", "5",
        "--lineage-search-record", "search-rec-1",
        "--lead-id", "lead-1",
    )
    stub.join()

    assert code == 0, stderr
    payload = stub.request_frame["body"]["operation"]["payload"]
    assert payload == {
        "url": "https://example.test/article",
        "lineage": {"kind": "search", "record_id": "search-rec-1", "lead_id": "lead-1"},
        "max_pages": 5,
    }


def test_ingest_url_lineage_flags_must_be_given_together(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"  # no stub started: request must never be sent

    code, stdout, stderr = run_research_cli(
        "ingest", "url",
        *_envelope_args(socket_path),
        "--url", "https://example.test/article",
        "--lineage-search-record", "search-rec-1",
    )

    assert code == 2
    assert stdout == ""
    assert json.loads(stderr)["schema_version"] == "hound.error.v1"


@pytest.mark.parametrize("max_pages", ["1", "21", "0"])
def test_ingest_url_max_pages_out_of_range_is_rejected(tmp_path: Path, max_pages: str) -> None:
    socket_path = tmp_path / "houndd.sock"  # no stub started

    code, stdout, stderr = run_research_cli(
        "ingest", "url",
        *_envelope_args(socket_path),
        "--url", "https://example.test/article",
        "--max-pages", max_pages,
    )

    assert code == 2
    assert stdout == ""


def test_ingest_url_rejects_a_non_public_url(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"  # no stub started

    code, stdout, stderr = run_research_cli("ingest", "url", *_envelope_args(socket_path), "--url", "ftp://example.test/x")

    assert code == 2
    assert stdout == ""


# --- transport-level outcome/exit-code mapping (shared machinery) -----------


def test_ingest_search_non_completed_outcome_is_exit_4(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(socket_path, _commit_response(request_id="req-1", ok=False, outcome="refused", record_ids=["rec-1"], entry_ids=["entry-1"]))

    code, stdout, stderr = run_research_cli("ingest", "search", *_envelope_args(socket_path), "--query", "x")
    stub.join()

    assert code == 4, stderr
    assert json.loads(stdout)["outcome"] == "refused"


def test_ingest_search_invalid_request_is_exit_2(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    error = {"code": "invalid_request", "retryable": False, "message": "invalid request"}
    stub = StubHoundd(socket_path, _commit_response(request_id="req-1", ok=False, outcome="invalid", record_ids=[], entry_ids=[], error=error, status=400))

    code, _, stderr = run_research_cli("ingest", "search", *_envelope_args(socket_path), "--query", "x")
    stub.join()

    assert code == 2, stderr


def test_ingest_url_unavailable_service_is_exit_5(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    error = {"code": "unavailable", "retryable": True, "message": "service unavailable"}
    stub = StubHoundd(socket_path, _commit_response(request_id="req-1", ok=False, outcome="unavailable", record_ids=[], entry_ids=[], error=error, status=503))

    code, _, stderr = run_research_cli("ingest", "url", *_envelope_args(socket_path), "--url", "https://example.test/x")
    stub.join()

    assert code == 5, stderr


# --- journal query --view intake-ledger.v1 -----------------------------------


def _read_response(*, request_id: str) -> dict[str, Any]:
    row = {
        "entry_id": "entry-1",
        "appended_at": "2026-08-03T00:00:00Z",
        "producer": {"owner_id": "writer", "capability": "ingest.file", "run_id": "run-1"},
        "operation": {"capability": "ingest.file", "artifact_kind": "file"},
        "source": {"provider": "local"},
        "classification": {"outcome": "completed", "evidence_status": "clear"},
        "artifact": {"record_id": "rec-1"},
        "lineage": {"relation": "none", "record_id": "none", "lead_id": "none"},
        "access": "public",
    }
    body = {
        "schema_version": "houndd.read-response.v1",
        "request_id": request_id,
        "ok": True,
        "outcome": "completed",
        "record_ids": ["rec-1"],
        "entry_ids": ["entry-1"],
        "usage": {"requests": 0, "bytes": 0, "cost": 0},
        "result": [row],
        "projection": {"schema_version": "houndd.intake-ledger.v1", "integrity": "verified", "high_watermark": "hwm-1"},
    }
    return {"wire_version": "houndd.uds.v1", "status": 200, "body": body}


def test_journal_query_view_adds_view_to_payload_and_returns_projection(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(socket_path, _read_response(request_id="req-1"))

    code, stdout, stderr = run_research_cli(
        "journal", "query",
        "--socket", str(socket_path),
        "--owner-id", "writer",
        "--run-id", "run-1",
        "--policy-id", "policy-1",
        "--requested-access", "public",
        "--view", "intake-ledger.v1",
        "--request-id", "req-1",
    )
    stub.join()

    assert code == 0, stderr
    assert stub.request_frame["body"]["operation"]["payload"] == {"filter": {}, "limit": 50, "view": "intake-ledger.v1"}
    body = json.loads(stdout)
    assert body["projection"]["schema_version"] == "houndd.intake-ledger.v1"
    assert body["result"] == [
        {
            "entry_id": "entry-1",
            "appended_at": "2026-08-03T00:00:00Z",
            "producer": {"owner_id": "writer", "capability": "ingest.file", "run_id": "run-1"},
            "operation": {"capability": "ingest.file", "artifact_kind": "file"},
            "source": {"provider": "local"},
            "classification": {"outcome": "completed", "evidence_status": "clear"},
            "artifact": {"record_id": "rec-1"},
            "lineage": {"relation": "none", "record_id": "none", "lead_id": "none"},
            "access": "public",
        }
    ]


def test_journal_query_without_view_omits_it_from_payload(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    body = {
        "schema_version": "houndd.read-response.v1",
        "request_id": "req-1",
        "ok": True,
        "outcome": "completed",
        "record_ids": [],
        "entry_ids": [],
        "usage": {"requests": 0, "bytes": 0, "cost": 0},
        "result": [],
    }
    stub = StubHoundd(socket_path, {"wire_version": "houndd.uds.v1", "status": 200, "body": body})

    code, stdout, stderr = run_research_cli(
        "journal", "query",
        "--socket", str(socket_path),
        "--owner-id", "writer",
        "--run-id", "run-1",
        "--policy-id", "policy-1",
        "--requested-access", "public",
        "--request-id", "req-1",
    )
    stub.join()

    assert code == 0, stderr
    assert "view" not in stub.request_frame["body"]["operation"]["payload"]


def test_journal_query_invalid_view_is_rejected_by_argparse(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"  # no stub started

    code, stdout, stderr = run_research_cli(
        "journal", "query",
        "--socket", str(socket_path),
        "--owner-id", "writer",
        "--run-id", "run-1",
        "--policy-id", "policy-1",
        "--view", "not-a-real-view",
    )

    assert code == 2
    assert stdout == ""
