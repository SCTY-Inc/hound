"""Wire tests for the shared hound_client package: exact request frames,
canonical/echo/bound rejection, and record decoding against a stub houndd,
with no live daemon and no network."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import threading
from pathlib import Path
from typing import Any, Callable

import pytest

from hound_client import (
    MAX_FRAME_BYTES,
    HounddClient,
    HounddClientError,
    HounddJournalCursorRejectedError,
    HounddJournalFilterUnavailableError,
    canonical_bytes,
    default_socket_path,
)
from houndd.contracts import canonical_bytes as houndd_canonical_bytes


def _read_exact(connection: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            raise AssertionError("stub houndd connection closed before a full frame arrived")
        data.extend(chunk)
    return bytes(data)


class StubHoundd:
    """Accepts exactly one length-prefixed frame and writes back the bytes a test supplies."""

    def __init__(self, socket_path: Path, reply: bytes | Callable[[dict[str, Any]], bytes]) -> None:
        self.socket_path = socket_path
        self.request_frame: dict[str, Any] | None = None
        self._reply = reply
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
            reply = self._reply(self.request_frame) if callable(self._reply) else self._reply
            try:
                connection.sendall(reply)
            except OSError:
                # A client that rejects the header hangs up before the body.
                pass

    def join(self) -> None:
        self._thread.join(timeout=5)
        self._server.close()


def _framed(value: dict[str, Any]) -> bytes:
    encoded = houndd_canonical_bytes(value)
    return len(encoded).to_bytes(4, "big") + encoded


def _client(socket_path: Path) -> HounddClient:
    return HounddClient(socket_path, owner_id="lane-owner", policy_id="policy-1")


def _commit_response(
    *,
    request_id: str,
    ok: bool = True,
    outcome: str = "completed",
    record_ids: list[str] | None = None,
    error: dict[str, Any] | None = None,
    status: int = 200,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "schema_version": "houndd.commit-response.v1",
        "request_id": request_id,
        "ok": ok,
        "outcome": outcome,
        "record_ids": [] if record_ids is None else record_ids,
        "entry_ids": ["entry-1"] if record_ids else [],
        "usage": {"requests": 1, "bytes": 0, "cost": 0},
    }
    if error is not None:
        body["error"] = error
    return {"wire_version": "houndd.uds.v1", "status": status, "body": body}


def _read_response(
    *,
    request_id: str,
    result: list[dict[str, Any]] | None = None,
    status: int = 200,
    ok: bool = True,
    outcome: str = "completed",
    error: dict[str, Any] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "schema_version": "houndd.read-response.v1",
        "request_id": request_id,
        "ok": ok,
        "outcome": outcome,
        "record_ids": [row["record_id"] for row in result] if result is not None else [],
        "entry_ids": [],
        "usage": {"requests": 0, "bytes": 0, "cost": 0},
    }
    if result is not None:
        body["result"] = result
    if error is not None:
        body["error"] = error
    if extra is not None:
        body.update(extra)
    return {"wire_version": "houndd.uds.v1", "status": status, "body": body}


def _record_row(record: dict[str, Any], content: bytes | None = None, *, record_id: str = "rec-1") -> dict[str, Any]:
    encoded = houndd_canonical_bytes(record)
    row: dict[str, Any] = {
        "schema": "hound.source.search-record.v2",
        "record_id": record_id,
        "body_base64": base64.b64encode(encoded).decode("ascii"),
        "byte_length": len(encoded),
    }
    if content is not None:
        row["content_base64"] = base64.b64encode(content).decode("ascii")
        row["content_sha256"] = hashlib.sha256(content).hexdigest()
        row["content_byte_length"] = len(content)
    return row


# --- commit -----------------------------------------------------------------


def test_commit_sends_exact_request_frame_and_returns_first_record(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(socket_path, _framed(_commit_response(request_id="req-1", record_ids=["rec-1"])))

    record_id = _client(socket_path).commit(
        path="/v1/ingest/search",
        capability="ingest.search",
        payload={"query": "respite care", "limit": 7},
        idempotency_key="key-1",
        request_id="req-1",
        run_id="run-1",
    )
    stub.join()

    assert record_id == "rec-1"
    assert stub.request_frame == {
        "wire_version": "houndd.uds.v1",
        "method": "POST",
        "path": "/v1/ingest/search",
        "body": {
            "schema_version": "houndd.commit-request.v1",
            "request_id": "req-1",
            "idempotency_key": "key-1",
            "producer": {"owner_id": "lane-owner", "capability": "ingest.search", "run_id": "run-1"},
            "requested_access": "public",
            "policy_id": "policy-1",
            "operation": {"name": "ingest.search", "payload": {"query": "respite care", "limit": 7}},
        },
    }


def test_commit_non_completed_outcome_carries_the_daemon_message(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(
        socket_path,
        _framed(
            _commit_response(
                request_id="req-1",
                ok=False,
                outcome="failed",
                record_ids=["rec-1"],
            )
        ),
    )

    with pytest.raises(HounddClientError) as caught:
        _client(socket_path).commit(
            path="/v1/ingest/search",
            capability="ingest.search",
            payload={"query": "q", "limit": 1},
            idempotency_key="key-1",
            request_id="req-1",
            run_id="run-1",
        )
    stub.join()

    assert str(caught.value) == "ingest.search did not complete: failed"


def test_commit_non_200_status_does_not_invent_a_record(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(
        socket_path,
        _framed(
            _commit_response(
                request_id="req-1",
                ok=False,
                outcome="unavailable",
                status=503,
                error={"code": "unavailable", "retryable": True, "message": "service unavailable"},
            )
        ),
    )

    with pytest.raises(HounddClientError, match="did not complete: service unavailable"):
        _client(socket_path).commit(
            path="/v1/ingest/url",
            capability="ingest.url",
            payload={"url": "https://example.org/", "lineage": {"kind": "direct"}},
            idempotency_key="key-1",
            request_id="req-1",
            run_id="run-1",
        )
    stub.join()


def test_commit_completed_without_record_ids_is_an_error(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(socket_path, _framed(_commit_response(request_id="req-1", record_ids=[])))

    with pytest.raises(HounddClientError, match="completed commit response is invalid"):
        _client(socket_path).commit(
            path="/v1/ingest/search",
            capability="ingest.search",
            payload={"query": "q", "limit": 1},
            idempotency_key="key-1",
            request_id="req-1",
            run_id="run-1",
        )
    stub.join()


def test_commit_rejects_record_counts_that_do_not_bind_its_operation(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    response = _commit_response(request_id="req-1", record_ids=["rec-1", "rec-2"])
    stub = StubHoundd(socket_path, _framed(response))

    with pytest.raises(HounddClientError, match="completed commit response is invalid"):
        _commit(_client(socket_path))
    stub.join()


def test_commit_rejects_the_reviewer_forged_incomplete_completed_response_and_trailing_bytes(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    forged = _commit_response(request_id="req-1", record_ids=["forged-record"])
    forged["body"]["entry_ids"] = []
    stub = StubHoundd(socket_path, _framed(forged) + b"trailing")

    with pytest.raises(HounddClientError):
        _commit(_client(socket_path))
    stub.join()


@pytest.mark.parametrize(
    "mutation",
    (
        lambda response: response["body"].update({"schema_version": "houndd.read-response.v1"}),
        lambda response: response["body"].update({"ok": False}),
        lambda response: response["body"].update({"usage": {"requests": "1", "bytes": 0, "cost": 0}}),
    ),
)
def test_commit_rejects_canonical_but_wrong_operation_response_shape(
    tmp_path: Path,
    mutation: Callable[[dict[str, Any]], None],
) -> None:
    socket_path = tmp_path / "houndd.sock"
    response = _commit_response(request_id="req-1", record_ids=["rec-1"])
    mutation(response)
    stub = StubHoundd(socket_path, _framed(response))

    with pytest.raises(HounddClientError):
        _commit(_client(socket_path))
    stub.join()


# --- transport rejections ---------------------------------------------------


def _commit(client: HounddClient) -> str:
    return client.commit(
        path="/v1/ingest/search",
        capability="ingest.search",
        payload={"query": "q", "limit": 1},
        idempotency_key="key-1",
        request_id="req-1",
        run_id="run-1",
    )


def test_non_canonical_response_frame_is_rejected(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    # Same value, non-canonical encoding: indented and unsorted on the wire.
    encoded = json.dumps(_commit_response(request_id="req-1", record_ids=["rec-1"]), indent=2).encode("utf-8")
    stub = StubHoundd(socket_path, len(encoded).to_bytes(4, "big") + encoded)

    with pytest.raises(HounddClientError, match="houndd response is not canonical"):
        _commit(_client(socket_path))
    stub.join()


def test_duplicate_response_keys_are_rejected_before_schema_validation(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    response = _commit_response(request_id="req-1", record_ids=["rec-1"])
    body = houndd_canonical_bytes(response["body"])
    raw = b'{"body":' + body + b',"body":' + body + b',"status":200,"wire_version":"houndd.uds.v1"}'
    stub = StubHoundd(socket_path, len(raw).to_bytes(4, "big") + raw)

    with pytest.raises(HounddClientError, match="has duplicate JSON keys"):
        _commit(_client(socket_path))
    stub.join()


def test_response_that_is_not_json_is_rejected(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(socket_path, (3).to_bytes(4, "big") + b"{[}")

    with pytest.raises(HounddClientError, match="houndd response is not valid JSON"):
        _commit(_client(socket_path))
    stub.join()


def test_request_id_mismatch_is_rejected(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(socket_path, _framed(_commit_response(request_id="other-request", record_ids=["rec-1"])))

    with pytest.raises(HounddClientError, match="houndd response does not answer this request"):
        _commit(_client(socket_path))
    stub.join()


def test_wire_version_mismatch_is_rejected(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    response = _commit_response(request_id="req-1", record_ids=["rec-1"])
    response["wire_version"] = "houndd.uds.v2"
    stub = StubHoundd(socket_path, _framed(response))

    with pytest.raises(HounddClientError, match="houndd response does not answer this request"):
        _commit(_client(socket_path))
    stub.join()


@pytest.mark.parametrize("declared", [0, MAX_FRAME_BYTES + 1])
def test_frame_length_outside_the_bound_is_rejected_before_the_body(tmp_path: Path, declared: int) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(socket_path, declared.to_bytes(4, "big"))

    with pytest.raises(HounddClientError, match="houndd response frame is out of bounds"):
        _commit(_client(socket_path))
    stub.join()


def test_truncated_response_body_is_rejected(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(socket_path, (64).to_bytes(4, "big") + b"{}")

    with pytest.raises(HounddClientError, match="houndd response was truncated"):
        _commit(_client(socket_path))
    stub.join()


def test_absent_socket_reports_the_daemon_as_unavailable(tmp_path: Path) -> None:
    with pytest.raises(HounddClientError, match="houndd is unavailable: "):
        _commit(_client(tmp_path / "missing.sock"))


def test_client_refuses_relative_and_unsafe_socket_paths() -> None:
    with pytest.raises(HounddClientError):
        HounddClient(Path("relative.sock"), owner_id="lane-owner", policy_id="policy-1")
    with pytest.raises(HounddClientError):
        HounddClient(Path("/tmp/../socket.sock"), owner_id="lane-owner", policy_id="policy-1")


# --- record.get -------------------------------------------------------------


def test_record_get_decodes_the_body_and_derives_its_request_id(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    record = {"schema_version": "hound.source.search-record.v2", "provider": "exa", "leads": []}
    stub = StubHoundd(
        socket_path,
        lambda frame: _framed(_read_response(request_id=frame["body"]["request_id"], result=[_record_row(record, record_id="rec-abcdef")])),
    )

    body, content = _client(socket_path).record_get("rec-abcdef", run_id="run-1")
    stub.join()

    assert body == record
    assert content == b""
    assert stub.request_frame == {
        "wire_version": "houndd.uds.v1",
        "method": "GET",
        "path": "/v1/record",
        "body": {
            "schema_version": "houndd.read-request.v1",
            "request_id": "record-get-rec-abcdef",
            "producer": {"owner_id": "lane-owner", "capability": "record.get", "run_id": "run-1"},
            "requested_access": "public",
            "policy_id": "policy-1",
            "operation": {"name": "record.get", "payload": {"record_id": "rec-abcdef"}},
        },
    }


def test_record_get_with_content_verifies_the_declared_digest(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    document = "# Respite care\n".encode("utf-8")
    stub = StubHoundd(
        socket_path,
        lambda frame: _framed(
            _read_response(
                request_id=frame["body"]["request_id"],
                result=[_record_row({"url": "https://example.org/"}, document)],
            )
        ),
    )

    body, content = _client(socket_path).record_get("rec-1", run_id="run-1", include_content=True, request_id="req-9")
    stub.join()

    assert body == {"url": "https://example.org/"}
    assert content == document
    assert stub.request_frame is not None
    assert stub.request_frame["body"]["request_id"] == "req-9"
    assert stub.request_frame["body"]["operation"]["payload"] == {"record_id": "rec-1", "include_content": True}


def test_record_get_rejects_content_that_does_not_match_its_digest(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    row = _record_row({"url": "https://example.org/"}, b"real document")
    row["content_sha256"] = hashlib.sha256(b"a different document").hexdigest()
    stub = StubHoundd(
        socket_path,
        lambda frame: _framed(_read_response(request_id=frame["body"]["request_id"], result=[row])),
    )

    with pytest.raises(HounddClientError, match="content does not match its declared digest"):
        _client(socket_path).record_get("rec-1", run_id="run-1", include_content=True)
    stub.join()


def test_record_get_rejects_content_that_is_not_base64(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    row = _record_row({"url": "https://example.org/"}, b"real document")
    row["content_base64"] = "not base64!!"
    stub = StubHoundd(
        socket_path,
        lambda frame: _framed(_read_response(request_id=frame["body"]["request_id"], result=[row])),
    )

    with pytest.raises(HounddClientError, match="houndd record content is not valid base64"):
        _client(socket_path).record_get("rec-1", run_id="run-1", include_content=True)
    stub.join()


def test_record_get_rejects_a_body_that_is_not_a_json_object(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    row = _record_row({"url": "https://example.org/"})
    invalid_body = b'["not an object"]'
    row["body_base64"] = base64.b64encode(invalid_body).decode("ascii")
    row["byte_length"] = len(invalid_body)
    stub = StubHoundd(
        socket_path,
        lambda frame: _framed(_read_response(request_id=frame["body"]["request_id"], result=[row])),
    )

    with pytest.raises(HounddClientError, match="body is not canonical"):
        _client(socket_path).record_get("rec-1", run_id="run-1")
    stub.join()


def test_record_get_rejects_a_missing_result(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(
        socket_path,
        lambda frame: _framed(_read_response(request_id=frame["body"]["request_id"], result=[])),
    )

    with pytest.raises(HounddClientError, match="record response is invalid"):
        _client(socket_path).record_get("rec-1", run_id="run-1")
    stub.join()


def test_record_get_non_200_reports_the_daemon_message(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(
        socket_path,
        lambda frame: _framed(
            _read_response(
                request_id=frame["body"]["request_id"],
                status=404,
                ok=False,
                outcome="not_found",
            )
        ),
    )

    with pytest.raises(HounddClientError, match="record.get rec-1 failed: not_found"):
        _client(socket_path).record_get("rec-1", run_id="run-1")
    stub.join()


# --- journal.query -----------------------------------------------------------


def _journal_entry_dict(*, entry_index: int = 0, access: str = "public") -> dict[str, Any]:
    unsigned = {
        "schema_version": "houndd.journal.v1",
        "sequence": entry_index,
        "appended_at": "2026-08-01T00:00:00Z",
        "producer": {"owner_id": "ingest", "capability": "capture", "run_id": "seed"},
        "artifact": {
            "kind": "capture",
            "schema": "houndd.capture.v1",
            "record_id": f"record-{entry_index}",
            "hash": hashlib.sha256(f"record-{entry_index}".encode()).hexdigest(),
            "authorized_uri": f"houndd://record-{entry_index}",
        },
        "classification": {"outcome": "completed", "evidence_status": "evidence"},
        "access": access,
        "policy_id": "policy-1",
        "dedupe": {
            "object_key": f"record-{entry_index}",
            "content_sha256": hashlib.sha256(f"content-{entry_index}".encode()).hexdigest(),
        },
        "lineage": {"relation": "none", "record_id": f"record-{entry_index}", "lead_id": "none"},
        "source": {"provider": "fixture", "native_id": f"record-{entry_index}", "canonical_url": f"https://fixture.test/{entry_index}"},
        "usage": {},
    }
    entry = dict(unsigned)
    entry["entry_id"] = hashlib.sha256(houndd_canonical_bytes(unsigned)).hexdigest()
    return entry


def _journal_response(
    *,
    request_id: str,
    entries: list[dict[str, Any]] | None = None,
    cursor: str | None = None,
    status: int = 200,
    ok: bool = True,
    outcome: str = "completed",
    error: dict[str, Any] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result = [] if entries is None else entries
    body: dict[str, Any] = {
        "schema_version": "houndd.read-response.v1",
        "request_id": request_id,
        "ok": ok,
        "outcome": outcome,
        "record_ids": [entry["artifact"]["record_id"] for entry in result],
        "entry_ids": [entry["entry_id"] for entry in result],
        "usage": {"requests": 0, "bytes": 0, "cost": 0},
    }
    if status == 200:
        body["result"] = result
        if cursor is not None:
            body["cursor"] = cursor
    if error is not None:
        body["error"] = error
    if extra is not None:
        body.update(extra)
    return {"wire_version": "houndd.uds.v1", "status": status, "body": body}


def _journal_query(
    client: HounddClient, *, cursor: str | None = None, request_id: str = "journal-req-1"
) -> tuple[list[dict[str, Any]], str | None]:
    return client.journal_query(cursor=cursor, limit=10, run_id="run-1", request_id=request_id)


def test_journal_query_sends_exact_request_frame_and_returns_entries_and_cursor(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    entry = _journal_entry_dict()
    stub = StubHoundd(
        socket_path,
        lambda frame: _framed(_journal_response(request_id=frame["body"]["request_id"], entries=[entry], cursor="cursor-token-1")),
    )

    entries, cursor = _client(socket_path).journal_query(cursor=None, limit=10, run_id="run-1", request_id="journal-req-1")
    stub.join()

    assert entries == [entry]
    assert cursor == "cursor-token-1"
    assert stub.request_frame == {
        "wire_version": "houndd.uds.v1",
        "method": "GET",
        "path": "/v1/journal",
        "body": {
            "schema_version": "houndd.read-request.v1",
            "request_id": "journal-req-1",
            "producer": {"owner_id": "lane-owner", "capability": "journal.query", "run_id": "run-1"},
            "requested_access": "public",
            "policy_id": "policy-1",
            "operation": {"name": "journal.query", "payload": {"filter": {}, "limit": 10}},
        },
    }


def test_journal_query_includes_the_cursor_in_the_request_payload_when_provided(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(socket_path, lambda frame: _framed(_journal_response(request_id=frame["body"]["request_id"], entries=[])))

    entries, cursor = _client(socket_path).journal_query(cursor="prior-cursor", limit=5, run_id="run-1", request_id="journal-req-2")
    stub.join()

    assert entries == []
    assert cursor is None
    assert stub.request_frame is not None
    assert stub.request_frame["body"]["operation"]["payload"] == {"filter": {}, "limit": 5, "cursor": "prior-cursor"}


def test_journal_query_rejects_a_forged_entry_with_a_tampered_field_but_unchanged_ids(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    entry = _journal_entry_dict()
    tampered = dict(entry)
    tampered["access"] = "restricted"  # flipped after the entry ID was computed; the ID no longer binds
    stub = StubHoundd(
        socket_path,
        lambda frame: _framed(_journal_response(request_id=frame["body"]["request_id"], entries=[tampered])),
    )

    with pytest.raises(HounddClientError, match="entry ID does not match its canonical envelope"):
        _journal_query(_client(socket_path))
    stub.join()


def test_journal_query_rejects_duplicate_response_keys(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    response = _journal_response(request_id="journal-req-1", entries=[])
    body = houndd_canonical_bytes(response["body"])
    raw = b'{"body":' + body + b',"body":' + body + b',"status":200,"wire_version":"houndd.uds.v1"}'
    stub = StubHoundd(socket_path, len(raw).to_bytes(4, "big") + raw)

    with pytest.raises(HounddClientError, match="has duplicate JSON keys"):
        _journal_query(_client(socket_path))
    stub.join()


def test_journal_query_rejects_trailing_bytes(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(socket_path, _framed(_journal_response(request_id="journal-req-1", entries=[])) + b"trailing")

    with pytest.raises(HounddClientError, match="trailing bytes"):
        _journal_query(_client(socket_path))
    stub.join()


def test_journal_query_rejects_wrong_request_id(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(socket_path, _framed(_journal_response(request_id="other-request", entries=[])))

    with pytest.raises(HounddClientError, match="houndd response does not answer this request"):
        _journal_query(_client(socket_path))
    stub.join()


def test_journal_query_rejects_a_non_canonical_response(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    encoded = json.dumps(_journal_response(request_id="journal-req-1", entries=[]), indent=2).encode("utf-8")
    stub = StubHoundd(socket_path, len(encoded).to_bytes(4, "big") + encoded)

    with pytest.raises(HounddClientError, match="houndd response is not canonical"):
        _journal_query(_client(socket_path))
    stub.join()


def test_journal_query_rejects_ids_that_do_not_bind_the_result(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    entry = _journal_entry_dict()

    def reply(frame: dict[str, Any]) -> bytes:
        response = _journal_response(request_id=frame["body"]["request_id"], entries=[entry])
        response["body"]["entry_ids"] = ["some-other-entry-id"]
        return _framed(response)

    stub = StubHoundd(socket_path, reply)

    with pytest.raises(HounddClientError, match="ids do not bind its result"):
        _journal_query(_client(socket_path))
    stub.join()


def test_journal_query_rejects_an_unrequested_projection_field(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(
        socket_path,
        lambda frame: _framed(
            _journal_response(
                request_id=frame["body"]["request_id"],
                entries=[],
                extra={"projection": {"schema_version": "houndd.intake-ledger.v1", "integrity": "verified", "high_watermark": "0"}},
            )
        ),
    )

    with pytest.raises(HounddClientError, match="houndd journal response is invalid"):
        _journal_query(_client(socket_path))
    stub.join()


def test_journal_query_surfaces_filter_not_available_as_a_distinct_error(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(
        socket_path,
        lambda frame: _framed(
            _journal_response(
                request_id=frame["body"]["request_id"],
                status=400,
                ok=False,
                outcome="invalid",
                error={"code": "filter_not_available", "retryable": False, "message": "filter is not available"},
            )
        ),
    )

    with pytest.raises(HounddJournalFilterUnavailableError, match="filter is not available"):
        _journal_query(_client(socket_path))
    stub.join()


def test_journal_query_surfaces_a_rejected_cursor_as_a_distinct_error(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(
        socket_path,
        lambda frame: _framed(
            _journal_response(
                request_id=frame["body"]["request_id"],
                status=400,
                ok=False,
                outcome="invalid",
                error={"code": "invalid_request", "retryable": False, "message": "request is invalid"},
            )
        ),
    )

    with pytest.raises(HounddJournalCursorRejectedError, match="rejected the persisted cursor"):
        _client(socket_path).journal_query(cursor="stale-cursor", limit=10, run_id="run-1", request_id="journal-req-1")
    stub.join()


def test_journal_query_400_without_a_cursor_is_generic_not_cursor_rejected(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(
        socket_path,
        lambda frame: _framed(
            _journal_response(
                request_id=frame["body"]["request_id"],
                status=400,
                ok=False,
                outcome="invalid",
                error={"code": "invalid_request", "retryable": False, "message": "request is invalid"},
            )
        ),
    )

    with pytest.raises(HounddClientError) as caught:
        _client(socket_path).journal_query(cursor=None, limit=10, run_id="run-1", request_id="journal-req-1")
    stub.join()

    assert not isinstance(caught.value, HounddJournalCursorRejectedError)
    assert not isinstance(caught.value, HounddJournalFilterUnavailableError)


def test_journal_query_rejects_an_error_code_outside_the_allowlist(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(
        socket_path,
        lambda frame: _framed(
            _journal_response(
                request_id=frame["body"]["request_id"],
                status=400,
                ok=False,
                outcome="invalid",
                error={"code": "made_up_error", "retryable": False, "message": "request is invalid"},
            )
        ),
    )

    with pytest.raises(HounddClientError, match="journal error is invalid"):
        _journal_query(_client(socket_path))
    stub.join()


@pytest.mark.parametrize(
    "status,outcome,error",
    (
        (404, "not_found", None),
        (503, "unavailable", {"code": "service_unavailable", "retryable": True, "message": "service is unavailable"}),
        (503, "unavailable", {"code": "response_too_large", "retryable": True, "message": "service response is unavailable"}),
    ),
)
def test_journal_query_non_completed_statuses_report_the_daemon_message(
    tmp_path: Path,
    status: int,
    outcome: str,
    error: dict[str, Any] | None,
) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(
        socket_path,
        lambda frame: _framed(
            _journal_response(request_id=frame["body"]["request_id"], status=status, ok=False, outcome=outcome, error=error)
        ),
    )

    with pytest.raises(HounddClientError, match="journal.query failed"):
        _journal_query(_client(socket_path))
    stub.join()


def test_journal_query_rejects_an_out_of_range_limit(tmp_path: Path) -> None:
    with pytest.raises(HounddClientError, match="journal limit is invalid"):
        _client(tmp_path / "houndd.sock").journal_query(limit=0, run_id="run-1", request_id="journal-req-1")


def test_journal_query_rejects_a_non_dict_filter(tmp_path: Path) -> None:
    with pytest.raises(HounddClientError, match="journal filter is invalid"):
        _client(tmp_path / "houndd.sock").journal_query(
            query_filter=["not", "a", "dict"],  # type: ignore[arg-type]
            run_id="run-1",
            request_id="journal-req-1",
        )


# --- readiness --------------------------------------------------------------


def test_ready_accepts_an_ok_probe_and_sends_the_service_ready_frame(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(socket_path, _framed(_read_response(request_id="ready-probe", extra={"ok": True})))

    assert _client(socket_path).ready() is None
    stub.join()

    assert stub.request_frame == {
        "wire_version": "houndd.uds.v1",
        "method": "GET",
        "path": "/v1/ready",
        "body": {
            "schema_version": "houndd.read-request.v1",
            "request_id": "ready-probe",
            "producer": {"owner_id": "lane-owner", "capability": "service.ready", "run_id": "ready-check"},
            "requested_access": "public",
            "policy_id": "policy-1",
            "operation": {"name": "service.ready", "payload": {}},
        },
    }


def test_ready_rejects_a_degraded_daemon(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(
        socket_path,
        _framed(
            _read_response(
                request_id="ready-probe",
                status=503,
                ok=False,
                outcome="unavailable",
                error={"code": "service_unavailable", "retryable": True, "message": "service is not ready"},
            )
        ),
    )

    with pytest.raises(HounddClientError, match="houndd is not ready: service is not ready"):
        _client(socket_path).ready()
    stub.join()


def test_ready_on_a_200_that_is_not_ok_is_rejected(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(socket_path, _framed(_read_response(request_id="ready-probe", ok=False, outcome="degraded")))

    with pytest.raises(HounddClientError, match="ready response is invalid"):
        _client(socket_path).ready()
    stub.join()


# --- canonicalization and socket resolution ---------------------------------


@pytest.mark.parametrize(
    "value",
    [
        {},
        [],
        {"b": 1, "a": 2},
        {"z": {"y": [1, 2, {"x": None, "a": True}], "b": ""}, "a": 0},
        {"unicode": "café — 家族", "escaped": 'quote " and \\ and \n'},
        {"numbers": [0, -1, 1.5, 1e30, 0.1]},
        {"nested": [[{"deep": {"deeper": ["value"]}}]], "empty": [{}, []]},
        {"slash": "https://example.org/a?b=c&d=e"},
    ],
)
def test_canonical_bytes_matches_houndd(value: object) -> None:
    assert canonical_bytes(value) == houndd_canonical_bytes(value)


def test_canonical_bytes_refuses_non_finite_numbers() -> None:
    with pytest.raises(ValueError):
        canonical_bytes({"nan": float("nan")})


def test_default_socket_path_prefers_the_runtime_directory(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/run/user/4242")
    assert default_socket_path() == Path("/run/user/4242/hound/houndd.sock")


def test_default_socket_path_falls_back_to_the_user_runtime_directory(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    assert default_socket_path() == Path(f"/run/user/{os.getuid()}/hound/houndd.sock")
