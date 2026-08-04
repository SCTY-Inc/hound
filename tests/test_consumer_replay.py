"""Proof: the reference consumer (examples/consumer/consumer.py) replays the
houndd journal without loss or duplication, including across a houndd
restart, and follows the documented replay discipline (docs/how-to-consume.md)
when a cursor is exhausted or rejected.

Runs an ephemeral houndd against a scratch state dir and scratch socket under
pytest's own ``tmp_path`` -- never the production state dir, production
socket, or houndd.service.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from datetime import datetime, timedelta, UTC

import pytest

from houndd import HounddStore
from houndd.contracts import canonical_bytes, make_journal_envelope

_CONSUMER_PATH = Path(__file__).resolve().parents[1] / "examples" / "consumer" / "consumer.py"
_SPEC = importlib.util.spec_from_file_location("hound_examples_consumer", _CONSUMER_PATH)
assert _SPEC is not None and _SPEC.loader is not None
consumer = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(consumer)

OWNER_ID = "reader"
POLICY_ID = "policy-consumer"
RUN_ID = "consumer-test"
WRITER_OWNER_ID = "ingest"
BASE_TIME = datetime(2026, 8, 1, tzinfo=UTC)


def _policy(uid: int) -> dict[str, object]:
    return {
        "schema_version": "houndd.policy.v1",
        "rules": [
            {
                "subject": f"linux-uid:{uid}",
                "claim_selector": {"owner_id": OWNER_ID, "capability": "journal.query", "run_id": None},
                "policy_id": POLICY_ID,
                "event_producer_selectors": [{"owner_id": WRITER_OWNER_ID, "capability": "capture", "run_id": None}],
                "readable_tiers": ["public", "workspace"],
                "allowed_output_tiers": ["restricted"],
            }
        ],
    }


def _write_policy(state_root: Path) -> None:
    service = state_root / "service"
    service.mkdir(mode=0o700, exist_ok=True)
    policy = service / "policy.json"
    policy.write_bytes(canonical_bytes(_policy(os.getuid())))
    policy.chmod(0o600)


def _seed_events(state_root: Path, *, start_sequence: int, count: int) -> list[str]:
    """Append ``count`` durable journal entries directly to the store (offline).

    Returns the appended entry_ids in commit order. Must only be called while
    no houndd process holds this state root.
    """

    entry_ids: list[str] = []
    with HounddStore(state_root) as store:
        for offset in range(count):
            index = start_sequence + offset
            content = f"fixture-{index}".encode()
            digest = hashlib.sha256(content).hexdigest()
            record_id = f"record-{index}"
            store.records.put_bytes(record_id, content, expected_sha256=digest)
            assert store.records.blob(content) == digest
            appended_at = (BASE_TIME + timedelta(seconds=index)).isoformat().replace("+00:00", "Z")
            event = make_journal_envelope(
                sequence=index,
                appended_at=appended_at,
                producer={"owner_id": WRITER_OWNER_ID, "capability": "capture", "run_id": "seed"},
                artifact={
                    "kind": "capture",
                    "schema": "houndd.capture.v1",
                    "record_id": record_id,
                    "hash": digest,
                    "authorized_uri": f"houndd://{record_id}",
                },
                lineage={"relation": "none", "record_id": record_id, "lead_id": "none"},
                source={"provider": "fixture", "native_id": record_id, "canonical_url": f"https://fixture.test/{record_id}"},
                classification={"outcome": "completed", "evidence_status": "evidence"},
                access="public",
                policy_id=POLICY_ID,
                dedupe={"object_key": record_id, "content_sha256": digest},
                usage={},
            )
            store.journal.append(event)
            entry_ids.append(event["entry_id"])
        store.rebuild_index()
    return entry_ids


def _start_service(state_root: Path, socket_path: Path) -> subprocess.Popen:
    process = subprocess.Popen(
        [sys.executable, "-m", "houndd.cli", "serve", "--state", os.fspath(state_root), "--socket", os.fspath(socket_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + 5
    while not socket_path.exists() and process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.02)
    if process.poll() is not None:
        raise AssertionError(f"houndd exited early: {process.stderr.read()}")
    assert socket_path.exists(), "houndd did not create its socket in time"
    return process


def _stop_service(process: subprocess.Popen) -> None:
    process.terminate()
    process.wait(timeout=5)


def _drain(
    socket_path: Path,
    state_path: Path,
    output_path: Path,
    *,
    limit: int,
    max_polls: int = 40,
) -> int:
    """Call run_once until a poll both returns nothing new and drains its cursor.

    This is the steady-state behavior of a scheduled consumer: keep polling
    until there is nothing left to do. It intentionally does not assume how
    many polls a page boundary takes -- that is an implementation detail of
    the query engine's pagination, not part of the replay contract.
    """

    total_new = 0
    for _ in range(max_polls):
        new_count = consumer.run_once(
            socket_path,
            state_path,
            output_path,
            owner_id=OWNER_ID,
            policy_id=POLICY_ID,
            run_id=RUN_ID,
            limit=limit,
        )
        total_new += new_count
        state = consumer.load_state(state_path)
        if state.get("cursor") is None and new_count == 0:
            return total_new
    raise AssertionError(f"consumer did not reach a fixed point within {max_polls} polls")


def _ledger_entry_ids(output_path: Path) -> list[str]:
    if not output_path.exists():
        return []
    lines = [line for line in output_path.read_text(encoding="utf-8").splitlines() if line]
    return [json.loads(line)["entry_id"] for line in lines]


def test_consumer_replays_across_restart_without_loss_or_duplicates(tmp_path: Path) -> None:
    state_root = tmp_path / "state"
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    socket_path = runtime / "houndd.sock"
    consumer_state_path = tmp_path / "lane" / "reader-policy-consumer.consumer-state.json"
    output_path = tmp_path / "lane" / "reader.jsonl"

    state_root.mkdir(mode=0o700)
    _write_policy(state_root)
    first_batch = _seed_events(state_root, start_sequence=0, count=5)

    process = _start_service(state_root, socket_path)
    try:
        new_count = _drain(socket_path, consumer_state_path, output_path, limit=2)
    finally:
        _stop_service(process)

    assert new_count == 5
    assert _ledger_entry_ids(output_path) == first_batch

    # houndd is fully stopped; append more durable journal entries offline,
    # exactly like a lane's own writers would between two consumer polls.
    second_batch = _seed_events(state_root, start_sequence=5, count=3)

    process = _start_service(state_root, socket_path)
    try:
        new_count = _drain(socket_path, consumer_state_path, output_path, limit=2)
    finally:
        _stop_service(process)

    assert new_count == 3
    ledger = _ledger_entry_ids(output_path)
    assert ledger == first_batch + second_batch
    assert len(ledger) == len(set(ledger)) == 8


def test_consumer_process_then_persist_survives_a_crash_between_the_two_steps(tmp_path: Path) -> None:
    state_root = tmp_path / "state"
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    socket_path = runtime / "houndd.sock"
    consumer_state_path = tmp_path / "lane" / "reader.consumer-state.json"
    output_path = tmp_path / "lane" / "reader.jsonl"

    state_root.mkdir(mode=0o700)
    _write_policy(state_root)
    entry_ids = _seed_events(state_root, start_sequence=0, count=2)

    process = _start_service(state_root, socket_path)
    try:
        # Simulate a crash after processing but before the cursor is persisted:
        # call the same two steps run_once uses, but stop short of the write.
        body = consumer.query_journal(
            socket_path,
            owner_id=OWNER_ID,
            policy_id=POLICY_ID,
            run_id=RUN_ID,
            request_id="crash-sim-1",
            cursor=None,
            limit=10,
        )
        consumer.process_entries_idempotent(body["result"], output_path)
        # No consumer.save_state_atomic call: the persisted cursor is still
        # whatever load_state would return with no file on disk (None).
        assert consumer.load_state(consumer_state_path).get("cursor") is None
        assert _ledger_entry_ids(output_path) == entry_ids

        # "Restart" the consumer: it redelivers the same page from scratch.
        new_count = consumer.run_once(
            socket_path,
            consumer_state_path,
            output_path,
            owner_id=OWNER_ID,
            policy_id=POLICY_ID,
            run_id=RUN_ID,
            limit=10,
        )
    finally:
        _stop_service(process)

    # At-least-once redelivery, absorbed by idempotent processing: no new
    # entries, and the ledger still holds each entry_id exactly once.
    assert new_count == 0
    ledger = _ledger_entry_ids(output_path)
    assert ledger == entry_ids
    assert len(ledger) == len(set(ledger))


def test_consumer_resnapshots_when_the_cursor_is_rejected(tmp_path: Path) -> None:
    state_root = tmp_path / "state"
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    socket_path = runtime / "houndd.sock"
    consumer_state_path = tmp_path / "lane" / "reader.consumer-state.json"
    output_path = tmp_path / "lane" / "reader.jsonl"

    state_root.mkdir(mode=0o700)
    _write_policy(state_root)
    entry_ids = _seed_events(state_root, start_sequence=0, count=2)

    consumer_state_path.parent.mkdir(parents=True, exist_ok=True)
    consumer.save_state_atomic(consumer_state_path, {"cursor": "not-a-real-cursor-token"})

    process = _start_service(state_root, socket_path)
    try:
        with pytest.raises(consumer.CursorRejectedError):
            consumer.query_journal(
                socket_path,
                owner_id=OWNER_ID,
                policy_id=POLICY_ID,
                run_id=RUN_ID,
                request_id="rejected-cursor-probe",
                cursor="not-a-real-cursor-token",
                limit=10,
            )

        new_count = consumer.run_once(
            socket_path,
            consumer_state_path,
            output_path,
            owner_id=OWNER_ID,
            policy_id=POLICY_ID,
            run_id=RUN_ID,
            limit=10,
        )
    finally:
        _stop_service(process)

    assert new_count == 2
    assert _ledger_entry_ids(output_path) == entry_ids
    assert consumer.load_state(consumer_state_path).get("cursor") is None
