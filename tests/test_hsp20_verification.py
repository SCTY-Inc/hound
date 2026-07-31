"""HSP-20: independent verification, disposable SQLite, tamper, orphan, and permission evidence."""

from __future__ import annotations

import sqlite3
import json
import stat

import pytest

from houndd import HounddStore, ProjectionError, TransactionError, UnsafeStoreError, make_journal_envelope


def _request(index: int) -> dict[str, object]:
    return {
        "schema_version": "houndd.request.v1",
        "request_id": f"request-{index}",
        "idempotency_key": f"key-{index}",
        "producer": {"owner_id": "owner", "capability": "capture", "run_id": f"run-{index}"},
        "requested_access": "restricted" if index == 1 else "public",
        "policy_id": "policy",
        "operation": {"name": "capture", "payload": {"index": index}},
    }


def _populate(store: HounddStore, count: int = 3) -> None:
    for index in range(count):
        store.begin(_request(index), principal=f"peer:{index}", capability="capture").commit(
            record={"schema_version": "houndd.capture.v1", "index": index}, blob=f"blob-{index}".encode()
        )
    store.rebuild_index()


def test_hsp20_delete_rebuild_projection_matches_journal_and_detects_drift(tmp_path) -> None:
    store = HounddStore(tmp_path / "store")
    _populate(store)
    expected = store.projection.rows()
    store.projection.delete()
    store.rebuild_index()
    assert store.projection.rows() == expected
    connection = sqlite3.connect(store.projection.path)
    connection.execute("UPDATE entries SET outcome = 'tampered' WHERE sequence = 0")
    connection.commit()
    connection.close()
    assert store.verify()["valid"] is False


def test_hsp20_tamper_and_orphans_fail_independent_verification(tmp_path) -> None:
    store = HounddStore(tmp_path / "store")
    _populate(store, count=1)
    record_id = store.journal.entries()[0]["artifact"]["record_id"]
    path = store.records.record_path(record_id)
    path.write_bytes(path.read_bytes() + b"tamper")
    assert store.verify()["valid"] is False

    clean = HounddStore(tmp_path / "clean")
    _populate(clean, count=1)
    clean.records.blob(b"orphan")
    assert clean.verify()["valid"] is False


def test_hsp20_journal_chain_sequence_and_orphan_event_tampering_fails_closed(tmp_path) -> None:
    store = HounddStore(tmp_path / "store")
    _populate(store, count=1)
    events = store.journal.events_path
    original = events.read_bytes()
    events.write_bytes(original.replace(b'"sequence":0', b'"sequence":9', 1))
    assert store.verify()["valid"] is False

    events.write_bytes(original)
    chain = store.journal.chain_path
    chain_bytes = chain.read_bytes()
    chain.write_bytes(chain_bytes.replace(b'"sequence":0', b'"sequence":1', 1))
    assert store.verify()["valid"] is False

    chain.write_bytes(chain_bytes)
    orphan = make_journal_envelope(
        sequence=1,
        appended_at="2026-07-31T00:00:01Z",
        producer={"owner_id": "owner", "capability": "capture", "run_id": "orphan"},
        artifact={"kind": "failure", "schema": "houndd.failure.v1", "record_id": "f" * 64, "hash": "e" * 64, "authorized_uri": "houndd://orphan"},
        lineage={"relation": "none", "record_id": "f" * 64, "lead_id": "none"},
        source={"provider": "provider", "native_id": "orphan", "canonical_url": "none"},
        classification={"outcome": "failed", "evidence_status": "failure"},
        access="restricted",
        policy_id="policy",
        dedupe={"object_key": "orphan", "content_sha256": "d" * 64},
        usage={},
    )
    store.journal.append(orphan)
    assert any("orphan journal record" in failure for failure in store.verify()["failures"])


def test_hsp20_idempotency_stage_and_existing_file_modes_are_verified(tmp_path) -> None:
    store = HounddStore(tmp_path / "store")
    _populate(store, count=1)
    idempotency_file = next((store.root / "transactions" / "idempotency").glob("*.json"))
    idempotency = json.loads(idempotency_file.read_text())
    idempotency["status"] = "complete"
    idempotency["response"] = {"entry_ids": ["not-journaled"], "record_ids": ["not-journaled"]}
    idempotency_file.write_text(json.dumps(idempotency))
    assert store.verify()["valid"] is False

    stage_file = next((store.root / "transactions" / "stages").glob("*.json"))
    stage = json.loads(stage_file.read_text())
    stage["status"] = "drifted"
    stage_file.write_text(json.dumps(stage))
    assert store.verify()["valid"] is False

    idempotency_file.chmod(0o644)
    with pytest.raises(TransactionError):
        HounddStore(store.root)

    clean = HounddStore(tmp_path / "clean")
    _populate(clean, count=1)
    clean.records.record_path(clean.journal.entries()[0]["artifact"]["record_id"]).chmod(0o644)
    assert clean.verify()["valid"] is False
    clean.projection.path.chmod(0o644)
    with pytest.raises(UnsafeStoreError):
        HounddStore(clean.root)


def test_hsp20_new_sqlite_is_owner_only(tmp_path) -> None:
    store = HounddStore(tmp_path / "store")
    _populate(store, count=1)
    assert stat.S_IMODE(store.projection.path.stat().st_mode) == 0o600


def test_hsp20_projection_rebuild_rolls_back_on_fault_and_unsafe_modes_fail_closed(tmp_path) -> None:
    store = HounddStore(tmp_path / "store")
    _populate(store, count=2)
    before = store.projection.rows()

    def fault(point: str) -> None:
        if point == "during_projection_rebuild":
            raise ProjectionError("injected rebuild crash")

    with pytest.raises(ProjectionError):
        store.projection.rebuild(store.journal, store.records, fault=fault)
    assert store.projection.rows() == before

    unsafe = tmp_path / "unsafe"
    unsafe.mkdir()
    unsafe.chmod(0o755)
    with pytest.raises(UnsafeStoreError):
        HounddStore(unsafe)
