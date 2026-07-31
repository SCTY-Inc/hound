"""HSP-20: independent verification, disposable SQLite, tamper, orphan, and permission evidence."""

from __future__ import annotations

import os
import sqlite3
import json
import stat
import shutil
from pathlib import Path

import pytest

from houndd import HounddStore, ProjectionError, StoreError, TransactionError, UnsafeStoreError, make_journal_envelope, verify_store


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


def _tree_snapshot(path: Path) -> list[str]:
    return sorted(str(child.relative_to(path)) for child in path.rglob("*"))


def _swap_root(root: Path, replacement_kind: str) -> tuple[Path, Path]:
    backup = root.with_name(f"{root.name}.backup")
    root.rename(backup)
    if replacement_kind == "symlink":
        replacement = root.with_name(f"{root.name}.replacement")
        replacement.mkdir()
        root.symlink_to(replacement, target_is_directory=True)
    elif replacement_kind == "directory":
        root.mkdir()
        replacement = root
    else:  # pragma: no cover - defensive parameter guard
        raise AssertionError(f"unknown replacement kind: {replacement_kind}")
    return backup, replacement


def _swap_root_with_copy(root: Path, replacement_kind: str, *, tamper_record: bool = False) -> tuple[Path, Path]:
    backup = root.with_name(f"{root.name}.backup")
    root.rename(backup)
    if replacement_kind == "symlink":
        replacement = root.with_name(f"{root.name}.replacement")
        shutil.copytree(backup, replacement)
        root.symlink_to(replacement, target_is_directory=True)
    elif replacement_kind == "directory":
        shutil.copytree(backup, root)
        replacement = root
    else:  # pragma: no cover - defensive parameter guard
        raise AssertionError(f"unknown replacement kind: {replacement_kind}")
    if tamper_record:
        record_path = next((replacement / "records").glob("*.bin"))
        record_path.write_bytes(record_path.read_bytes() + b"tampered")
    return backup, replacement


def _fd_count() -> int:
    return len(os.listdir("/proc/self/fd"))


def _swap_index(root: Path, kind: str, *, outside: Path | None = None, swap_back: bool = False) -> None:
    """Replace the visible projection leaf while a held descriptor remains open."""

    index = root / "index.sqlite"
    original = root / ".index.sqlite.original"
    index.rename(original)
    if kind == "symlink":
        assert outside is not None
        index.symlink_to(outside / "index.sqlite")
    elif kind == "different-file":
        replacement = root / ".index.sqlite.replacement"
        replacement.write_bytes(b"not the held database")
        replacement.rename(index)
    else:  # pragma: no cover - defensive parameter guard
        raise AssertionError(f"unknown leaf replacement kind: {kind}")
    if swap_back:
        index.unlink()
        original.rename(index)


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


@pytest.mark.parametrize("replacement_kind", ["symlink", "directory"])
def test_hsp20_projection_rows_fails_closed_when_root_swaps_during_sqlite_open(
    tmp_path, monkeypatch: pytest.MonkeyPatch, replacement_kind: str
) -> None:
    store = HounddStore(tmp_path / "store")
    _populate(store, count=1)
    real_connect = sqlite3.connect
    swapped = False

    def connect_with_swap(*args, **kwargs):
        nonlocal swapped
        if not swapped:
            _swap_root_with_copy(store.root, replacement_kind)
            swapped = True
        return real_connect(*args, **kwargs)

    monkeypatch.setattr("houndd.projection.sqlite3.connect", connect_with_swap)

    with pytest.raises(UnsafeStoreError):
        store.projection.rows()


@pytest.mark.parametrize("replacement_kind", ["symlink", "directory"])
def test_hsp20_verify_store_never_accepts_replacement_truth_during_projection_open(
    tmp_path, monkeypatch: pytest.MonkeyPatch, replacement_kind: str
) -> None:
    store = HounddStore(tmp_path / "store")
    _populate(store, count=1)
    real_connect = sqlite3.connect
    swapped = False

    def connect_with_swap(*args, **kwargs):
        nonlocal swapped
        if not swapped:
            _swap_root_with_copy(store.root, replacement_kind, tamper_record=True)
            swapped = True
        return real_connect(*args, **kwargs)

    monkeypatch.setattr("houndd.projection.sqlite3.connect", connect_with_swap)

    report = verify_store(store.root)
    assert report["valid"] is False
    assert report["failures"]


@pytest.mark.parametrize("replacement_kind", ["symlink", "directory"])
def test_hsp20_projection_rebuild_fails_closed_when_root_swaps_during_sqlite_open_empty(
    tmp_path, monkeypatch: pytest.MonkeyPatch, replacement_kind: str
) -> None:
    store = HounddStore(tmp_path / "store")
    real_connect = sqlite3.connect
    swapped = False

    def connect_with_swap(*args, **kwargs):
        nonlocal swapped
        if not swapped:
            _swap_root_with_copy(store.root, replacement_kind)
            swapped = True
        return real_connect(*args, **kwargs)

    monkeypatch.setattr("houndd.projection.sqlite3.connect", connect_with_swap)

    with pytest.raises(UnsafeStoreError):
        store.rebuild_index()


@pytest.mark.parametrize("replacement_kind", ["symlink", "directory"])
def test_hsp20_projection_rebuild_fails_closed_when_root_swaps_during_sqlite_open_populated(
    tmp_path, monkeypatch: pytest.MonkeyPatch, replacement_kind: str
) -> None:
    store = HounddStore(tmp_path / "store")
    _populate(store, count=1)
    monkeypatch.setattr(store.records, "verify_record", lambda *_args, **_kwargs: True)
    real_connect = sqlite3.connect
    swapped = False

    def connect_with_swap(*args, **kwargs):
        nonlocal swapped
        if not swapped:
            _swap_root_with_copy(store.root, replacement_kind)
            swapped = True
        return real_connect(*args, **kwargs)

    monkeypatch.setattr("houndd.projection.sqlite3.connect", connect_with_swap)

    with pytest.raises(UnsafeStoreError):
        store.rebuild_index()


@pytest.mark.parametrize("replacement_kind", ["symlink", "directory"])
def test_hsp20_projection_delete_fails_closed_when_root_swaps_around_unlink(
    tmp_path, monkeypatch: pytest.MonkeyPatch, replacement_kind: str
) -> None:
    store = HounddStore(tmp_path / "store")
    _populate(store, count=1)
    real_unlink = os.unlink
    swapped = False

    def unlink_with_swap(*args, **kwargs):
        nonlocal swapped
        if not swapped:
            _swap_root_with_copy(store.root, replacement_kind)
            swapped = True
        return real_unlink(*args, **kwargs)

    monkeypatch.setattr("houndd.projection.os.unlink", unlink_with_swap)

    with pytest.raises(UnsafeStoreError):
        store.projection.delete()


@pytest.mark.parametrize("replacement_kind", ["symlink", "different-file"])
def test_hsp20_projection_rows_refuses_leaf_replacement_during_sqlite_open(
    tmp_path, monkeypatch: pytest.MonkeyPatch, replacement_kind: str
) -> None:
    store = HounddStore(tmp_path / "store")
    _populate(store, count=1)
    outside = tmp_path / "outside"
    outside.mkdir()
    real_connect = sqlite3.connect

    def connect_with_leaf_swap(*args, **kwargs):
        _swap_index(store.root, replacement_kind, outside=outside)
        return real_connect(*args, **kwargs)

    monkeypatch.setattr("houndd.projection.sqlite3.connect", connect_with_leaf_swap)

    with pytest.raises(UnsafeStoreError):
        store.projection.rows()
    assert not (outside / "index.sqlite").exists()


def test_hsp20_projection_rows_refuses_leaf_swap_back_during_sqlite_open(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = HounddStore(tmp_path / "store")
    _populate(store, count=1)
    real_connect = sqlite3.connect

    def connect_with_swap_back(*args, **kwargs):
        _swap_index(store.root, "different-file", swap_back=True)
        return real_connect(*args, **kwargs)

    monkeypatch.setattr("houndd.projection.sqlite3.connect", connect_with_swap_back)

    with pytest.raises(UnsafeStoreError):
        store.projection.rows()


@pytest.mark.parametrize("replacement_kind", ["symlink", "different-file"])
def test_hsp20_verify_store_never_accepts_leaf_replacement_truth(
    tmp_path, monkeypatch: pytest.MonkeyPatch, replacement_kind: str
) -> None:
    store = HounddStore(tmp_path / "store")
    _populate(store, count=1)
    outside = tmp_path / "outside"
    outside.mkdir()
    real_connect = sqlite3.connect
    swapped = False

    def connect_with_leaf_swap(*args, **kwargs):
        nonlocal swapped
        if not swapped:
            _swap_index(store.root, replacement_kind, outside=outside)
            swapped = True
        return real_connect(*args, **kwargs)

    monkeypatch.setattr("houndd.projection.sqlite3.connect", connect_with_leaf_swap)

    report = verify_store(store.root)
    assert report["valid"] is False
    assert report["failures"]
    assert not (outside / "index.sqlite").exists()


@pytest.mark.parametrize("replacement_kind", ["symlink", "different-file"])
@pytest.mark.parametrize("populated", [False, True])
def test_hsp20_projection_rebuild_refuses_leaf_replacement_without_outside_write(
    tmp_path, monkeypatch: pytest.MonkeyPatch, replacement_kind: str, populated: bool
) -> None:
    store = HounddStore(tmp_path / "store")
    if populated:
        _populate(store, count=1)
        monkeypatch.setattr(store.records, "verify_record", lambda *_args, **_kwargs: True)
    outside = tmp_path / "outside"
    outside.mkdir()
    real_connect = sqlite3.connect

    def connect_with_leaf_swap(*args, **kwargs):
        _swap_index(store.root, replacement_kind, outside=outside)
        return real_connect(*args, **kwargs)

    monkeypatch.setattr("houndd.projection.sqlite3.connect", connect_with_leaf_swap)

    with pytest.raises(UnsafeStoreError):
        store.rebuild_index()
    assert not (outside / "index.sqlite").exists()


@pytest.mark.parametrize("replacement_kind", ["symlink", "different-file"])
def test_hsp20_projection_delete_refuses_leaf_replacement_around_unlink(
    tmp_path, monkeypatch: pytest.MonkeyPatch, replacement_kind: str
) -> None:
    store = HounddStore(tmp_path / "store")
    _populate(store, count=1)
    outside = tmp_path / "outside"
    outside.mkdir()
    real_unlink = os.unlink

    def unlink_with_leaf_swap(*args, **kwargs):
        _swap_index(store.root, replacement_kind, outside=outside)
        return real_unlink(*args, **kwargs)

    monkeypatch.setattr("houndd.projection.os.unlink", unlink_with_leaf_swap)

    with pytest.raises(UnsafeStoreError):
        store.projection.delete()
    assert not (outside / "index.sqlite").exists()


def test_hsp20_projection_refuses_preexisting_leaf_symlink(tmp_path) -> None:
    root = tmp_path / "store"
    root.mkdir(mode=0o700)
    outside = tmp_path / "outside.sqlite"
    root.joinpath("index.sqlite").symlink_to(outside)

    with pytest.raises(UnsafeStoreError):
        HounddStore(root)


def test_hsp20_projection_rows_are_read_only_and_projection_fds_are_flat(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = HounddStore(tmp_path / "store")
    _populate(store, count=1)
    before = _tree_snapshot(store.root)
    index_before = store.projection.path.stat()
    baseline = _fd_count()
    for _ in range(20):
        assert store.projection.rows()
    index_after = store.projection.path.stat()
    assert _tree_snapshot(store.root) == before
    assert (index_after.st_mtime_ns, index_after.st_ctime_ns, index_after.st_size) == (
        index_before.st_mtime_ns,
        index_before.st_ctime_ns,
        index_before.st_size,
    )
    assert _fd_count() == baseline

    def failing_connect(*_args, **_kwargs):
        raise sqlite3.OperationalError("injected sqlite open failure")

    monkeypatch.setattr("houndd.projection.sqlite3.connect", failing_connect)
    failure_baseline = _fd_count()
    for _ in range(10):
        with pytest.raises(ProjectionError):
            store.projection.rows()
    assert _fd_count() == failure_baseline


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


@pytest.mark.parametrize("replacement_kind", ["symlink", "directory"])
@pytest.mark.parametrize(
    ("operation", "expected_error"),
    [
        ("record_read", UnsafeStoreError),
        ("record_write", UnsafeStoreError),
        ("record_list", UnsafeStoreError),
        ("blob_write", UnsafeStoreError),
        ("journal_entries", UnsafeStoreError),
        ("journal_append", UnsafeStoreError),
        ("transaction_begin", TransactionError),
        ("transaction_commit", TransactionError),
        ("projection_rows", UnsafeStoreError),
        ("projection_rebuild", UnsafeStoreError),
    ],
)
def test_hsp20_root_swap_fails_closed_for_all_public_store_operations(
    tmp_path, replacement_kind: str, operation: str, expected_error: type[BaseException]
) -> None:
    store = HounddStore(tmp_path / "store")
    response = store.begin(_request(0), principal="peer:0", capability="capture").commit(
        record={"schema_version": "houndd.capture.v1", "value": "x"}, blob=b"x"
    )
    pending = store.begin(_request(1), principal="peer:1", capability="capture")
    store.rebuild_index()
    entry = store.journal.entries()[0]
    record_id = response["record_ids"][0]
    backup, replacement = _swap_root(store.root, replacement_kind)
    backup_snapshot = _tree_snapshot(backup)
    replacement_snapshot = _tree_snapshot(replacement)

    with pytest.raises(expected_error):
        if operation == "record_read":
            store.records.read(record_id)
        elif operation == "record_write":
            store.records.put_bytes("legacy-swap", b"legacy")
        elif operation == "record_list":
            store.records.record_ids()
        elif operation == "blob_write":
            store.records.blob(b"blob-swap")
        elif operation == "journal_entries":
            store.journal.entries()
        elif operation == "journal_append":
            store.journal.append(entry)
        elif operation == "transaction_begin":
            store.begin(_request(2), principal="peer:2", capability="capture")
        elif operation == "transaction_commit":
            pending.commit(record={"schema_version": "houndd.capture.v1", "value": "later"}, blob=b"later")
        elif operation == "projection_rows":
            store.projection.rows()
        elif operation == "projection_rebuild":
            store.projection.rebuild(store.journal, store.records)
        else:  # pragma: no cover - exhaustive guard
            raise AssertionError(f"unknown operation: {operation}")

    assert _tree_snapshot(backup) == backup_snapshot
    assert _tree_snapshot(replacement) == replacement_snapshot


def test_hsp20_verify_store_closes_verifier_anchors_on_success_and_failure(tmp_path) -> None:
    store = HounddStore(tmp_path / "store")
    _populate(store, count=1)

    for _ in range(3):
        assert verify_store(store.root)["valid"] is True
    baseline = _fd_count()
    for _ in range(25):
        assert verify_store(store.root)["valid"] is True
    assert _fd_count() == baseline

    store.journal.directory.chmod(0o755)
    failure_baseline = _fd_count()
    for _ in range(5):
        report = verify_store(store.root)
        assert report["valid"] is False
        assert _fd_count() == failure_baseline


@pytest.mark.parametrize(
    ("component", "operation"),
    [
        ("records", "read"),
        ("legacy", "write"),
        ("journal", "read"),
        ("transactions", "begin"),
    ],
)
def test_hsp20_swapped_parents_fail_closed_after_init(tmp_path, component: str, operation: str) -> None:
    store = HounddStore(tmp_path / "store")
    _populate(store, count=1)
    outside = tmp_path / f"{component}-outside"
    outside.mkdir()
    original = store.root / component
    backup = tmp_path / f"{component}-backup"
    original.rename(backup)
    original.symlink_to(outside, target_is_directory=True)

    if component == "records" and operation == "read":
        record_id = store.journal.entries()[0]["artifact"]["record_id"]
        with pytest.raises(StoreError):
            store.records.read(record_id)
    elif component == "legacy" and operation == "write":
        with pytest.raises(StoreError):
            store.records.put_bytes("legacy-record", b"legacy-bytes")
    elif component == "journal" and operation == "read":
        with pytest.raises(StoreError):
            store.journal.entries()
    elif component == "transactions" and operation == "begin":
        with pytest.raises(StoreError):
            store.begin(_request(99), principal="peer:99", capability="capture")
    else:  # pragma: no cover
        raise AssertionError("unexpected swap case")

    assert not any(outside.iterdir())


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
        clean.projection.rows()
    assert stat.S_IMODE(clean.projection.path.stat().st_mode) == 0o644
    assert clean.verify()["valid"] is False
    assert stat.S_IMODE(clean.projection.path.stat().st_mode) == 0o644
    with pytest.raises(UnsafeStoreError):
        HounddStore(clean.root)


def test_hsp20_verify_missing_store_is_invalid_without_creating_root(tmp_path) -> None:
    missing = tmp_path / "missing"
    report = verify_store(missing)
    assert report["valid"] is False
    assert not missing.exists()


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
