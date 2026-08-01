"""HSP-20: independent verification, disposable SQLite, tamper, orphan, and permission evidence."""

from __future__ import annotations

import os
import sqlite3
import json
import stat
import shutil
from pathlib import Path

import pytest

from tests.slice3a_evidence_capture import capture as _capture_evidence, descriptor_inventory as _fd_inventory, inventory as _capture_inventory

from houndd import (
    HounddStore,
    Journal,
    Projection,
    ProjectionError,
    RecordStore,
    StoreError,
    TransactionCoordinator,
    TransactionError,
    UnsafeStoreError,
    canonical_bytes,
    make_journal_envelope,
    verify_store,
)
from houndd._safety import AnchoredRoot


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


def _swap_root_back(root: Path, outside: Path, *, unlink=os.unlink) -> None:
    """Momentarily replace ``root`` with a symlink, then restore its inode."""

    backup = root.with_name(f"{root.name}.swap-back")
    root.rename(backup)
    root.symlink_to(outside, target_is_directory=True)
    unlink(root)
    backup.rename(root)


def _swap_ancestor(ancestor: Path, outside: Path) -> Path:
    """Leave one supplied root-path component pointing outside its old tree."""

    detached = ancestor.with_name(f"{ancestor.name}.detached")
    ancestor.rename(detached)
    ancestor.symlink_to(outside, target_is_directory=True)
    return detached


def _journal_entry(sequence: int) -> dict[str, object]:
    return make_journal_envelope(
        sequence=sequence,
        appended_at=f"2026-07-31T00:00:{sequence:02d}Z",
        producer={"owner_id": "owner", "capability": "capture", "run_id": f"append-{sequence}"},
        artifact={
            "kind": "failure",
            "schema": "houndd.failure.v1",
            "record_id": "f" * 64,
            "hash": "e" * 64,
            "authorized_uri": "houndd://append",
        },
        lineage={"relation": "none", "record_id": "f" * 64, "lead_id": "none"},
        source={"provider": "provider", "native_id": f"append-{sequence}", "canonical_url": "none"},
        classification={"outcome": "failed", "evidence_status": "failure"},
        access="restricted",
        policy_id="policy",
        dedupe={"object_key": f"append:{sequence}", "content_sha256": "d" * 64},
        usage={},
    )


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
    if not index.exists():
        # Rebuild now intentionally has no visible leaf until the complete
        # in-memory database is ready for atomic publication.  Create an
        # attacker leaf here so the empty-projection race remains covered.
        index.write_bytes(b"attacker leaf")
        index.chmod(0o600)
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


@pytest.mark.parametrize("operation", ["rows", "verify", "delete", "rebuild"])
def test_hsp20_projection_swap_back_uses_held_root_and_never_writes_outside(
    tmp_path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    store = HounddStore(tmp_path / "store")
    _populate(store, count=1)

    if operation in {"rows", "verify"}:
        real_connect = sqlite3.connect
        swapped = False

        def connect_with_swap_back(*args, **kwargs):
            nonlocal swapped
            if not swapped:
                _swap_root_back(store.root, outside)
                swapped = True
            return real_connect(*args, **kwargs)

        monkeypatch.setattr("houndd.projection.sqlite3.connect", connect_with_swap_back)
        if operation == "rows":
            assert store.projection.rows()
        else:
            assert store.verify()["valid"] is True
        assert swapped
    elif operation == "delete":
        real_unlink = os.unlink
        swapped = False

        def unlink_with_swap_back(*args, **kwargs):
            nonlocal swapped
            if not swapped:
                _swap_root_back(store.root, outside)
                swapped = True
            return real_unlink(*args, **kwargs)

        monkeypatch.setattr("houndd.projection.os.unlink", unlink_with_swap_back)
        store.projection.delete()
        assert swapped
    else:
        real_replace = os.replace
        swapped = False

        def replace_with_swap_back(*args, **kwargs):
            nonlocal swapped
            if not swapped:
                _swap_root_back(store.root, outside)
                swapped = True
            return real_replace(*args, **kwargs)

        monkeypatch.setattr("houndd.projection.os.replace", replace_with_swap_back)
        assert store.rebuild_index()["valid"] is True
        assert swapped

    assert not any(outside.iterdir())


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


@pytest.mark.parametrize("component", ["root", "parent", "intermediate", "grandparent"])
@pytest.mark.parametrize("entry_point", ["houndd", "records", "journal", "transactions", "projection"])
def test_hsp20_preexisting_symlink_in_any_supplied_root_component_has_no_effects(
    tmp_path, component: str, entry_point: str
) -> None:
    root = tmp_path / "supplied" / "grandparent" / "intermediate" / "parent" / "store"
    ancestors = {
        "root": root,
        "parent": root.parent,
        "intermediate": root.parents[1],
        "grandparent": root.parents[2],
    }
    unsafe = ancestors[component]
    unsafe.parent.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    unsafe.symlink_to(outside / unsafe.name, target_is_directory=True)
    before = _tree_snapshot(outside)

    with pytest.raises(StoreError):
        if entry_point == "houndd":
            HounddStore(root)
        elif entry_point == "records":
            RecordStore(root)
        elif entry_point == "journal":
            Journal(root)
        elif entry_point == "transactions":
            TransactionCoordinator(root)
        else:
            # A dangling root symlink is unsafe, not the normal optional
            # missing-projection case.
            Projection(root)

    assert _tree_snapshot(outside) == before


@pytest.mark.parametrize("supplied", ["", "safe/../missing", "safe/./missing"])
def test_hsp20_projection_rejects_unsafe_missing_root_spelling_but_allows_normal_absence(tmp_path, supplied: str) -> None:
    (tmp_path / "safe").mkdir()
    root = supplied if not supplied else f"{tmp_path}/{supplied}"

    with pytest.raises(UnsafeStoreError):
        Projection(root)

    assert Projection(tmp_path / "normally-missing").rows() == []


def test_hsp20_rejected_root_construction_keeps_ancestor_fds_flat(tmp_path) -> None:
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o755)
    baseline = _fd_count()

    for _ in range(100):
        with pytest.raises(UnsafeStoreError):
            AnchoredRoot(unsafe, error_type=UnsafeStoreError)

    assert _fd_count() == baseline


@pytest.mark.parametrize("operation", ["read", "append"])
def test_hsp20_anchored_leaf_validation_failures_are_fd_flat_and_nonmutating(
    tmp_path: Path,
    operation: str,
) -> None:
    if not Path("/proc/self/fd").exists():
        pytest.skip("requires procfs descriptor inventory")
    root = tmp_path / "store"
    root.mkdir(mode=0o700)
    leaf = root / f"unsafe-{operation}.bin"
    leaf.write_bytes(b"durable truth")
    leaf.chmod(0o644)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    outside_sentinel = outside / "sentinel"
    outside_sentinel.write_bytes(b"outside remains untouched")
    anchor = AnchoredRoot(root, error_type=UnsafeStoreError)

    def fail_validation() -> None:
        if operation == "read":
            anchor.read_bytes(leaf.name)
        else:
            anchor.append_bytes(leaf.name, data=b"must not append")

    try:
        with pytest.raises(UnsafeStoreError, match="has group/world permissions") as warmup:
            fail_validation()
        assert type(warmup.value) is UnsafeStoreError
        baseline = _fd_count()
        before = (
            leaf.read_bytes(),
            leaf.stat().st_ino,
            stat.S_IMODE(leaf.stat().st_mode),
            _tree_snapshot(root),
            _tree_snapshot(outside),
            outside_sentinel.read_bytes(),
        )
        fd_baseline = _fd_inventory()
        state_baseline = _capture_inventory(root)

        for _ in range(64):
            with pytest.raises(UnsafeStoreError, match="has group/world permissions") as caught:
                fail_validation()
            assert type(caught.value) is UnsafeStoreError

        assert _fd_count() == baseline
        assert (
            leaf.read_bytes(),
            leaf.stat().st_ino,
            stat.S_IMODE(leaf.stat().st_mode),
            _tree_snapshot(root),
            _tree_snapshot(outside),
            outside_sentinel.read_bytes(),
        ) == before

        leaf.chmod(0o600)
        success_baseline = _fd_count()
        if operation == "read":
            assert anchor.read_bytes(leaf.name) == b"durable truth"
        else:
            anchor.append_bytes(leaf.name, data=b" appended")
            assert leaf.read_bytes() == b"durable truth appended"
        assert _fd_count() == success_baseline
        assert _tree_snapshot(outside) == before[4]
        assert outside_sentinel.read_bytes() == before[5]
        _capture_evidence("fd_failure", {"path": f"anchored_{operation}", "baseline": fd_baseline, "after": _fd_inventory(), "baseline_count": baseline, "after_count": _fd_count(), "retry_count": 64, "fd_delta": _fd_count() - baseline, "before_state": state_baseline, "after_state": _capture_inventory(root), "outside_before": before[4], "outside_after": _tree_snapshot(outside)})
    finally:
        anchor.close()


@pytest.mark.parametrize("ancestor_name", ["parent", "intermediate", "grandparent"])
@pytest.mark.parametrize(
    "operation",
    [
        "record_read",
        "record_write",
        "record_list",
        "blob_write",
        "journal_read",
        "journal_append",
        "transaction_begin",
        "transaction_commit",
        "projection_rows",
        "projection_verify",
        "projection_delete",
        "projection_rebuild",
    ],
)
def test_hsp20_lasting_ancestry_replacement_refuses_before_public_operation_effects(
    tmp_path, monkeypatch: pytest.MonkeyPatch, ancestor_name: str, operation: str
) -> None:
    root = tmp_path / "supplied" / "grandparent" / "intermediate" / "parent" / "store"
    root.parent.mkdir(parents=True)
    store = HounddStore(root)
    _populate(store, count=1)
    record_id = store.journal.entries()[0]["artifact"]["record_id"]
    pending = (
        store.begin(_request(50), principal="peer:50", capability="capture") if operation == "transaction_commit" else None
    )
    ancestors = {
        "parent": store.root.parent,
        "intermediate": store.root.parents[1],
        "grandparent": store.root.parents[2],
    }
    outside = tmp_path / f"outside-{ancestor_name}-{operation}"
    outside.mkdir()
    detached_before = _tree_snapshot(ancestors[ancestor_name])
    detached: Path | None = None
    swapped = False

    def swap_once() -> None:
        nonlocal detached, swapped
        if not swapped:
            detached = _swap_ancestor(ancestors[ancestor_name], outside)
            swapped = True

    if operation == "projection_verify":
        original_walk = AnchoredRoot._walk

        def walk_then_swap(anchor, *, create):
            links = original_walk(anchor, create=create)
            if anchor.path == store.root and not create:
                swap_once()
            return links

        monkeypatch.setattr(AnchoredRoot, "_walk", walk_then_swap)
        report = store.verify()
        assert report["valid"] is False
    else:
        anchor = {
            "record_read": store.records.anchor,
            "record_write": store.records.anchor,
            "record_list": store.records.anchor,
            "blob_write": store.records.blobs.anchor,
            "journal_read": store.journal.anchor,
            "journal_append": store.journal.anchor,
            "transaction_begin": store.transactions.anchor,
            "transaction_commit": store.transactions.anchor,
            "projection_rows": store.projection.anchor,
            "projection_delete": store.projection.anchor,
            "projection_rebuild": store.projection.anchor,
        }[operation]
        assert anchor is not None
        original_walk = anchor._walk

        def walk_then_swap(*, create):
            links = original_walk(create=create)
            if not create:
                swap_once()
            return links

        monkeypatch.setattr(anchor, "_walk", walk_then_swap)
        expected = TransactionError if operation.startswith("transaction_") else UnsafeStoreError
        with pytest.raises(expected):
            if operation == "record_read":
                store.records.read(record_id)
            elif operation == "record_write":
                store.records.put_bytes("lasting-write", b"lasting-write")
            elif operation == "record_list":
                store.records.record_ids()
            elif operation == "blob_write":
                store.records.blob(b"lasting-blob")
            elif operation == "journal_read":
                store.journal.entries()
            elif operation == "journal_append":
                store.journal.append(_journal_entry(1))
            elif operation == "transaction_begin":
                store.begin(_request(51), principal="peer:51", capability="capture")
            elif operation == "transaction_commit":
                assert pending is not None
                pending.commit(record={"schema_version": "houndd.capture.v1", "value": "lasting"}, blob=b"lasting")
            elif operation == "projection_rows":
                store.projection.rows()
            elif operation == "projection_delete":
                store.projection.delete()
            else:
                store.rebuild_index()

    assert swapped
    assert detached is not None
    assert _tree_snapshot(outside) == []
    assert _tree_snapshot(detached) == detached_before


def test_hsp20_unrelated_parent_sibling_churn_does_not_poison_initialized_store(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "sibling-parent" / "store"
    root.parent.mkdir()
    store = HounddStore(root)
    _populate(store, count=1)
    record_id = store.journal.entries()[0]["artifact"]["record_id"]
    sibling = store.root.parent / "unrelated-sibling"
    original_walk = store.records.anchor._walk
    churn_during_read = False

    def walk_with_sibling_churn(*, create):
        links = original_walk(create=create)
        if churn_during_read:
            sibling.mkdir()
            sibling.rmdir()
        return links

    monkeypatch.setattr(store.records.anchor, "_walk", walk_with_sibling_churn)
    baseline = _fd_count()
    for _ in range(100):
        sibling.mkdir()
        sibling.rmdir()
        churn_during_read = True
        assert store.records.read(record_id)
        churn_during_read = False
        sibling.mkdir()
        sibling.rmdir()
        assert store.journal.entries()
        assert store.projection.rows()
    assert _fd_count() == baseline


def test_hsp20_canonical_store_bytes_never_include_the_absolute_filesystem_path(tmp_path) -> None:
    root = tmp_path / "absolute-path" / "store"
    root.parent.mkdir()
    store = HounddStore(root)
    response = store.begin(_request(1), principal="peer:1", capability="capture").commit(
        record={"schema_version": "houndd.capture.v1", "value": "portable"}, blob=b"portable"
    )
    record_id = response["record_ids"][0]
    absolute = os.fspath(tmp_path).encode()

    assert absolute not in store.records.read(record_id)
    assert absolute not in store.journal.events_path.read_bytes()
    assert absolute not in canonical_bytes(response)


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
    fd_baseline = _fd_inventory()
    state_baseline = _capture_inventory(store.root)
    for _ in range(5):
        report = verify_store(store.root)
        assert report["valid"] is False
        assert _fd_count() == failure_baseline
    _capture_evidence("fd_failure", {"path": "public_verified_snapshot", "baseline": fd_baseline, "after": _fd_inventory(), "baseline_count": failure_baseline, "after_count": _fd_count(), "retry_count": 5, "fd_delta": _fd_count() - failure_baseline, "before_state": state_baseline, "after_state": _capture_inventory(store.root), "result": "invalid"})


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
    record_id = store.journal.entries()[0]["artifact"]["record_id"]
    outside = tmp_path / f"{component}-outside"
    outside.mkdir()
    original = store.root / component
    backup = tmp_path / f"{component}-backup"
    original.rename(backup)
    original.symlink_to(outside, target_is_directory=True)

    if component == "records" and operation == "read":
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


def test_hsp20_rebuild_mid_temp_write_preserves_prior_projection_bytes_and_rows(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = HounddStore(tmp_path / "store")
    _populate(store, count=2)
    before_bytes = store.projection.path.read_bytes()
    before_rows = store.projection.rows()

    def partial_write_then_fail(descriptor: int, data: bytes) -> None:
        assert os.write(descriptor, data[:32]) == 32
        raise OSError("injected partial temp write")

    monkeypatch.setattr(store.projection, "_write_descriptor", partial_write_then_fail)

    with pytest.raises(OSError, match="partial temp write"):
        store.rebuild_index()

    assert store.projection.path.read_bytes() == before_bytes
    assert store.projection.rows() == before_rows
    assert not list(store.root.glob(".index.sqlite.tmp.*"))


@pytest.mark.parametrize("failure_point", ["temp_write", "temp_fsync", "replace"])
def test_hsp20_rebuild_pre_replace_failures_leave_prior_projection_intact(
    tmp_path, monkeypatch: pytest.MonkeyPatch, failure_point: str
) -> None:
    store = HounddStore(tmp_path / "store")
    _populate(store, count=1)
    before_bytes = store.projection.path.read_bytes()
    before_rows = store.projection.rows()

    if failure_point == "temp_write":
        monkeypatch.setattr(store.projection, "_write_descriptor", lambda *_args: (_ for _ in ()).throw(OSError("temp write failed")))
    elif failure_point == "temp_fsync":
        monkeypatch.setattr("houndd.projection.os.fsync", lambda _fd: (_ for _ in ()).throw(OSError("temp fsync failed")))
    else:
        monkeypatch.setattr("houndd.projection.os.replace", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("replace failed")))

    with pytest.raises(OSError):
        store.rebuild_index()

    assert store.projection.path.read_bytes() == before_bytes
    assert store.projection.rows() == before_rows
    assert not list(store.root.glob(".index.sqlite.tmp.*"))


def test_hsp20_successful_rebuild_publishes_private_bytes_and_syncs_directory(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = HounddStore(tmp_path / "store")
    _populate(store, count=1)
    synced: list[int] = []
    real_fsync = os.fsync

    def recording_fsync(descriptor: int) -> None:
        synced.append(descriptor)
        real_fsync(descriptor)

    monkeypatch.setattr("houndd.projection.os.fsync", recording_fsync)
    report = store.rebuild_index()

    assert report["valid"] is True
    assert store.projection.rows()
    assert stat.S_IMODE(store.projection.path.stat().st_mode) == 0o600
    assert len(synced) >= 2  # private temp, then anchored root directory


def test_hsp20_rebuild_reclaims_private_stale_projection_temps(tmp_path) -> None:
    store = HounddStore(tmp_path / "store")
    _populate(store, count=1)
    stale = store.root / ".index.sqlite.tmp.stale"
    stale.write_bytes(b"incomplete projection")
    stale.chmod(0o600)

    assert store.rebuild_index()["valid"] is True
    assert not stale.exists()
    assert len(store.projection.rows()) == 1


def test_hsp20_rebuild_refuses_unsafe_stale_projection_temp_without_outside_write(tmp_path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    store = HounddStore(tmp_path / "store")
    _populate(store, count=1)
    stale = store.root / ".index.sqlite.tmp.unsafe"
    stale.symlink_to(outside / "index.sqlite")

    with pytest.raises(UnsafeStoreError):
        store.rebuild_index()

    assert stale.is_symlink()
    assert not any(outside.iterdir())


def test_hsp20_rebuild_preserves_stale_temp_replaced_during_reclamation(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = HounddStore(tmp_path / "store")
    _populate(store, count=1)
    stale = store.root / ".index.sqlite.tmp.stale"
    stale.write_bytes(b"original")
    stale.chmod(0o600)
    original_visible = store.projection._visible_stat
    replaced = False

    def visible_then_replace(anchor, name):
        nonlocal replaced
        visible = original_visible(anchor, name)
        if name == stale.name and not replaced:
            stale.unlink()
            stale.write_bytes(b"replacement")
            stale.chmod(0o600)
            replaced = True
        return visible

    monkeypatch.setattr(store.projection, "_visible_stat", visible_then_replace)
    with pytest.raises(UnsafeStoreError):
        store.rebuild_index()
    assert stale.read_bytes() == b"replacement"


@pytest.mark.parametrize("operation", ["rows", "verify"])
def test_hsp20_post_lstat_leaf_swap_is_rejected(tmp_path, monkeypatch: pytest.MonkeyPatch, operation: str) -> None:
    store = HounddStore(tmp_path / "store")
    _populate(store, count=1)
    original_visible = type(store.projection)._visible_index_stat
    swapped = False

    def visible_then_swap(projection, anchor):
        nonlocal swapped
        visible = original_visible(projection, anchor)
        if not swapped:
            _swap_index(store.root, "different-file")
            swapped = True
        return visible

    monkeypatch.setattr(type(store.projection), "_visible_index_stat", visible_then_swap)
    if operation == "rows":
        with pytest.raises(UnsafeStoreError):
            store.projection.rows()
    else:
        report = store.verify()
        assert report["valid"] is False
        assert report["failures"]


def test_hsp20_post_lstat_swap_back_is_rejected_by_directory_generation(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = HounddStore(tmp_path / "store")
    _populate(store, count=1)
    original_visible = type(store.projection)._visible_index_stat
    swapped = False

    def visible_then_swap_back(projection, anchor):
        nonlocal swapped
        visible = original_visible(projection, anchor)
        if not swapped:
            _swap_index(store.root, "different-file", swap_back=True)
            swapped = True
        return visible

    monkeypatch.setattr(type(store.projection), "_visible_index_stat", visible_then_swap_back)
    with pytest.raises(UnsafeStoreError):
        store.projection.rows()


@pytest.mark.parametrize("operation", ["rows", "delete", "rebuild"])
def test_hsp20_initialized_projection_fails_closed_when_root_is_renamed_away(tmp_path, operation: str) -> None:
    store = HounddStore(tmp_path / "store")
    _populate(store, count=1)
    store.root.rename(tmp_path / "moved-store")

    with pytest.raises(UnsafeStoreError):
        if operation == "rows":
            store.projection.rows()
        elif operation == "delete":
            store.projection.delete()
        else:
            store.projection.rebuild(store.journal, store.records)


def test_hsp20_delete_rejects_replacement_created_during_final_absence_check(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = HounddStore(tmp_path / "store")
    _populate(store, count=1)
    original_visible = store.projection._visible_index_stat
    replaced = False

    def absent_then_replace(anchor):
        nonlocal replaced
        try:
            return original_visible(anchor)
        except FileNotFoundError:
            if not replaced:
                store.projection.path.write_bytes(b"replacement")
                store.projection.path.chmod(0o600)
                replaced = True
            raise

    monkeypatch.setattr(store.projection, "_visible_index_stat", absent_then_replace)
    with pytest.raises(UnsafeStoreError):
        store.projection.delete()
    assert store.projection.path.read_bytes() == b"replacement"


def test_hsp20_clean_delete_syncs_and_leaves_an_absent_projection(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = HounddStore(tmp_path / "store")
    _populate(store, count=1)
    synced: list[int] = []
    real_fsync = os.fsync

    def recording_fsync(descriptor: int) -> None:
        synced.append(descriptor)
        real_fsync(descriptor)

    monkeypatch.setattr("houndd.projection.os.fsync", recording_fsync)
    store.projection.delete()

    assert not store.projection.path.exists()
    assert store.projection.rows() == []
    assert synced
