"""HSP-20: non-repairing journal snapshots and durable service identity."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from houndd.contracts import canonical_bytes, canonical_hash, make_journal_envelope
from houndd.journal import Journal, JournalError, PersistedJournalSnapshot
from houndd.service_identity import (
    ServiceIdentity,
    ServiceIdentityConflict,
    ServiceIdentityError,
    ServiceIdentityLocked,
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _event(sequence: int, *, when: str | None = None) -> dict[str, object]:
    return make_journal_envelope(
        sequence=sequence,
        appended_at=when or f"2026-07-31T00:00:{sequence:02d}Z",
        producer={"owner_id": "owner", "capability": "capture", "run_id": f"run-{sequence}"},
        artifact={
            "kind": "capture",
            "schema": "houndd.capture.v1",
            "record_id": f"record-{sequence}",
            "hash": _digest(f"record-{sequence}"),
            "authorized_uri": f"houndd://records/{sequence}",
        },
        lineage={"relation": "none", "record_id": f"record-{sequence}", "lead_id": "none"},
        source={
            "provider": "provider",
            "native_id": f"native-{sequence}",
            "canonical_url": f"https://example.test/{sequence}",
        },
        classification={"outcome": "completed", "evidence_status": "evidence"},
        access="workspace",
        policy_id="policy",
        dedupe={"object_key": f"object-{sequence}", "content_sha256": _digest(f"content-{sequence}")},
        usage={},
    )


def _manifest(root: Path) -> tuple[tuple[object, ...], ...]:
    if not root.exists():
        return ()
    result: list[tuple[object, ...]] = []
    for path in sorted((root, *root.rglob("*")), key=lambda item: os.fspath(item.relative_to(root))):
        info = path.lstat()
        relative = "." if path == root else os.fspath(path.relative_to(root))
        kind = "symlink" if stat.S_ISLNK(info.st_mode) else "directory" if stat.S_ISDIR(info.st_mode) else "file"
        digest = hashlib.sha256(path.read_bytes()).hexdigest() if kind == "file" else None
        target = os.readlink(path) if kind == "symlink" else None
        result.append(
            (
                relative,
                kind,
                target,
                info.st_dev,
                info.st_ino,
                info.st_uid,
                info.st_gid,
                stat.S_IMODE(info.st_mode),
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
                digest,
            )
        )
    return tuple(result)


def _canonical_identity(path: Path) -> dict[str, object]:
    raw = path.read_bytes()
    value = json.loads(raw.decode("utf-8"))
    assert canonical_bytes(value) == raw
    assert set(value) == {"schema_version", "generation", "active_kid", "keys"}
    return value


def test_verified_snapshot_returns_exact_triplet_and_empty_read_creates_no_head(tmp_path: Path) -> None:
    root = tmp_path / "store"
    journal = Journal(root)
    journal.append(_event(0))
    journal.append(_event(1))
    before = _manifest(root)

    snapshot = journal.verified_snapshot()

    assert type(snapshot) is PersistedJournalSnapshot
    assert snapshot.event_rows == tuple(journal.events_path.read_bytes().splitlines(keepends=True))
    assert snapshot.chain_rows == tuple(journal.chain_path.read_bytes().splitlines(keepends=True))
    assert snapshot.head_bytes == journal.head_path.read_bytes()
    assert _manifest(root) == before

    empty_root = tmp_path / "empty"
    empty = Journal(empty_root)
    assert not empty.head_path.exists()
    empty_before = _manifest(empty_root)
    assert empty.verified_snapshot() == PersistedJournalSnapshot((), (), None)
    assert not empty.head_path.exists()
    assert _manifest(empty_root) == empty_before


def test_verified_snapshot_linearizes_against_real_append(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "store"
    reader = Journal(root)
    writer = Journal(root)
    reader.append(_event(0))
    reader.append(_event(1))
    events_read = threading.Event()
    release_snapshot = threading.Event()
    append_started = threading.Event()
    append_finished = threading.Event()
    original_read = reader.anchor.read_bytes

    def paused_read(*parts: str) -> bytes:
        value = original_read(*parts)
        if parts == ("journal", "events.jsonl"):
            events_read.set()
            assert release_snapshot.wait(5)
        return value

    monkeypatch.setattr(reader.anchor, "read_bytes", paused_read)

    def append() -> None:
        append_started.set()
        writer.append(_event(2))
        append_finished.set()

    with ThreadPoolExecutor(max_workers=2) as executor:
        snapshot_future = executor.submit(reader.verified_snapshot)
        assert events_read.wait(5)
        append_future = executor.submit(append)
        assert append_started.wait(5)
        assert not append_finished.wait(0.1)
        release_snapshot.set()
        snapshot = snapshot_future.result(timeout=5)
        append_future.result(timeout=5)

    assert len(snapshot.event_rows) == len(snapshot.chain_rows) == 2
    assert json.loads(snapshot.head_bytes)["sequence"] == 1  # type: ignore[arg-type]
    assert len(reader.verified_snapshot().event_rows) == 3


def test_verified_snapshot_is_non_repairing_and_explicit_reconcile_repairs_only_suffix(tmp_path: Path) -> None:
    root = tmp_path / "store"
    journal = Journal(root)
    journal.append(_event(0))
    journal.append(_event(1))
    pristine_chain = journal.chain_path.read_bytes()
    pristine_head = journal.head_path.read_bytes()
    journal.chain_path.write_bytes(b"".join(pristine_chain.splitlines(keepends=True)[:-1]))
    journal.head_path.unlink()
    damaged = _manifest(root)

    with pytest.raises(JournalError, match="incomplete|missing"):
        journal.verified_snapshot()
    assert _manifest(root) == damaged

    assert journal.reconcile() == {"valid": True, "sequence": 1, "entries": 2, "chain_entries": 2}
    assert journal.chain_path.read_bytes() == pristine_chain
    assert journal.head_path.read_bytes() == pristine_head
    assert len(journal.verified_snapshot().event_rows) == 2


def test_explicit_reconcile_does_not_begin_suffix_repair_before_rejecting_corrupt_head(tmp_path: Path) -> None:
    root = tmp_path / "store"
    journal = Journal(root)
    journal.append(_event(0))
    journal.append(_event(1))
    chain_rows = journal.chain_path.read_bytes().splitlines(keepends=True)
    journal.chain_path.write_bytes(chain_rows[0])
    journal.head_path.write_bytes(b"{malformed")
    before = _manifest(root)

    with pytest.raises(JournalError):
        journal.reconcile()

    assert _manifest(root) == before


@pytest.mark.parametrize("case", ["partial_event", "noncanonical_chain", "forged_chain_and_head", "wrong_head", "unsafe_mode"])
def test_verified_snapshot_tampering_fails_without_mutation(tmp_path: Path, case: str) -> None:
    root = tmp_path / case
    journal = Journal(root)
    journal.append(_event(0))
    if case == "partial_event":
        journal.events_path.write_bytes(journal.events_path.read_bytes().rstrip(b"\n"))
    elif case == "noncanonical_chain":
        row = json.loads(journal.chain_path.read_bytes())
        journal.chain_path.write_bytes(json.dumps(row, indent=2).encode("utf-8") + b"\n")
    elif case == "forged_chain_and_head":
        row = json.loads(journal.chain_path.read_bytes())
        body = {key: row[key] for key in ("sequence", "entry_id", "event_sha256", "previous_chain_sha256")}
        body["event_sha256"] = "f" * 64
        row = {**body, "chain_sha256": canonical_hash(body)}
        journal.chain_path.write_bytes(canonical_bytes(row) + b"\n")
        journal.head_path.write_bytes(
            canonical_bytes({"sequence": 0, "entry_id": row["entry_id"], "chain_sha256": row["chain_sha256"]})
        )
    elif case == "wrong_head":
        head = json.loads(journal.head_path.read_bytes())
        head["chain_sha256"] = "e" * 64
        journal.head_path.write_bytes(canonical_bytes(head))
    else:
        journal.chain_path.chmod(0o644)
    before = _manifest(root)

    with pytest.raises(JournalError):
        journal.verified_snapshot()

    assert _manifest(root) == before


def test_service_identity_is_canonical_private_persistent_and_lifetime_locked(tmp_path: Path) -> None:
    root = tmp_path / "store"
    previous_umask = os.umask(0)
    try:
        identity = ServiceIdentity(root, create=True)
    finally:
        os.umask(previous_umask)
    state = identity.state
    body = _canonical_identity(root / "service" / "identity.json")

    assert body["schema_version"] == "houndd.service-identity.v1"
    assert body["generation"] == state.generation
    assert body["active_kid"] == state.active_kid
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE((root / "service").stat().st_mode) == 0o700
    assert stat.S_IMODE((root / "service" / "lock").stat().st_mode) == 0o600
    assert stat.S_IMODE((root / "service" / "identity.json").stat().st_mode) == 0o600
    assert len(bytes.fromhex(state.generation)) == 32
    assert set(body["keys"]) == set(state.keyring.keys)  # type: ignore[arg-type]
    for encoded in body["keys"].values():  # type: ignore[union-attr]
        assert len(base64.urlsafe_b64decode(f"{encoded}=")) == 32

    with pytest.raises(ServiceIdentityLocked):
        ServiceIdentity(root)
    identity.close()

    restarted = ServiceIdentity(root)
    assert restarted.state == state
    restarted.close()


def test_service_identity_lifetime_lock_survives_process_boundary_and_releases_on_kill(tmp_path: Path) -> None:
    root = tmp_path / "store"
    child = """
import sys
from houndd.service_identity import ServiceIdentity

identity = ServiceIdentity(sys.argv[1], create=True)
print("locked", flush=True)
sys.stdin.read()
"""
    environment = {**os.environ, "PYTHONPATH": os.fspath(Path(__file__).parents[1] / "src")}
    process = subprocess.Popen(
        [sys.executable, "-c", child, os.fspath(root)],
        env=environment,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stdout is not None and process.stdout.readline().strip() == "locked"
        with pytest.raises(ServiceIdentityLocked):
            ServiceIdentity(root)
        process.kill()
        assert process.wait(timeout=5) < 0
        reopened = ServiceIdentity(root)
        reopened.close()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def test_service_identity_rotation_retirement_and_generation_roll_are_atomic(tmp_path: Path) -> None:
    root = tmp_path / "store"
    identity = ServiceIdentity(root, create=True)
    initial = identity.state
    rotated = identity.rotate_cursor_key()
    assert rotated.generation == initial.generation
    assert rotated.active_kid != initial.active_kid
    assert set(rotated.keyring.keys) == {initial.active_kid, rotated.active_kid}

    before_rejections = (root / "service" / "identity.json").read_bytes()
    with pytest.raises(ServiceIdentityConflict):
        identity.retire_cursor_key(rotated.active_kid)
    with pytest.raises(ServiceIdentityConflict):
        identity.retire_cursor_key("k-000000000000000000000000")
    assert (root / "service" / "identity.json").read_bytes() == before_rejections

    retired = identity.retire_cursor_key(initial.active_kid)
    assert set(retired.keyring.keys) == {rotated.active_kid}
    rolled = identity.roll_generation()
    assert rolled.generation != retired.generation
    assert rolled.keyring == retired.keyring
    identity.close()

    restarted = ServiceIdentity(root)
    assert restarted.state == rolled
    restarted.close()


class _InjectedIdentityCrash(RuntimeError):
    pass


_IDENTITY_FAULT_POINTS = (
    "before_identity_temp_write",
    "after_identity_temp_write",
    "after_identity_temp_fsync",
    "after_identity_rename",
    "after_identity_directory_fsync",
)


@pytest.mark.parametrize("operation", ["create", "rotate", "retire", "roll"])
@pytest.mark.parametrize("fault_point", _IDENTITY_FAULT_POINTS)
def test_service_identity_faults_leave_absent_old_or_new_complete_state(
    tmp_path: Path,
    operation: str,
    fault_point: str,
) -> None:
    root = tmp_path / f"{operation}-{fault_point}"
    old_bytes: bytes | None = None
    retired_kid: str | None = None
    if operation != "create":
        setup = ServiceIdentity(root, create=True)
        if operation == "retire":
            initial_kid = setup.state.active_kid
            setup.rotate_cursor_key()
            retired_kid = initial_kid
        setup.close()
        old_bytes = (root / "service" / "identity.json").read_bytes()

    def fault(point: str) -> None:
        if point == fault_point:
            raise _InjectedIdentityCrash(point)

    if operation == "create":
        with pytest.raises(_InjectedIdentityCrash):
            ServiceIdentity(root, create=True, random_bytes=lambda size: b"C" * size, fault_hook=fault)
    else:
        identity = ServiceIdentity(root, random_bytes=lambda size: b"R" * size, fault_hook=fault)
        with pytest.raises(_InjectedIdentityCrash):
            if operation == "rotate":
                identity.rotate_cursor_key()
            elif operation == "retire":
                assert retired_kid is not None
                identity.retire_cursor_key(retired_kid)
            else:
                identity.roll_generation()
        with pytest.raises(ServiceIdentityError):
            _ = identity.state
        identity.close()

    path = root / "service" / "identity.json"
    before_rename = fault_point in {
        "before_identity_temp_write",
        "after_identity_temp_write",
        "after_identity_temp_fsync",
    }
    if operation == "create" and before_rename:
        assert not path.exists()
        recovered = ServiceIdentity(root, create=True)
    else:
        current = path.read_bytes()
        _canonical_identity(path)
        if before_rename:
            assert current == old_bytes
        else:
            assert current != old_bytes
        recovered = ServiceIdentity(root)
    assert recovered.state.active_kid in recovered.state.keyring.keys
    recovered.close()


def test_service_identity_rejects_permissions_symlinks_and_leaf_replacement_without_repair(tmp_path: Path) -> None:
    unsafe_root = tmp_path / "unsafe"
    unsafe_root.mkdir(mode=0o755)
    with pytest.raises(ServiceIdentityError):
        ServiceIdentity(unsafe_root, create=True)
    assert stat.S_IMODE(unsafe_root.stat().st_mode) == 0o755

    outside = tmp_path / "outside"
    outside.mkdir()
    symlink_root = tmp_path / "symlink-root"
    symlink_root.mkdir(mode=0o700)
    (symlink_root / "service").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ServiceIdentityError):
        ServiceIdentity(symlink_root, create=True)
    assert not any(outside.iterdir())

    root = tmp_path / "store"
    identity = ServiceIdentity(root, create=True)
    identity_path = root / "service" / "identity.json"
    original = identity_path.read_bytes()
    held_aside = root / "service" / "identity.old"
    identity_path.rename(held_aside)
    identity_path.write_bytes(b"replacement must survive")
    identity_path.chmod(0o600)
    with pytest.raises(ServiceIdentityError):
        _ = identity.state
    assert identity_path.read_bytes() == b"replacement must survive"
    identity.close()

    identity_path.unlink()
    held_aside.rename(identity_path)
    identity_path.chmod(0o644)
    with pytest.raises(ServiceIdentityError):
        ServiceIdentity(root)
    assert identity_path.read_bytes() == original
    assert stat.S_IMODE(identity_path.stat().st_mode) == 0o644


@pytest.mark.parametrize("case", ["partial", "noncanonical", "unknown", "short_secret", "identity_symlink", "lock_symlink", "temp_symlink"])
def test_service_identity_malformed_and_symlink_matrix_fails_closed(tmp_path: Path, case: str) -> None:
    root = tmp_path / case
    identity = ServiceIdentity(root, create=True)
    identity.close()
    identity_path = root / "service" / "identity.json"
    lock_path = root / "service" / "lock"
    outside = tmp_path / f"outside-{case}"
    outside.mkdir()
    if case == "partial":
        identity_path.write_bytes(identity_path.read_bytes()[:20])
    elif case == "noncanonical":
        value = json.loads(identity_path.read_bytes())
        identity_path.write_bytes(json.dumps(value, indent=2).encode("utf-8"))
    elif case == "unknown":
        value = json.loads(identity_path.read_bytes())
        value["unknown"] = True
        identity_path.write_bytes(canonical_bytes(value))
    elif case == "short_secret":
        value = json.loads(identity_path.read_bytes())
        value["keys"][value["active_kid"]] = base64.urlsafe_b64encode(b"short").rstrip(b"=").decode("ascii")
        identity_path.write_bytes(canonical_bytes(value))
    elif case == "identity_symlink":
        identity_path.unlink()
        identity_path.symlink_to(outside / "identity.json")
    elif case == "lock_symlink":
        lock_path.unlink()
        lock_path.symlink_to(outside / "lock")
    else:
        (root / "service" / ".identity.json.tmp.attacker").symlink_to(outside / "temp")
    before = _manifest(root)

    with pytest.raises(ServiceIdentityError):
        ServiceIdentity(root)

    assert _manifest(root) == before
    assert not any(outside.iterdir())


def test_service_identity_partial_temp_write_keeps_old_truth_and_private_reclaimable_temp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "store"
    identity = ServiceIdentity(root, create=True)
    old = (root / "service" / "identity.json").read_bytes()
    real_write = os.write
    injected = False

    def partial_write(descriptor: int, data: bytes | memoryview) -> int:
        nonlocal injected
        if not injected:
            injected = True
            real_write(descriptor, bytes(data)[:11])
            raise OSError("injected partial identity write")
        return real_write(descriptor, data)

    monkeypatch.setattr("houndd.service_identity.os.write", partial_write)
    with pytest.raises(ServiceIdentityError):
        identity.rotate_cursor_key()
    identity.close()

    assert (root / "service" / "identity.json").read_bytes() == old
    temps = list((root / "service").glob(".identity.json.tmp.*"))
    assert len(temps) == 1
    assert stat.S_IMODE(temps[0].stat().st_mode) == 0o600
    reopened = ServiceIdentity(root)
    assert reopened.state.active_kid in reopened.state.keyring.keys
    assert not list((root / "service").glob(".identity.json.tmp.*"))
    reopened.close()


def test_service_identity_relocation_preserves_identity_without_absolute_paths(tmp_path: Path) -> None:
    original_root = tmp_path / "location-a"
    original = ServiceIdentity(original_root, create=True)
    expected_state = original.state
    original.close()
    identity_bytes = (original_root / "service" / "identity.json").read_bytes()
    assert os.fspath(original_root).encode("utf-8") not in identity_bytes

    relocated_root = tmp_path / "location-b"
    shutil.copytree(original_root, relocated_root)
    relocated = ServiceIdentity(relocated_root)
    assert relocated.state == expected_state
    assert (relocated_root / "service" / "identity.json").read_bytes() == identity_bytes
    relocated.close()
