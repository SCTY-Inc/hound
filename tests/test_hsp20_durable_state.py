"""HSP-20: non-repairing journal snapshots and durable service identity."""

from __future__ import annotations

import base64
from contextlib import contextmanager
import errno
import hashlib
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from houndd.contracts import canonical_bytes, canonical_hash, make_journal_envelope
from houndd.journal import Journal, JournalError, PersistedJournalSnapshot
from houndd.query_engine import QuerySnapshotError
from houndd.service_identity import (
    ServiceIdentity,
    ServiceIdentityConflict,
    ServiceIdentityError,
    ServiceIdentityLocked,
)
import houndd.service_identity as identity_module
from houndd.snapshot import build_journal_query_snapshot


_NONCANONICAL_SEQUENCE_SCALARS = (
    pytest.param(False, 0, id="false"),
    pytest.param(True, 1, id="true"),
    pytest.param(0.0, 0, id="zero-float"),
    pytest.param(1.0, 1, id="one-float"),
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
    assert snapshot.event_rows == tuple(row + b"\n" for row in journal.events_path.read_bytes().split(b"\n")[:-1])
    assert snapshot.chain_rows == tuple(row + b"\n" for row in journal.chain_path.read_bytes().split(b"\n")[:-1])
    assert snapshot.head_bytes == journal.head_path.read_bytes()
    assert _manifest(root) == before

    empty_root = tmp_path / "empty"
    empty = Journal(empty_root)
    assert not empty.head_path.exists()
    empty_before = _manifest(empty_root)
    assert empty.verified_snapshot() == PersistedJournalSnapshot((), (), None)
    assert not empty.head_path.exists()
    assert _manifest(empty_root) == empty_before

    sentinel_root = tmp_path / "empty-sentinel"
    sentinel = Journal(sentinel_root)
    empty_head = canonical_bytes({"sequence": -1, "chain_sha256": "0" * 64, "entry_id": ""})
    sentinel.head_path.write_bytes(empty_head)
    sentinel.head_path.chmod(0o600)
    sentinel_before = _manifest(sentinel_root)
    persisted = sentinel.verified_snapshot()
    assert persisted == PersistedJournalSnapshot((), (), empty_head)
    assert build_journal_query_snapshot(persisted).events == ()
    assert _manifest(sentinel_root) == sentinel_before


def test_verified_snapshot_reads_triplet_once_under_one_lock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "store"
    journal = Journal(root)
    for sequence in range(3):
        journal.append(_event(sequence))
    before = _manifest(root)
    lock_entries = 0
    lock_active = False
    reads: list[tuple[str, ...]] = []
    real_lock = journal._lock
    real_read = journal.anchor.read_bytes

    @contextmanager
    def observed_lock():
        nonlocal lock_entries, lock_active
        lock_entries += 1
        with real_lock():
            lock_active = True
            try:
                yield
            finally:
                lock_active = False

    def observed_read(*parts: str) -> bytes:
        assert lock_active
        reads.append(parts)
        return real_read(*parts)

    monkeypatch.setattr(journal, "_lock", observed_lock)
    monkeypatch.setattr(journal.anchor, "read_bytes", observed_read)
    monkeypatch.setattr(journal, "reconcile", lambda: (_ for _ in ()).throw(AssertionError("snapshot repaired")))
    snapshot = journal.verified_snapshot()

    assert lock_entries == 1
    assert reads == [
        ("journal", "events.jsonl"),
        ("journal", "chain.jsonl"),
        ("journal", "head.json"),
    ]
    assert len(snapshot.event_rows) == len(snapshot.chain_rows) == 3
    assert _manifest(root) == before


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


@pytest.mark.parametrize(
    "case",
    [
        "partial_event",
        "noncanonical_event",
        "crlf_event",
        "invalid_envelope",
        "missing_chain",
        "extra_chain",
        "crlf_chain",
        "noncanonical_chain",
        "wrong_event_hash",
        "wrong_previous_hash",
        "wrong_chain_hash",
        "forged_chain_and_head",
        "missing_head",
        "stale_head",
        "noncanonical_head",
        "wrong_head",
        "unsafe_mode",
    ],
)
def test_verified_snapshot_tampering_fails_without_mutation(tmp_path: Path, case: str) -> None:
    root = tmp_path / case
    journal = Journal(root)
    journal.append(_event(0))
    if case == "partial_event":
        journal.events_path.write_bytes(journal.events_path.read_bytes().rstrip(b"\n"))
    elif case == "noncanonical_event":
        row = json.loads(journal.events_path.read_bytes())
        journal.events_path.write_bytes(json.dumps(row, indent=2).encode("utf-8") + b"\n")
    elif case == "crlf_event":
        journal.events_path.write_bytes(journal.events_path.read_bytes().replace(b"\n", b"\r\n"))
    elif case == "invalid_envelope":
        row = json.loads(journal.events_path.read_bytes())
        row["access"] = "unknown"
        journal.events_path.write_bytes(canonical_bytes(row) + b"\n")
    elif case == "missing_chain":
        journal.chain_path.write_bytes(b"")
    elif case == "extra_chain":
        journal.chain_path.write_bytes(journal.chain_path.read_bytes() * 2)
    elif case == "crlf_chain":
        journal.chain_path.write_bytes(journal.chain_path.read_bytes().replace(b"\n", b"\r\n"))
    elif case == "noncanonical_chain":
        row = json.loads(journal.chain_path.read_bytes())
        journal.chain_path.write_bytes(json.dumps(row, indent=2).encode("utf-8") + b"\n")
    elif case in {"wrong_event_hash", "wrong_previous_hash", "wrong_chain_hash"}:
        row = json.loads(journal.chain_path.read_bytes())
        field = {
            "wrong_event_hash": "event_sha256",
            "wrong_previous_hash": "previous_chain_sha256",
            "wrong_chain_hash": "chain_sha256",
        }[case]
        row[field] = "d" * 64
        journal.chain_path.write_bytes(canonical_bytes(row) + b"\n")
    elif case == "forged_chain_and_head":
        row = json.loads(journal.chain_path.read_bytes())
        body = {key: row[key] for key in ("sequence", "entry_id", "event_sha256", "previous_chain_sha256")}
        body["event_sha256"] = "f" * 64
        row = {**body, "chain_sha256": canonical_hash(body)}
        journal.chain_path.write_bytes(canonical_bytes(row) + b"\n")
        journal.head_path.write_bytes(
            canonical_bytes({"sequence": 0, "entry_id": row["entry_id"], "chain_sha256": row["chain_sha256"]})
        )
    elif case == "missing_head":
        journal.head_path.unlink()
    elif case == "stale_head":
        journal.head_path.write_bytes(
            canonical_bytes({"sequence": -1, "chain_sha256": "0" * 64, "entry_id": ""})
        )
    elif case == "noncanonical_head":
        head = json.loads(journal.head_path.read_bytes())
        journal.head_path.write_bytes(json.dumps(head, indent=2).encode("utf-8"))
    elif case == "wrong_head":
        head = json.loads(journal.head_path.read_bytes())
        head["chain_sha256"] = "e" * 64
        journal.head_path.write_bytes(canonical_bytes(head))
    elif case == "unsafe_mode":
        journal.chain_path.chmod(0o644)
    before = _manifest(root)

    with pytest.raises(JournalError):
        journal.verified_snapshot()

    assert _manifest(root) == before


@pytest.mark.parametrize("scalar,sequence", _NONCANONICAL_SEQUENCE_SCALARS)
@pytest.mark.parametrize("target", ["chain", "current_head"])
@pytest.mark.parametrize("operation", ["verified_snapshot", "reconcile", "append"])
def test_journal_operations_reject_noncanonical_sequence_scalars_without_changing_bytes(
    tmp_path: Path,
    scalar: object,
    sequence: int,
    target: str,
    operation: str,
) -> None:
    root = tmp_path / "store"
    journal = Journal(root)
    for index in range(sequence + 1):
        journal.append(_event(index))
    if target == "chain":
        rows = journal.chain_path.read_bytes().splitlines(keepends=True)
        value = json.loads(rows[sequence])
        value["sequence"] = scalar
        rows[sequence] = canonical_bytes(value) + b"\n"
        journal.chain_path.write_bytes(b"".join(rows))
    else:
        value = json.loads(journal.head_path.read_bytes())
        value["sequence"] = scalar
        journal.head_path.write_bytes(canonical_bytes(value))
    before = _manifest(root)

    with pytest.raises(JournalError):
        if operation == "verified_snapshot":
            journal.verified_snapshot()
        elif operation == "reconcile":
            journal.reconcile()
        else:
            journal.append(_event(sequence + 1))

    assert _manifest(root) == before


@pytest.mark.parametrize("scalar,sequence", _NONCANONICAL_SEQUENCE_SCALARS)
@pytest.mark.parametrize("operation", ["reconcile", "append"])
def test_recovery_rejects_noncanonical_older_prefix_heads_without_changing_bytes(
    tmp_path: Path,
    scalar: object,
    sequence: int,
    operation: str,
) -> None:
    root = tmp_path / "store"
    journal = Journal(root)
    for index in range(sequence + 2):
        journal.append(_event(index))
    event = json.loads(journal.events_path.read_bytes().splitlines()[sequence])
    chain = json.loads(journal.chain_path.read_bytes().splitlines()[sequence])
    journal.head_path.write_bytes(
        canonical_bytes(
            {
                "sequence": scalar,
                "entry_id": event["entry_id"],
                "chain_sha256": chain["chain_sha256"],
            }
        )
    )
    before = _manifest(root)

    with pytest.raises(JournalError):
        if operation == "reconcile":
            journal.reconcile()
        else:
            journal.append(_event(sequence + 2))

    assert _manifest(root) == before


@pytest.mark.parametrize("scalar,sequence", _NONCANONICAL_SEQUENCE_SCALARS)
@pytest.mark.parametrize("target", ["chain", "head"])
def test_query_snapshot_builder_rejects_noncanonical_sequence_scalars_without_changing_bytes(
    tmp_path: Path,
    scalar: object,
    sequence: int,
    target: str,
) -> None:
    root = tmp_path / "store"
    journal = Journal(root)
    for index in range(sequence + 1):
        journal.append(_event(index))
    persisted = journal.verified_snapshot()
    chain_rows = list(persisted.chain_rows)
    head_bytes = persisted.head_bytes
    if target == "chain":
        value = json.loads(chain_rows[sequence])
        value["sequence"] = scalar
        chain_rows[sequence] = canonical_bytes(value) + b"\n"
    else:
        assert head_bytes is not None
        value = json.loads(head_bytes)
        value["sequence"] = scalar
        head_bytes = canonical_bytes(value)
    malformed = PersistedJournalSnapshot(persisted.event_rows, tuple(chain_rows), head_bytes)
    before = _manifest(root)

    with pytest.raises(QuerySnapshotError):
        build_journal_query_snapshot(malformed)

    assert _manifest(root) == before


@pytest.mark.parametrize(
    "case",
    ["tampered_event", "divergent_middle_chain", "partial_event", "noncanonical_chain"],
)
def test_integrity_corruption_is_not_recovery(tmp_path: Path, case: str) -> None:
    root = tmp_path / case
    journal = Journal(root)
    for sequence in range(3):
        journal.append(_event(sequence))
    if case == "tampered_event":
        rows = journal.events_path.read_bytes().splitlines(keepends=True)
        event = json.loads(rows[1])
        event["access"] = "restricted"
        rows[1] = canonical_bytes(event) + b"\n"
        journal.events_path.write_bytes(b"".join(rows))
    elif case == "divergent_middle_chain":
        rows = journal.chain_path.read_bytes().splitlines(keepends=True)
        chain = json.loads(rows[1])
        chain["chain_sha256"] = "c" * 64
        rows[1] = canonical_bytes(chain) + b"\n"
        journal.chain_path.write_bytes(b"".join(rows))
    elif case == "partial_event":
        journal.events_path.write_bytes(journal.events_path.read_bytes().rstrip(b"\n"))
    else:
        rows = journal.chain_path.read_bytes().splitlines(keepends=True)
        chain = json.loads(rows[1])
        rows[1] = json.dumps(chain, indent=2).encode("utf-8") + b"\n"
        journal.chain_path.write_bytes(b"".join(rows))
    damaged = _manifest(root)

    with pytest.raises(JournalError):
        journal.verified_snapshot()
    assert _manifest(root) == damaged
    with pytest.raises(JournalError):
        journal.reconcile()
    assert _manifest(root) == damaged


@pytest.mark.parametrize("operation", ["reconcile", "append"])
@pytest.mark.parametrize("head_case", ["out_of_range", "random", "mismatched_prefix"])
def test_recovery_rejects_divergent_canonical_heads_without_changing_bytes(
    tmp_path: Path,
    operation: str,
    head_case: str,
) -> None:
    root = tmp_path / f"{operation}-{head_case}"
    journal = Journal(root)
    journal.append(_event(0))
    journal.append(_event(1))
    head = json.loads(journal.head_path.read_bytes())
    first_chain = json.loads(journal.chain_path.read_bytes().splitlines()[0])
    first_event = json.loads(journal.events_path.read_bytes().splitlines()[0])
    if head_case == "out_of_range":
        head["sequence"] = 99
    elif head_case == "random":
        head = {"sequence": 0, "entry_id": "f" * 64, "chain_sha256": "e" * 64}
    else:
        head = {
            "sequence": first_event["sequence"],
            "entry_id": first_event["entry_id"],
            "chain_sha256": json.loads(journal.chain_path.read_bytes().splitlines()[1])["chain_sha256"],
        }
        assert head["chain_sha256"] != first_chain["chain_sha256"]
    journal.head_path.write_bytes(canonical_bytes(head))
    before = _manifest(root)

    with pytest.raises(JournalError):
        if operation == "reconcile":
            journal.reconcile()
        else:
            journal.append(_event(2))

    assert _manifest(root) == before


def test_recovery_accepts_only_an_exact_persisted_chain_prefix_head(tmp_path: Path) -> None:
    root = tmp_path / "store"
    journal = Journal(root)
    journal.append(_event(0))
    prefix_head = journal.head_path.read_bytes()
    journal.append(_event(1))
    expected = journal.head_path.read_bytes()
    journal.head_path.write_bytes(prefix_head)

    journal.reconcile()

    assert journal.head_path.read_bytes() == expected
    assert len(journal.verified_snapshot().event_rows) == 2


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


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires POSIX fork semantics")
@pytest.mark.filterwarnings(
    r"ignore:This process .* is multi-threaded, use of fork\(\) may lead to deadlocks in the child\.:DeprecationWarning"
)
def test_forked_child_cannot_use_identity_or_unlock_parent_lifetime_lock(tmp_path: Path) -> None:
    root = tmp_path / "store"
    identity = ServiceIdentity(root, create=True)
    release_mutex = threading.Event()
    mutex_held = threading.Event()

    def hold_mutex() -> None:
        with identity._mutex:
            mutex_held.set()
            assert release_mutex.wait(10)

    holder = threading.Thread(target=hold_mutex)
    holder.start()
    assert mutex_held.wait(5)
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:  # pragma: no cover - assertions are reported over the pipe
        os.close(read_fd)
        outcomes: list[str] = []
        try:
            def timed_out(_signum, _frame):
                raise RuntimeError("inherited mutex blocked")

            signal.signal(signal.SIGALRM, timed_out)
            operations = (
                lambda: identity.state,
                lambda: identity.lease().__enter__(),
                identity.rotate_cursor_key,
                identity.roll_generation,
            )
            for operation in operations:
                signal.alarm(1)
                try:
                    operation()
                except ServiceIdentityError:
                    outcomes.append("rejected")
                except RuntimeError:
                    outcomes.append("blocked")
                else:
                    outcomes.append("accepted")
                finally:
                    signal.alarm(0)
            signal.alarm(1)
            try:
                identity.close()
            except RuntimeError:
                outcomes.append("close_blocked")
            else:
                outcomes.append("closed")
            finally:
                signal.alarm(0)
            os.write(write_fd, json.dumps(outcomes).encode("utf-8"))
        finally:
            os.close(write_fd)
            os._exit(0)

    os.close(write_fd)
    try:
        child_outcomes = json.loads(os.read(read_fd, 4096).decode("utf-8"))
        _, status = os.waitpid(child, 0)
        assert os.waitstatus_to_exitcode(status) == 0
        assert child_outcomes == ["rejected"] * 4 + ["closed"]
        with pytest.raises(ServiceIdentityLocked):
            ServiceIdentity(root)
        release_mutex.set()
        holder.join(timeout=5)
        assert not holder.is_alive()
        assert identity.state.active_kid in identity.state.keyring.keys
    finally:
        os.close(read_fd)
        release_mutex.set()
        holder.join(timeout=5)
        identity.close()

    reopened = ServiceIdentity(root)
    reopened.close()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires POSIX fork semantics")
@pytest.mark.filterwarnings(
    r"ignore:This process .* is multi-threaded, use of fork\(\) may lead to deadlocks in the child\.:DeprecationWarning"
)
def test_forked_child_can_open_its_own_identity_only_after_parent_owner_closes(tmp_path: Path) -> None:
    root = tmp_path / "store"
    owner = ServiceIdentity(root, create=True)
    parent_read, child_write = os.pipe()
    child_read, parent_write = os.pipe()
    child = os.fork()
    if child == 0:  # pragma: no cover - child outcome is asserted over a pipe
        os.close(parent_read)
        os.close(parent_write)
        try:
            owner.close()
            try:
                ServiceIdentity(root)
            except ServiceIdentityLocked:
                os.write(child_write, b"locked\n")
            else:
                os.write(child_write, b"unexpected-open\n")
                os._exit(2)
            if os.read(child_read, 1) != b"x":
                os._exit(3)
            child_owner = ServiceIdentity(root)
            child_owner.rotate_cursor_key()
            child_owner.close()
            os.write(child_write, b"opened\n")
        finally:
            os.close(child_read)
            os.close(child_write)
        os._exit(0)

    os.close(child_read)
    os.close(child_write)
    try:
        assert os.read(parent_read, 64) == b"locked\n"
        with pytest.raises(ServiceIdentityLocked):
            ServiceIdentity(root)
        assert owner.state.active_kid in owner.state.keyring.keys
        owner.close()
        os.write(parent_write, b"x")
        assert os.read(parent_read, 64) == b"opened\n"
        _, status = os.waitpid(child, 0)
        assert os.waitstatus_to_exitcode(status) == 0
    finally:
        owner.close()
        os.close(parent_read)
        os.close(parent_write)
        try:
            os.waitpid(child, os.WNOHANG)
        except ChildProcessError:
            pass

    reopened = ServiceIdentity(root)
    assert len(reopened.state.keyring.keys) == 2
    reopened.close()


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


def _leave_identity_transaction(
    root: Path,
    fault_point: str,
) -> tuple[Path, dict[str, object], bytes]:
    initial = ServiceIdentity(root, create=True)
    initial.close()
    canonical = (root / "service" / "identity.json").read_bytes()

    def fault(point: str) -> None:
        if point == fault_point:
            raise _InjectedIdentityCrash(point)

    crashy = ServiceIdentity(root, fault_hook=fault)
    with pytest.raises(_InjectedIdentityCrash):
        crashy.rotate_cursor_key()
    crashy.close()
    service = root / "service"
    marker_path = next(service.glob(".identity.txn.*.json"))
    marker = json.loads(marker_path.read_bytes())
    assert type(marker) is dict and type(marker["roles"]) is dict
    return service, marker, canonical


def test_service_identity_new_bytes_originate_in_an_unnamed_fsynced_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not hasattr(os, "O_TMPFILE"):
        pytest.skip("requires Linux O_TMPFILE")
    observed_unnamed_opens = 0
    real_open = identity_module.os.open

    def observed_open(path, flags, *args, **kwargs):
        nonlocal observed_unnamed_opens
        if flags & os.O_TMPFILE == os.O_TMPFILE:
            observed_unnamed_opens += 1
            assert os.fspath(path) == "."
            assert not flags & os.O_EXCL
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(identity_module.os, "open", observed_open)
    identity = ServiceIdentity(tmp_path / "store", create=True)
    assert identity.state.active_kid in identity.state.keyring.keys
    identity.close()
    assert observed_unnamed_opens == 1


@pytest.mark.parametrize("empty_path_errno", [errno.EPERM, errno.ENOENT])
def test_service_identity_exact_fd_procfs_fallback_uses_only_held_relative_dirfds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    empty_path_errno: int,
) -> None:
    real_linkat = identity_module._linkat
    calls: list[tuple[int, str, int, str, int]] = []

    def forced_fallback(
        source_dir_fd: int,
        source: str,
        destination_dir_fd: int,
        destination: str,
        flags: int,
    ) -> None:
        calls.append((source_dir_fd, source, destination_dir_fd, destination, flags))
        assert "/" not in source
        assert "/" not in destination
        if flags == identity_module._AT_EMPTY_PATH:
            raise OSError(empty_path_errno, os.strerror(empty_path_errno), destination)
        assert flags == identity_module._AT_SYMLINK_FOLLOW
        assert source_dir_fd != identity_module._AT_FDCWD
        assert stat.S_ISDIR(os.fstat(source_dir_fd).st_mode)
        followed = os.stat(source, dir_fd=source_dir_fd, follow_symlinks=True)
        assert identity_module._same_file(followed, os.fstat(int(source)))
        real_linkat(source_dir_fd, source, destination_dir_fd, destination, flags)

    monkeypatch.setattr(identity_module, "_linkat", forced_fallback)
    identity = ServiceIdentity(tmp_path / "store", create=True)
    identity.close()

    assert any(call[-1] == identity_module._AT_EMPTY_PATH for call in calls)
    assert any(call[-1] == identity_module._AT_SYMLINK_FOLLOW for call in calls)
    fallback_destinations = {
        call[3] for call in calls if call[-1] == identity_module._AT_SYMLINK_FOLLOW
    }
    assert "identity.json" in fallback_destinations
    assert sum(name.endswith(".new") for name in fallback_destinations) == 1
    assert not list((tmp_path / "store" / "service").glob(".identity.txn.*"))


def test_service_identity_masked_procfs_fails_without_named_temp_or_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_linkat = identity_module._linkat

    def no_empty_path(*args, **kwargs):
        if args[-1] == identity_module._AT_EMPTY_PATH:
            raise OSError(errno.EPERM, os.strerror(errno.EPERM))
        return real_linkat(*args, **kwargs)

    def masked_procfs() -> int:
        raise OSError(errno.ENOENT, os.strerror(errno.ENOENT), "/proc/self/fd")

    monkeypatch.setattr(identity_module, "_linkat", no_empty_path)
    monkeypatch.setattr(identity_module, "_open_proc_self_fd", masked_procfs)
    root = tmp_path / "store"
    with pytest.raises(ServiceIdentityError, match="exact-FD identity linking is unavailable"):
        ServiceIdentity(root, create=True)

    assert not (root / "service" / "identity.json").exists()
    assert not list((root / "service").glob(".identity.json.tmp.*"))


def test_service_identity_procfs_fallback_without_symlink_follow_cannot_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_linkat = identity_module._linkat
    omitted_follow = False

    def unsafe_flags(
        source_dir_fd: int,
        source: str,
        destination_dir_fd: int,
        destination: str,
        flags: int,
    ) -> None:
        nonlocal omitted_follow
        if flags == identity_module._AT_EMPTY_PATH:
            raise OSError(errno.EPERM, os.strerror(errno.EPERM), destination)
        omitted_follow = True
        real_linkat(source_dir_fd, source, destination_dir_fd, destination, 0)

    monkeypatch.setattr(identity_module, "_linkat", unsafe_flags)
    root = tmp_path / "store"
    with pytest.raises(ServiceIdentityError):
        ServiceIdentity(root, create=True)
    assert omitted_follow
    assert not (root / "service" / "identity.json").exists()


@pytest.mark.parametrize("reuse_number", [False, True])
def test_service_identity_procfs_fallback_rejects_closed_or_reused_source_fd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reuse_number: bool,
) -> None:
    real_linkat = identity_module._linkat
    injected = False

    def close_source(
        source_dir_fd: int,
        source: str,
        destination_dir_fd: int,
        destination: str,
        flags: int,
    ) -> None:
        nonlocal injected
        if flags == identity_module._AT_EMPTY_PATH and not injected:
            injected = True
            os.close(source_dir_fd)
            if reuse_number:
                replacement = os.open("/dev/null", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
                if replacement != source_dir_fd:
                    os.dup2(replacement, source_dir_fd)
                    os.close(replacement)
            raise OSError(errno.EPERM, os.strerror(errno.EPERM), destination)
        real_linkat(source_dir_fd, source, destination_dir_fd, destination, flags)

    monkeypatch.setattr(identity_module, "_linkat", close_source)
    root = tmp_path / "store"
    with pytest.raises(ServiceIdentityError):
        ServiceIdentity(root, create=True)
    assert injected
    assert not (root / "service" / "identity.json").exists()
    assert not list((root / "service").glob(".identity.json.tmp.*"))


def test_service_identity_pre_link_witness_collision_is_preserved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "store"
    hostile = b"preexisting witness must survive"
    real_linkat = identity_module._linkat
    installed: Path | None = None

    def collide(
        source_dir_fd: int,
        source: str,
        destination_dir_fd: int,
        destination: str,
        flags: int,
    ) -> None:
        nonlocal installed
        if destination.endswith(".new") and installed is None:
            installed = root / "service" / destination
            installed.write_bytes(hostile)
            installed.chmod(0o600)
        real_linkat(source_dir_fd, source, destination_dir_fd, destination, flags)

    monkeypatch.setattr(identity_module, "_linkat", collide)
    with pytest.raises(ServiceIdentityConflict, match="destination already exists"):
        ServiceIdentity(root, create=True)
    assert installed is not None and installed.read_bytes() == hostile
    assert not (root / "service" / "identity.json").exists()


@pytest.mark.parametrize("link_errno", [errno.EXDEV, errno.EMLINK, errno.EPERM])
def test_service_identity_hard_link_primitive_failures_are_unavailable_without_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    link_errno: int,
) -> None:
    def fail_link(
        source_dir_fd: int,
        source: str,
        destination_dir_fd: int,
        destination: str,
        flags: int,
    ) -> None:
        raise OSError(link_errno, os.strerror(link_errno), source, destination)

    monkeypatch.setattr(identity_module, "_linkat", fail_link)
    root = tmp_path / "store"
    with pytest.raises(ServiceIdentityError, match="linking is unavailable"):
        ServiceIdentity(root, create=True)
    assert not (root / "service" / "identity.json").exists()
    assert not list((root / "service").glob(".identity.json.tmp.*"))


@pytest.mark.parametrize("rename_errno", [errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP])
def test_service_identity_exchange_primitive_failures_preserve_old_truth_and_poison(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    rename_errno: int,
) -> None:
    root = tmp_path / "store"
    identity = ServiceIdentity(root, create=True)
    canonical = root / "service" / "identity.json"
    old = canonical.read_bytes()

    def unavailable(*args, **kwargs) -> None:
        raise OSError(rename_errno, os.strerror(rename_errno))

    monkeypatch.setattr(identity_module, "_renameat2", unavailable)
    with pytest.raises(ServiceIdentityError, match="path operations are unavailable"):
        identity.rotate_cursor_key()
    with pytest.raises(ServiceIdentityError, match="must be reopened"):
        _ = identity.state
    assert canonical.read_bytes() == old
    assert list((root / "service").glob(".identity.txn.*"))
    identity.close()


@pytest.mark.parametrize("boundary", ["file_fsync", "directory_fsync"])
def test_service_identity_real_fsync_failures_publish_nothing_and_recover(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    root = tmp_path / "store"
    real_fsync = identity_module.os.fsync
    injected = False

    def fail_once(descriptor: int) -> None:
        nonlocal injected
        info = os.fstat(descriptor)
        matches = (
            boundary == "file_fsync" and stat.S_ISREG(info.st_mode) and info.st_nlink == 0
        ) or (boundary == "directory_fsync" and stat.S_ISDIR(info.st_mode))
        if matches and not injected:
            injected = True
            raise OSError(errno.EIO, os.strerror(errno.EIO))
        real_fsync(descriptor)

    monkeypatch.setattr(identity_module.os, "fsync", fail_once)
    with pytest.raises(ServiceIdentityError):
        ServiceIdentity(root, create=True)
    assert injected
    assert not (root / "service" / "identity.json").exists()
    assert not list((root / "service").glob(".identity.json.tmp.*"))

    monkeypatch.setattr(identity_module.os, "fsync", real_fsync)
    recovered = ServiceIdentity(root, create=True)
    assert recovered.state.active_kid in recovered.state.keyring.keys
    recovered.close()
    assert not list((root / "service").glob(".identity.txn.*"))


def test_service_identity_safely_rejects_unlinkable_otmpfile_excl(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_open = identity_module.os.open
    procfs_reached = False

    def open_with_excl(path, flags, *args, **kwargs):
        if flags & os.O_TMPFILE == os.O_TMPFILE:
            flags |= os.O_EXCL
        return real_open(path, flags, *args, **kwargs)

    def forbidden_procfs() -> int:
        nonlocal procfs_reached
        procfs_reached = True
        return real_open(
            "/proc/self/fd",
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0),
        )

    monkeypatch.setattr(identity_module.os, "open", open_with_excl)
    monkeypatch.setattr(identity_module, "_open_proc_self_fd", forbidden_procfs)
    root = tmp_path / "store"
    with pytest.raises(ServiceIdentityError, match="O_EXCL"):
        ServiceIdentity(root, create=True)
    assert procfs_reached
    assert not (root / "service" / "identity.json").exists()
    retained = list((root / "service").glob(".identity.txn.*"))
    assert len(retained) == 1 and retained[0].name.endswith(".json")


def test_service_identity_links_each_witness_from_its_held_fd_with_exact_link_increments(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_link = identity_module._link_identity_fd
    links: list[tuple[int, str, int, int]] = []

    def observed_link(source_fd: int, destination: str, **kwargs) -> None:
        before = os.fstat(source_fd).st_nlink
        real_link(source_fd, destination, **kwargs)
        links.append((source_fd, destination, before, os.fstat(source_fd).st_nlink))

    monkeypatch.setattr(identity_module, "_link_identity_fd", observed_link)
    root = tmp_path / "store"
    identity = ServiceIdentity(root, create=True)
    create_links = list(links)
    links.clear()
    identity.rotate_cursor_key()
    replace_links = list(links)
    identity.close()

    assert [item[1] for item in create_links] == [
        next(name for _, name, _, _ in create_links if name.endswith(".new")),
        "identity.json",
    ]
    assert len({item[0] for item in create_links}) == 1
    assert [(item[2], item[3]) for item in create_links] == [(0, 1), (1, 2)]
    assert [item[1].rsplit(".", 1)[-1] for item in replace_links] == ["new", "old", "swap"]
    new_link, old_link, swap_link = replace_links
    assert new_link[0] == swap_link[0] != old_link[0]
    assert (new_link[2], new_link[3]) == (0, 1)
    assert (swap_link[2], swap_link[3]) == (1, 2)
    assert (old_link[2], old_link[3]) == (1, 2)


def test_service_identity_post_link_destination_replacement_is_detected_and_preserved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    donor_root = tmp_path / "donor"
    donor = ServiceIdentity(donor_root, create=True)
    donor.close()
    hostile = (donor_root / "service" / "identity.json").read_bytes()
    root = tmp_path / "store"
    identity_path = root / "service" / "identity.json"
    displaced = root / "service" / "identity.linked-but-displaced"
    real_linkat = identity_module._linkat
    linked_inode: int | None = None

    def replace_after_link(
        source_dir_fd: int,
        source: str,
        destination_dir_fd: int,
        destination: str,
        flags: int,
    ) -> None:
        nonlocal linked_inode
        real_linkat(source_dir_fd, source, destination_dir_fd, destination, flags)
        if destination == "identity.json" and linked_inode is None:
            linked_inode = identity_path.stat().st_ino
            identity_path.rename(displaced)
            identity_path.write_bytes(hostile)
            identity_path.chmod(0o600)

    monkeypatch.setattr(identity_module, "_linkat", replace_after_link)
    with pytest.raises(ServiceIdentityError):
        ServiceIdentity(root, create=True, random_bytes=lambda size: b"N" * size)

    assert linked_inode is not None
    assert identity_path.read_bytes() == hostile
    assert displaced.stat().st_ino == linked_inode
    new_witness = next((root / "service").glob(".identity.txn.*.new"))
    assert new_witness.stat().st_ino == linked_inode


def test_service_identity_recovers_marker_only_create_without_adopting_unpublished_bytes(
    tmp_path: Path,
) -> None:
    root = tmp_path / "store"

    def fault(point: str) -> None:
        if point == "after_identity_marker_fsync":
            raise _InjectedIdentityCrash(point)

    with pytest.raises(_InjectedIdentityCrash):
        ServiceIdentity(root, create=True, random_bytes=lambda size: b"M" * size, fault_hook=fault)
    assert not (root / "service" / "identity.json").exists()
    assert list((root / "service").glob(".identity.txn.*.json"))

    recovered = ServiceIdentity(root, create=True, random_bytes=lambda size: b"R" * size)
    assert (root / "service" / "identity.json").read_bytes() != canonical_bytes(
        {
            "schema_version": "houndd.service-identity.v1",
            "generation": "4d" * 32,
            "active_kid": f"k-{'4d' * 12}",
            "keys": {
                f"k-{'4d' * 12}": base64.urlsafe_b64encode(b"M" * 32).rstrip(b"=").decode("ascii")
            },
        }
    )
    recovered.close()
    assert not list((root / "service").glob(".identity.txn.*"))


def test_service_identity_create_collision_preserves_installed_canonical_inode(
    tmp_path: Path,
) -> None:
    donor_root = tmp_path / "donor"
    donor = ServiceIdentity(donor_root, create=True)
    donor.close()
    replacement = (donor_root / "service" / "identity.json").read_bytes()
    root = tmp_path / "store"
    identity_path = root / "service" / "identity.json"

    def install(point: str) -> None:
        if point == "before_identity_publication":
            identity_path.write_bytes(replacement)
            identity_path.chmod(0o600)

    with pytest.raises(ServiceIdentityError):
        ServiceIdentity(root, create=True, random_bytes=lambda size: b"N" * size, fault_hook=install)
    assert identity_path.read_bytes() == replacement
    replacement_inode = identity_path.stat().st_ino
    damaged = _manifest(root)

    with pytest.raises(ServiceIdentityError):
        ServiceIdentity(root)
    assert identity_path.stat().st_ino == replacement_inode
    assert identity_path.read_bytes() == replacement
    assert _manifest(root) == damaged


_IDENTITY_FAULT_POINTS = (
    "before_identity_temp_write",
    "after_identity_temp_write",
    "after_identity_temp_fsync",
    "after_identity_rename",
    "after_identity_directory_fsync",
)


_PROCESS_DEATH_COMMON_POINTS = (
    "before_identity_temp_write",
    "mid_identity_temp_write",
    "after_identity_temp_write",
    "after_identity_temp_fsync",
    "after_identity_marker_fsync",
    "after_identity_new_witness_link",
    "after_identity_prepared_directory_fsync",
    "before_identity_publication",
    "after_identity_rename",
    "after_identity_directory_fsync",
    "after_identity_quarantine_move",
    "after_identity_quarantine_fsync",
    "after_identity_quarantine_unlink",
    "after_identity_marker_cleanup",
)

_PROCESS_DEATH_CASES = tuple(
    (operation, point)
    for operation in ("create", "rotate", "retire", "roll")
    for point in _PROCESS_DEATH_COMMON_POINTS
) + tuple(
    (operation, point)
    for operation in ("rotate", "retire", "roll")
    for point in ("after_identity_old_witness_link", "after_identity_swap_witness_link")
)


@pytest.mark.parametrize("operation,fault_point", _PROCESS_DEATH_CASES)
def test_service_identity_real_process_death_matrix(
    tmp_path: Path,
    operation: str,
    fault_point: str,
) -> None:
    root = tmp_path / f"{operation}-{fault_point}"
    retired_kid = "-"
    old: bytes | None = None
    if operation != "create":
        setup = ServiceIdentity(root, create=True)
        if operation == "retire":
            retired_kid = setup.state.active_kid
            setup.rotate_cursor_key()
        setup.close()
        old = (root / "service" / "identity.json").read_bytes()
    if operation == "create":
        deterministic_kid = f"k-{'5a' * 12}"
        expected = canonical_bytes(
            {
                "schema_version": "houndd.service-identity.v1",
                "generation": "5a" * 32,
                "active_kid": deterministic_kid,
                "keys": {
                    deterministic_kid: base64.urlsafe_b64encode(b"Z" * 32).rstrip(b"=").decode("ascii")
                },
            }
        )
    else:
        assert old is not None
        expected_value = json.loads(old)
        if operation == "rotate":
            deterministic_kid = f"k-{'5a' * 12}"
            expected_value["active_kid"] = deterministic_kid
            expected_value["keys"][deterministic_kid] = base64.urlsafe_b64encode(b"Z" * 32).rstrip(b"=").decode("ascii")
        elif operation == "retire":
            del expected_value["keys"][retired_kid]
        else:
            expected_value["generation"] = "5a" * 32
        expected = canonical_bytes(expected_value)
    child = r'''
import os
import sys
import houndd.service_identity as module
from houndd.service_identity import ServiceIdentity

root, operation, fault_point, retired_kid = sys.argv[1:]
real_write = module.os.write

def write(descriptor, data):
    if fault_point == "mid_identity_temp_write":
        real_write(descriptor, bytes(data)[:11])
        os._exit(77)
    return real_write(descriptor, data)

def fault(point):
    if point == fault_point:
        os._exit(77)

module.os.write = write
identity = ServiceIdentity(root, create=operation == "create", random_bytes=lambda size: b"Z" * size, fault_hook=fault)
if operation == "rotate":
    identity.rotate_cursor_key()
elif operation == "retire":
    identity.retire_cursor_key(retired_kid)
elif operation == "roll":
    identity.roll_generation()
'''
    completed = subprocess.run(
        [sys.executable, "-c", child, os.fspath(root), operation, fault_point, retired_kid],
        env={**os.environ, "PYTHONPATH": os.fspath(Path(__file__).parents[1] / "src"), "PYTHONDONTWRITEBYTECODE": "1"},
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert completed.returncode == 77
    path = root / "service" / "identity.json"
    before_rename = fault_point in {
        "before_identity_temp_write",
        "mid_identity_temp_write",
        "after_identity_temp_write",
        "after_identity_temp_fsync",
        "after_identity_marker_fsync",
        "after_identity_new_witness_link",
        "after_identity_old_witness_link",
        "after_identity_swap_witness_link",
        "after_identity_prepared_directory_fsync",
        "before_identity_publication",
    }
    if operation == "create" and before_rename:
        assert not path.exists()
        reopened = ServiceIdentity(root, create=True)
    else:
        current = path.read_bytes()
        _canonical_identity(path)
        if before_rename:
            assert current == old
        elif fault_point == "after_identity_rename":
            assert current in {old, expected}
        elif fault_point == "after_identity_directory_fsync":
            assert current == expected
        reopened = ServiceIdentity(root)
    reopened_bytes = path.read_bytes()
    assert reopened.state.active_kid in reopened.state.keyring.keys
    reopened.close()
    assert path.read_bytes() == reopened_bytes
    assert not list((root / "service").glob(".identity.txn.*"))


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


@pytest.mark.parametrize("position", ["ancestor", "root"])
def test_service_identity_rejects_symlinked_ancestor_or_root_without_outside_writes(
    tmp_path: Path,
    position: str,
) -> None:
    outside = tmp_path / f"outside-{position}"
    outside.mkdir(mode=0o700)
    marker = outside / "marker"
    marker.write_bytes(b"outside must remain unchanged")
    before = _manifest(outside)
    link = tmp_path / f"link-{position}"
    link.symlink_to(outside, target_is_directory=True)
    root = link / "store" if position == "ancestor" else link

    with pytest.raises(ServiceIdentityError):
        ServiceIdentity(root, create=True)

    assert _manifest(outside) == before
    assert link.is_symlink()


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

    if case == "temp_symlink":
        assert not (root / "service" / ".identity.json.tmp.attacker").exists()
        preserved = list((root / "service").glob(".identity.untrusted.*"))
        assert len(preserved) == 1 and preserved[0].is_symlink()
        assert os.readlink(preserved[0]) == os.fspath(outside / "temp")
    else:
        assert _manifest(root) == before
    assert not any(outside.iterdir())


def test_service_identity_partial_unnamed_write_keeps_old_truth_and_no_namespace_artifact(
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
    assert not list((root / "service").glob(".identity.*"))
    reopened = ServiceIdentity(root)
    assert reopened.state.active_kid in reopened.state.keyring.keys
    reopened.close()


def test_service_identity_destination_replacement_is_preserved_before_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "store"
    identity = ServiceIdentity(root, create=True)
    identity_path = root / "service" / "identity.json"
    original_path = root / "service" / "identity.original"
    replacement = identity_path.read_bytes()
    replacement_inode: int | None = None
    triggered = False

    def install_replacement() -> None:
        nonlocal replacement_inode, triggered
        if triggered:
            return
        triggered = True
        identity_path.rename(original_path)
        identity_path.write_bytes(replacement)
        identity_path.chmod(0o600)
        replacement_inode = identity_path.stat().st_ino

    if hasattr(identity_module, "_exchange_identity_paths"):
        real_exchange = identity_module._exchange_identity_paths

        def raced_exchange(*args, **kwargs):
            install_replacement()
            return real_exchange(*args, **kwargs)

        monkeypatch.setattr(identity_module, "_exchange_identity_paths", raced_exchange)
    else:
        real_replace = identity_module.os.replace

        def raced_replace(*args, **kwargs):
            install_replacement()
            return real_replace(*args, **kwargs)

        monkeypatch.setattr(identity_module.os, "replace", raced_replace)

    with pytest.raises(ServiceIdentityError):
        identity.rotate_cursor_key()

    assert triggered and replacement_inode is not None
    assert identity_path.exists()
    assert identity_path.stat().st_ino == original_path.stat().st_ino
    assert identity_path.read_bytes() == replacement
    assert any(
        path.is_file() and path.stat().st_ino == replacement_inode
        for path in (root / "service").iterdir()
    )
    assert original_path.exists()
    identity.close()


def test_service_identity_unknown_legacy_temp_is_preserved_and_never_adopted(tmp_path: Path) -> None:
    root = tmp_path / "store"
    initial = ServiceIdentity(root, create=True)
    initial.close()
    canonical = (root / "service" / "identity.json").read_bytes()
    stale = root / "service" / ".identity.json.tmp.legacy"
    stale.write_bytes(b"complete but unmarked bytes must never become truth")
    stale.chmod(0o600)
    stale_inode = stale.stat().st_ino
    with pytest.raises(ServiceIdentityError):
        ServiceIdentity(root)
    assert (root / "service" / "identity.json").read_bytes() == canonical
    preserved = list((root / "service").glob(".identity.untrusted.*"))
    assert len(preserved) == 1
    assert preserved[0].stat().st_ino == stale_inode
    assert preserved[0].read_bytes() == b"complete but unmarked bytes must never become truth"
    damaged = _manifest(root)
    with pytest.raises(ServiceIdentityError):
        ServiceIdentity(root)
    assert _manifest(root) == damaged


@pytest.mark.parametrize(
    "role,fault_point",
    [
        ("marker", "after_identity_marker_fsync"),
        ("new", "after_identity_new_witness_link"),
        ("old", "after_identity_old_witness_link"),
        ("swap", "after_identity_swap_witness_link"),
    ],
)
def test_service_identity_same_content_transaction_inode_replacement_is_preserved(
    tmp_path: Path,
    role: str,
    fault_point: str,
) -> None:
    root = tmp_path / role
    service, marker, canonical = _leave_identity_transaction(root, fault_point)
    roles = marker["roles"]
    assert type(roles) is dict
    target = service / roles[role]
    original = service / f"preserved-original-{role}"
    raw = target.read_bytes()
    target.rename(original)
    target.write_bytes(raw)
    target.chmod(0o600)
    replacement_inode = target.stat().st_ino
    damaged = _manifest(root)

    with pytest.raises(ServiceIdentityError):
        ServiceIdentity(root)

    assert (service / "identity.json").read_bytes() == canonical
    assert target.stat().st_ino == replacement_inode
    assert target.read_bytes() == raw
    assert original.exists() and original.read_bytes() == raw
    assert _manifest(root) == damaged


@pytest.mark.parametrize("replacement", ["different", "partial", "symlink", "directory"])
def test_service_identity_hostile_new_witness_replacement_fails_without_destructive_effects(
    tmp_path: Path,
    replacement: str,
) -> None:
    root = tmp_path / replacement
    service, marker, canonical = _leave_identity_transaction(root, "after_identity_new_witness_link")
    roles = marker["roles"]
    assert type(roles) is dict
    target = service / roles["new"]
    original = service / "preserved-original-new"
    target.rename(original)
    outside = tmp_path / f"outside-{replacement}"
    outside.mkdir(mode=0o700)
    outside_marker = outside / "marker"
    outside_marker.write_bytes(b"outside remains unchanged")
    if replacement == "different":
        target.write_bytes(b"hostile complete replacement")
        target.chmod(0o600)
    elif replacement == "partial":
        target.write_bytes(original.read_bytes()[:17])
        target.chmod(0o600)
    elif replacement == "symlink":
        target.symlink_to(outside_marker)
    else:
        target.mkdir(mode=0o700)
    before = _manifest(root)
    outside_before = _manifest(outside)

    with pytest.raises(ServiceIdentityError):
        ServiceIdentity(root)

    assert (service / "identity.json").read_bytes() == canonical
    assert original.exists()
    assert _manifest(root) == before
    assert _manifest(outside) == outside_before


def test_service_identity_missing_witness_recovers_only_as_the_earlier_crash_compatible_state(
    tmp_path: Path,
) -> None:
    root = tmp_path / "store"
    service, marker, canonical = _leave_identity_transaction(root, "after_identity_new_witness_link")
    roles = marker["roles"]
    assert type(roles) is dict
    new_witness = service / roles["new"]
    preserved = service / "preserved-disappeared-new"
    new_bytes = new_witness.read_bytes()
    new_witness.rename(preserved)

    reopened = ServiceIdentity(root)
    assert (service / "identity.json").read_bytes() == canonical
    reopened.close()

    assert preserved.read_bytes() == new_bytes
    assert not list(service.glob(".identity.txn.*"))


@pytest.mark.parametrize("timing", ["before_quarantine", "after_quarantine"])
def test_service_identity_cleanup_replacement_is_quarantined_and_never_destroyed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    timing: str,
) -> None:
    root = tmp_path / timing
    service, marker, canonical = _leave_identity_transaction(root, "after_identity_rename")
    roles = marker["roles"]
    assert type(roles) is dict
    old_name = roles["old"]
    trash_name = roles["trash_old"]
    original = service / "preserved-cleanup-original"
    hostile = b"hostile cleanup replacement must survive"
    real_rename = identity_module._rename_identity_noreplace
    injected = False

    def raced_rename(source: str, destination: str, *, dir_fd: int) -> None:
        nonlocal injected
        if source == old_name and destination == trash_name and not injected:
            injected = True
            if timing == "before_quarantine":
                (service / source).rename(original)
                (service / source).write_bytes(hostile)
                (service / source).chmod(0o600)
                real_rename(source, destination, dir_fd=dir_fd)
                return
            real_rename(source, destination, dir_fd=dir_fd)
            (service / destination).rename(original)
            (service / destination).write_bytes(hostile)
            (service / destination).chmod(0o600)
            return
        real_rename(source, destination, dir_fd=dir_fd)

    monkeypatch.setattr(identity_module, "_rename_identity_noreplace", raced_rename)
    with pytest.raises(ServiceIdentityError):
        ServiceIdentity(root)

    assert injected
    assert (service / "identity.json").read_bytes() != canonical
    assert original.exists()
    assert any(path.is_file() and path.read_bytes() == hostile for path in service.iterdir())


def test_service_identity_canonical_replacement_during_cleanup_stops_before_unlink(
    tmp_path: Path,
) -> None:
    donor_root = tmp_path / "donor"
    donor = ServiceIdentity(donor_root, create=True)
    donor.close()
    hostile = (donor_root / "service" / "identity.json").read_bytes()
    root = tmp_path / "store"
    service, marker, _ = _leave_identity_transaction(root, "after_identity_rename")
    roles = marker["roles"]
    assert type(roles) is dict
    canonical = service / "identity.json"
    preserved = service / "preserved-published-identity"
    injected = False

    def replace(point: str) -> None:
        nonlocal injected
        if point == "after_identity_quarantine_move" and not injected:
            injected = True
            canonical.rename(preserved)
            canonical.write_bytes(hostile)
            canonical.chmod(0o600)

    with pytest.raises(ServiceIdentityError):
        ServiceIdentity(root, fault_hook=replace)

    assert injected
    assert canonical.read_bytes() == hostile
    assert preserved.exists()
    assert (service / roles["trash_old"]).exists()
    assert (service / roles["new"]).exists()
    assert (service / roles["swap"]).exists()


def test_service_identity_recovery_rejects_missing_marker_multiple_txids_and_impossible_roles(
    tmp_path: Path,
) -> None:
    for case in ("missing-marker", "multiple-txids", "impossible-roles"):
        root = tmp_path / case
        service, marker, canonical = _leave_identity_transaction(root, "after_identity_swap_witness_link")
        roles = marker["roles"]
        assert type(roles) is dict
        if case == "missing-marker":
            (service / roles["marker"]).rename(service / "preserved-missing-marker")
        elif case == "multiple-txids":
            (service / f".identity.txn.{'f' * 32}.new").write_bytes(b"second transaction")
            (service / f".identity.txn.{'f' * 32}.new").chmod(0o600)
        else:
            (service / roles["new"]).rename(service / "preserved-impossible-new")
        before = _manifest(root)

        with pytest.raises(ServiceIdentityError):
            ServiceIdentity(root)

        assert (service / "identity.json").read_bytes() == canonical
        assert _manifest(root) == before


@pytest.mark.parametrize("fault_point", ["after_identity_swap_witness_link", "after_identity_rename"])
def test_service_identity_copied_inflight_transaction_is_never_relocated_as_truth(
    tmp_path: Path,
    fault_point: str,
) -> None:
    original_root = tmp_path / "original"
    _, _, canonical = _leave_identity_transaction(original_root, fault_point)
    copied_root = tmp_path / "copied"
    shutil.copytree(original_root, copied_root)
    before = _manifest(copied_root)

    with pytest.raises(ServiceIdentityError):
        ServiceIdentity(copied_root)

    assert (copied_root / "service" / "identity.json").read_bytes() in {
        canonical,
        (original_root / "service" / "identity.json").read_bytes(),
    }
    assert _manifest(copied_root) == before


@pytest.mark.parametrize("race", ["swap", "canonical_and_swap", "after_exchange"])
def test_service_identity_exchange_races_preserve_every_inode_and_restore_old_canonical(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    race: str,
) -> None:
    donor_a_root = tmp_path / "donor-a"
    donor_a = ServiceIdentity(donor_a_root, create=True)
    donor_a.close()
    hostile_a = (donor_a_root / "service" / "identity.json").read_bytes()
    donor_b_root = tmp_path / "donor-b"
    donor_b = ServiceIdentity(donor_b_root, create=True)
    donor_b.close()
    hostile_b = (donor_b_root / "service" / "identity.json").read_bytes()
    root = tmp_path / "store"
    identity = ServiceIdentity(root, create=True)
    service = root / "service"
    canonical = service / "identity.json"
    old = canonical.read_bytes()
    real_exchange = identity_module._exchange_identity_paths
    preserved: list[tuple[int, bytes]] = []
    injected = False

    def replace(path: Path, saved_name: str, replacement: bytes) -> None:
        saved = service / saved_name
        path.rename(saved)
        preserved.append((saved.stat().st_ino, saved.read_bytes()))
        path.write_bytes(replacement)
        path.chmod(0o600)
        preserved.append((path.stat().st_ino, replacement))

    def raced_exchange(source: str, destination: str, *, dir_fd: int) -> None:
        nonlocal injected
        if destination == "identity.json" and not injected:
            injected = True
            swap = service / source
            if race in {"swap", "canonical_and_swap"}:
                replace(swap, "preserved-proposed-new", hostile_a)
            if race == "canonical_and_swap":
                replace(canonical, "preserved-original-canonical", hostile_b)
            if race == "after_exchange":
                real_exchange(source, destination, dir_fd=dir_fd)
                replace(canonical, "preserved-published-new", hostile_a)
                return
        real_exchange(source, destination, dir_fd=dir_fd)

    monkeypatch.setattr(identity_module, "_exchange_identity_paths", raced_exchange)
    with pytest.raises(ServiceIdentityError):
        identity.rotate_cursor_key()
    assert injected
    assert canonical.read_bytes() == old
    current = {
        (path.stat().st_ino, path.read_bytes())
        for path in service.iterdir()
        if path.is_file()
    }
    assert set(preserved) <= current
    assert any(raw == hostile_a for _, raw in current)
    if race == "canonical_and_swap":
        assert any(raw == hostile_b for _, raw in current)
    identity.close()


def test_service_identity_malformed_post_exchange_replacement_is_preserved_and_old_truth_restored(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "store"
    identity = ServiceIdentity(root, create=True)
    service = root / "service"
    canonical = service / "identity.json"
    old = canonical.read_bytes()
    hostile = b'{"partial":'
    preserved_new = service / "preserved-published-new"
    real_exchange = identity_module._exchange_identity_paths
    injected = False

    def raced_exchange(source: str, destination: str, *, dir_fd: int) -> None:
        nonlocal injected
        real_exchange(source, destination, dir_fd=dir_fd)
        if destination == "identity.json" and not injected:
            injected = True
            canonical.rename(preserved_new)
            canonical.write_bytes(hostile)
            canonical.chmod(0o600)

    monkeypatch.setattr(identity_module, "_exchange_identity_paths", raced_exchange)
    with pytest.raises(ServiceIdentityError):
        identity.rotate_cursor_key()

    assert injected
    assert canonical.read_bytes() == old
    assert preserved_new.exists()
    assert any(
        path.is_file() and path.read_bytes() == hostile
        for path in service.iterdir()
    )
    identity.close()


def test_service_identity_transaction_auxiliaries_are_private_under_umask_zero(tmp_path: Path) -> None:
    root = tmp_path / "store"
    previous_umask = os.umask(0)
    try:
        service, marker, _ = _leave_identity_transaction(root, "after_identity_swap_witness_link")
    finally:
        os.umask(previous_umask)
    roles = marker["roles"]
    assert type(roles) is dict
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE(service.stat().st_mode) == 0o700
    for role in ("marker", "new", "old", "swap"):
        path = service / roles[role]
        assert path.is_file() and not path.is_symlink()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.parametrize("operation", ["state", "rotate"])
@pytest.mark.parametrize("component", ["ancestor", "root", "service", "lock"])
def test_service_identity_lasting_path_replacements_fail_before_read_or_write(
    tmp_path: Path,
    operation: str,
    component: str,
) -> None:
    ancestor = tmp_path / f"ancestor-{operation}"
    if component == "ancestor":
        ancestor.mkdir(mode=0o700)
        root = ancestor / "store"
    else:
        root = tmp_path / f"{component}-{operation}"
    identity = ServiceIdentity(root, create=True)
    held = tmp_path / f"held-{component}-{operation}"
    replacement_marker = b"replacement tree must remain untouched"

    if component == "ancestor":
        ancestor.rename(held)
        ancestor.mkdir(mode=0o700)
        (ancestor / "marker").write_bytes(replacement_marker)
        replacement = ancestor
    elif component == "root":
        root.rename(held)
        root.mkdir(mode=0o700)
        (root / "marker").write_bytes(replacement_marker)
        replacement = root
    elif component == "service":
        service = root / "service"
        service.rename(held)
        service.mkdir(mode=0o700)
        (service / "marker").write_bytes(replacement_marker)
        replacement = service
    else:
        lock = root / "service" / "lock"
        lock.rename(held)
        lock.write_bytes(replacement_marker)
        lock.chmod(0o600)
        replacement = root / "service"

    replacement_before = _manifest(replacement)
    held_before = _manifest(held)
    with pytest.raises(ServiceIdentityError):
        if operation == "state":
            _ = identity.state
        else:
            identity.rotate_cursor_key()
    assert _manifest(replacement) == replacement_before
    assert _manifest(held) == held_before
    assert any(path.read_bytes() == replacement_marker for path in replacement.rglob("*") if path.is_file())
    identity.close()


@pytest.mark.parametrize(
    "component",
    ["ancestor", "root", "service", "lock", "identity", "marker", "temp"],
)
def test_service_identity_live_namespace_replacements_fail_at_the_next_phase_without_further_effects(
    tmp_path: Path,
    component: str,
) -> None:
    ancestor = tmp_path / f"ancestor-{component}"
    if component == "ancestor":
        ancestor.mkdir(mode=0o700)
        root = ancestor / "store"
    else:
        root = tmp_path / f"store-{component}"
    identity = ServiceIdentity(root, create=True)
    service = root / "service"
    trigger = "after_identity_new_witness_link" if component == "temp" else "after_identity_marker_fsync"
    snapshots: list[tuple[Path, tuple[tuple[object, ...], ...]]] = []
    raced = False

    def install(point: str) -> None:
        nonlocal raced
        if point != trigger or raced:
            return
        raced = True
        if component == "ancestor":
            held = tmp_path / "held-ancestor"
            ancestor.rename(held)
            ancestor.mkdir(mode=0o700)
            (ancestor / "replacement-marker").write_bytes(b"replacement remains untouched")
            snapshots.extend(((ancestor, _manifest(ancestor)), (held, _manifest(held))))
        elif component == "root":
            held = tmp_path / "held-root"
            root.rename(held)
            root.mkdir(mode=0o700)
            (root / "replacement-marker").write_bytes(b"replacement remains untouched")
            snapshots.extend(((root, _manifest(root)), (held, _manifest(held))))
        elif component == "service":
            held = tmp_path / "held-service"
            service.rename(held)
            service.mkdir(mode=0o700)
            (service / "replacement-marker").write_bytes(b"replacement remains untouched")
            snapshots.extend(((service, _manifest(service)), (held, _manifest(held))))
        elif component == "lock":
            target = service / "lock"
            saved = service / "preserved-lock"
            target.rename(saved)
            target.write_bytes(saved.read_bytes())
            target.chmod(0o600)
            snapshots.append((service, _manifest(service)))
        elif component == "identity":
            target = service / "identity.json"
            saved = service / "preserved-identity"
            raw = target.read_bytes()
            target.rename(saved)
            target.write_bytes(raw)
            target.chmod(0o600)
            snapshots.append((service, _manifest(service)))
        elif component == "marker":
            target = next(service.glob(".identity.txn.*.json"))
            saved = service / "preserved-marker"
            raw = target.read_bytes()
            target.rename(saved)
            target.write_bytes(raw)
            target.chmod(0o600)
            snapshots.append((service, _manifest(service)))
        else:
            target = next(service.glob(".identity.txn.*.new"))
            saved = service / "preserved-new-witness"
            raw = target.read_bytes()
            target.rename(saved)
            target.write_bytes(raw)
            target.chmod(0o600)
            snapshots.append((service, _manifest(service)))

    identity._fault_hook = install
    with pytest.raises(ServiceIdentityError):
        identity.rotate_cursor_key()
    assert raced
    for path, before in snapshots:
        assert _manifest(path) == before
    identity.close()


def test_service_identity_repeated_open_close_and_lock_failures_are_fd_flat(tmp_path: Path) -> None:
    proc_fd = Path("/proc/self/fd")
    if not proc_fd.exists():
        pytest.skip("requires procfs descriptor inventory")
    root = tmp_path / "store"
    owner = ServiceIdentity(root, create=True)
    baseline = len(tuple(proc_fd.iterdir()))
    for _ in range(40):
        with pytest.raises(ServiceIdentityLocked):
            ServiceIdentity(root)
        assert owner.state.active_kid in owner.state.keyring.keys
    assert len(tuple(proc_fd.iterdir())) == baseline
    owner.close()
    baseline = len(tuple(proc_fd.iterdir()))
    for _ in range(40):
        reopened = ServiceIdentity(root)
        _ = reopened.state
        reopened.close()
    assert len(tuple(proc_fd.iterdir())) == baseline


def test_service_identity_repeated_forced_procfs_publication_is_fd_flat(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proc_fd = Path("/proc/self/fd")
    if not proc_fd.exists():
        pytest.skip("requires procfs descriptor inventory")
    real_linkat = identity_module._linkat

    def force_procfs(*args, **kwargs):
        if args[-1] == identity_module._AT_EMPTY_PATH:
            raise OSError(errno.EPERM, os.strerror(errno.EPERM))
        return real_linkat(*args, **kwargs)

    monkeypatch.setattr(identity_module, "_linkat", force_procfs)
    identity = ServiceIdentity(tmp_path / "store", create=True)
    baseline = len(tuple(proc_fd.iterdir()))
    for _ in range(20):
        identity.rotate_cursor_key()
        assert len(tuple(proc_fd.iterdir())) == baseline
    identity.close()
    assert len(tuple(proc_fd.iterdir())) == baseline - 4


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
