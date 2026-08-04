"""GOALIE B11: the commit-path index refresh is incremental and rebuild-equal.

B9 refreshed the disposable index by rebuilding it from the whole journal on
every commit, so each commit paid for every entry behind it.  These tests pin
the two claims that let a commit stop paying that: the incrementally
maintained projection is the projection a from-scratch rebuild of the same
journal produces, and one commit derives exactly the rows that commit added.

Equivalence is proven over the schema and the ordered rows of both tables,
not over the SQLite file bytes: an appended database and a rebuilt one differ
in page layout and freelist while holding identical rows, so file bytes are
not a sound equality test (a refinement of the GOALIE B11 wording).
"""

from __future__ import annotations

import base64
import hashlib
import os
from contextlib import contextmanager
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
from typing import Any, Callable, Iterator

import pytest

from houndd import HounddStore
from houndd import projection as projection_module
from houndd.access import AuthenticatedPrincipal, EventSelector, PrincipalScope, ProducerSelector
from houndd.commit import normalize_source, parse_commit_request, resolve_route
from houndd.commit_runtime import CommitRuntime
from houndd.contracts import canonical_bytes
from houndd.projection import Projection, ProjectionError
from houndd.store import BlobStore, RecordStore
from houndd.verify import verify_store


PRINCIPAL = f"linux-uid:{os.getuid()}"
CAPABILITIES = ("ingest.file", "import.record", "ingest.search", "ingest.url")
SUSPECTED = b"# Intake\n\nPatient SSN 123-45-6789 and MRN 4471."


def _state(tmp_path: Path) -> Path:
    """One empty store; the runtime is driven directly, so no service files."""

    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    HounddStore(root).close()
    return root


def _scope() -> PrincipalScope:
    tiers = frozenset({"public"})
    return PrincipalScope(
        principal=AuthenticatedPrincipal(PRINCIPAL),
        readable_tiers=tiers,
        permitted_event_selectors=tuple(
            EventSelector("write-policy", ProducerSelector("writer", capability, None), tiers) for capability in CAPABILITIES
        ),
    )


def _local_body(operation: str, key: str, data: bytes, legacy_id: str | None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "source": {
            "kind": "bytes",
            "body_base64": base64.b64encode(data).decode("ascii"),
            "sha256": hashlib.sha256(data).hexdigest(),
            "byte_length": len(data),
        },
    }
    if operation == "ingest.file":
        payload["media_type"] = "application/octet-stream"
    else:
        payload["record_id"] = legacy_id or "legacy-1"
    return {
        "schema_version": "houndd.commit-request.v1",
        "request_id": key,
        "idempotency_key": key,
        "producer": {"owner_id": "writer", "capability": operation, "run_id": "run"},
        "requested_access": "public",
        "policy_id": "write-policy",
        "operation": {"name": operation, "payload": payload},
    }


def _local(runtime: CommitRuntime, operation: str, key: str, data: bytes, legacy_id: str | None = None) -> dict[str, Any]:
    """Commit one ingest.file or import.record request."""

    path = "/v1/ingest/file" if operation == "ingest.file" else "/v1/import-record"
    route = resolve_route("POST", path, require_available=True)
    request = parse_commit_request(_local_body(operation, key, data, legacy_id), route)
    source = normalize_source(request.source.to_wire())
    return runtime.execute(request, route, principal=PRINCIPAL, access="public", source=source, scanner_clear=True, scope=_scope())


def _file(runtime: CommitRuntime, key: str, data: bytes) -> dict[str, Any]:
    return _local(runtime, "ingest.file", key, data)


def _adapter(runtime: CommitRuntime, operation: str, key: str, host: Any) -> dict[str, Any]:
    """Commit one adapter attempt through the shared 3C2 request builder."""

    from tests import test_slice3c2_adapter_commit as slice3c2

    request, route = slice3c2._request(operation, key=key, request_id=key)
    return runtime.execute_adapter(request, route, principal=PRINCIPAL, access="public", adapter_host=host, scope=_scope())


def _snapshot(root: Path) -> bytes:
    """Canonical bytes of a whole projection: its schema and both tables, ordered."""

    connection = sqlite3.connect(f"file:{root / 'index.sqlite'}?mode=ro", uri=True)
    try:
        return canonical_bytes({
            "schema": [list(row) for row in connection.execute("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name")],
            "entries": [list(row) for row in connection.execute("SELECT * FROM entries ORDER BY sequence, entry_id")],
            "blobs": [list(row) for row in connection.execute("SELECT * FROM blobs ORDER BY content_sha256")],
        })
    finally:
        connection.close()


def _rebuilt(root: Path, into: Path) -> bytes:
    """Snapshot of a from-scratch rebuild of the same journal, off to the side."""

    shutil.copytree(root, into)
    with HounddStore(into) as store:
        store.rebuild_index()
    return _snapshot(into)


def _assert_equals_rebuild(root: Path, into: Path) -> None:
    assert _snapshot(root) == _rebuilt(root, into)


def _entry_ids(root: Path) -> list[str]:
    with Projection(root) as projection:
        return [row["entry_id"] for row in projection.rows()]


def _publish_index(root: Path, data: bytes) -> None:
    """Replace the projection file the way a foreign writer would."""

    temporary = root / "index.replacement"
    temporary.write_bytes(data)
    temporary.chmod(0o600)
    os.replace(temporary, root / "index.sqlite")


def _index_bytes(root: Path) -> bytes:
    return (root / "index.sqlite").read_bytes()


@contextmanager
def _derivations() -> Iterator[list[str]]:
    """Count row derivations: the unit of projection work per journal entry."""

    derived: list[str] = []
    original = projection_module._derive_rows

    def counting(event: Any, records: Any) -> Any:
        derived.append(event["entry_id"])
        return original(event, records)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(projection_module, "_derive_rows", counting)
        yield derived


@contextmanager
def _store_reads() -> Iterator[list[str]]:
    """Count every record and blob read, whoever makes it."""

    reads: list[str] = []

    def counter(owner: type, name: str) -> Callable[..., Any]:
        original = getattr(owner, name)

        def counted(self: Any, *args: Any, **kwargs: Any) -> Any:
            reads.append(name)
            return original(self, *args, **kwargs)

        return counted

    with pytest.MonkeyPatch.context() as patch:
        for owner, name in ((RecordStore, "verify_record"), (RecordStore, "read"), (BlobStore, "get")):
            patch.setattr(owner, name, counter(owner, name))
        yield reads


@contextmanager
def _refresh_refused() -> Iterator[list[str]]:
    """Refuse both projection drivers, keeping B9's failure isolation testable."""

    attempts: list[str] = []

    def refuse(name: str) -> Callable[..., Any]:
        def refused(self: Projection, *_: Any, **__: Any) -> dict[str, Any]:
            attempts.append(name)
            raise ProjectionError(f"simulated {name} failure")

        return refused

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(Projection, "append", refuse("append"))
        patch.setattr(Projection, "rebuild", refuse("rebuild"))
        yield attempts


# ----------------------------------------------------------- equivalence


def test_b11_incremental_projection_equals_a_full_rebuild_across_the_commit_matrix(tmp_path: Path) -> None:
    """Contract: after every commit the appended index is the rebuilt index."""

    from tests import test_slice3c2_adapter_commit as slice3c2

    from houndd.adapter_host import AdapterAbstained, AdapterFailed, AdapterHost

    state = _state(tmp_path)
    scratch = tmp_path / "rebuilds"
    scratch.mkdir(mode=0o700)
    runtime = CommitRuntime(state)
    try:
        commits: tuple[tuple[str, Callable[[], Any]], ...] = (
            ("file", lambda: _file(runtime, "file-one", b"b11 file one")),
            ("import", lambda: _local(runtime, "import.record", "import-one", b"b11 legacy one", "legacy-one")),
            ("search-completed", lambda: _adapter(runtime, "ingest.search", "search-completed", slice3c2._faux("ingest.search"))),
            ("url-completed", lambda: _adapter(runtime, "ingest.url", "url-completed", slice3c2._faux("ingest.url"))),
            ("url-degraded", lambda: _adapter(runtime, "ingest.url", "url-degraded", AdapterHost({}))),
            ("search-refused", lambda: _adapter(runtime, "ingest.search", "search-refused", slice3c2._faux("ingest.search", error=AdapterAbstained("provider abstained")))),
            ("url-failed", lambda: _adapter(runtime, "ingest.url", "url-failed", slice3c2._faux("ingest.url", error=AdapterFailed("provider failed", requests=1)))),
            ("url-quarantined", lambda: _adapter(runtime, "ingest.url", "url-quarantined", slice3c2._faux("ingest.url", content=SUSPECTED))),
            ("file-replayed", lambda: _file(runtime, "file-one", b"b11 file one")),
            ("file-shared-blob", lambda: _file(runtime, "file-two", b"b11 file one")),
            ("import-shared-bytes", lambda: _local(runtime, "import.record", "import-two", b"b11 file one", "legacy-two")),
        )
        for index, (label, commit) in enumerate(commits):
            commit()
            _assert_equals_rebuild(state, scratch / f"{index:02d}-{label}")
            assert verify_store(state)["valid"] is True
        assert len(_entry_ids(state)) == len(commits) - 1  # the replay published nothing
    finally:
        runtime.close()


def test_b11_interrupted_recovery_appends_one_row_incrementally(tmp_path: Path) -> None:
    """The sixth adapter outcome reaches the index through reconcile, still O(1)."""

    from tests import test_slice3c2_adapter_commit as slice3c2

    state = _state(tmp_path)
    runtime = CommitRuntime(state)
    try:
        _file(runtime, "before-one", b"b11 before one")
        _file(runtime, "before-two", b"b11 before two")
    finally:
        runtime.close()

    def crash(reached: str) -> None:
        if reached == "after_plan":
            raise RuntimeError("simulated process death")

    crashed = CommitRuntime(state, fault_hook=crash)
    try:
        with pytest.raises(RuntimeError):
            _adapter(crashed, "ingest.url", "interrupted", slice3c2._faux("ingest.url"))
    finally:
        crashed.close()

    recovered = CommitRuntime(state)
    try:
        with _derivations() as derived:
            assert [entry["outcome"] for entry in recovered.reconcile()] == ["interrupted"]
        assert derived == [recovered.journal.entries()[-1]["entry_id"]]  # type: ignore[union-attr]
        assert [row["outcome"] for row in Projection(state).rows()] == ["completed", "completed", "interrupted"]
        _assert_equals_rebuild(state, tmp_path / "rebuild")
        assert verify_store(state)["valid"] is True
    finally:
        recovered.close()


# ------------------------------------------------------------------ cost


def test_b11_refresh_cost_does_not_grow_with_the_journal(tmp_path: Path) -> None:
    """Contract: one commit derives one row however long the journal is."""

    state = _state(tmp_path)
    runtime = CommitRuntime(state)
    try:
        per_commit: list[int] = []
        for index in range(12):
            with _derivations() as derived:
                _file(runtime, f"cost-{index}", f"b11 cost {index}".encode())
            per_commit.append(len(derived))
        assert per_commit == [1] * 12

        # The same counter measures what B9 paid: rebuilding this journal once
        # derives every row, so its per-commit cost grew with every commit.
        with _derivations() as derived, Projection(state) as projection:
            projection.rebuild(runtime.journal, runtime.records)
        assert len(derived) == 12
    finally:
        runtime.close()


def test_b11_commit_store_reads_are_flat_in_journal_length(tmp_path: Path) -> None:
    """End-to-end cost: a late commit reads no more records or blobs than an early one."""

    state = _state(tmp_path)
    runtime = CommitRuntime(state)
    try:
        for index in range(3):
            _file(runtime, f"warm-{index}", f"b11 warm {index}".encode())
        with _store_reads() as early:
            _file(runtime, "early", b"b11 early")
        for index in range(12):
            _file(runtime, f"grow-{index}", f"b11 grow {index}".encode())
        with _store_reads() as late:
            _file(runtime, "late", b"b11 late")
        assert late == early != []
        assert len(runtime.journal.entries()) == 17  # type: ignore[union-attr]
    finally:
        runtime.close()


# -------------------------------------------------------------- fallback


def _assert_repaired_and_incremental(runtime: CommitRuntime, state: Path, tmp_path: Path, key: str) -> None:
    """A fallback repairs the index and hands the next commit back to append."""

    _assert_equals_rebuild(state, tmp_path / f"{key}-rebuild")
    assert verify_store(state)["valid"] is True
    with _derivations() as derived:
        _file(runtime, key, f"b11 {key}".encode())
    assert len(derived) == 1
    _assert_equals_rebuild(state, tmp_path / f"{key}-rebuild-again")
    assert verify_store(state)["valid"] is True


def test_b11_missing_index_falls_back_to_a_full_rebuild(tmp_path: Path) -> None:
    state = _state(tmp_path)
    runtime = CommitRuntime(state)
    try:
        for index in range(3):
            _file(runtime, f"gone-{index}", f"b11 gone {index}".encode())
        Projection(state).delete()
        with _derivations() as derived:
            _file(runtime, "after-delete", b"b11 after delete")
        assert len(derived) == 4
        _assert_repaired_and_incremental(runtime, state, tmp_path, "after-delete-next")
    finally:
        runtime.close()


def test_b11_sequence_gap_falls_back_to_a_full_rebuild(tmp_path: Path) -> None:
    state = _state(tmp_path)
    runtime = CommitRuntime(state)
    try:
        # A refused refresh leaves the index one entry behind the journal, so
        # the next commit's event is two sequences past the last indexed row.
        _file(runtime, "lag-one", b"b11 lag one")
        _file(runtime, "lag-two", b"b11 lag two")
        with _refresh_refused():
            _file(runtime, "lag-three", b"b11 lag three")
        assert len(_entry_ids(state)) == 2
        with _derivations() as derived:
            _file(runtime, "lag-four", b"b11 lag four")
        assert len(derived) == 4
        _assert_repaired_and_incremental(runtime, state, tmp_path, "lag-five")
    finally:
        runtime.close()


def test_b11_foreign_schema_index_falls_back_to_a_full_rebuild(tmp_path: Path) -> None:
    """A same-shaped foreign schema is the dangerous one: it would append silently."""

    state = _state(tmp_path)
    runtime = CommitRuntime(state)
    try:
        for index in range(3):
            _file(runtime, f"foreign-{index}", f"b11 foreign {index}".encode())
        foreign = sqlite3.connect(":memory:")
        try:
            foreign.deserialize(_index_bytes(state))
            foreign.execute("ALTER TABLE entries RENAME COLUMN canonical_url TO source_url")
            foreign.commit()
            _publish_index(state, foreign.serialize())
        finally:
            foreign.close()
        with _derivations() as derived:
            _file(runtime, "after-foreign", b"b11 after foreign")
        assert len(derived) == 4
        _assert_repaired_and_incremental(runtime, state, tmp_path, "after-foreign-next")
    finally:
        runtime.close()


def test_b11_blob_drift_falls_back_to_a_full_rebuild(tmp_path: Path) -> None:
    """The blobs table is derived from entries, so drift in it is unprovable."""

    state = _state(tmp_path)
    runtime = CommitRuntime(state)
    try:
        for index in range(3):
            _file(runtime, f"drift-{index}", f"b11 drift {index}".encode())
        drifted = sqlite3.connect(":memory:")
        try:
            drifted.deserialize(_index_bytes(state))
            drifted.execute("DELETE FROM blobs")
            drifted.commit()
            _publish_index(state, drifted.serialize())
        finally:
            drifted.close()
        with _derivations() as derived:
            _file(runtime, "after-drift", b"b11 after drift")
        assert len(derived) == 4
        _assert_repaired_and_incremental(runtime, state, tmp_path, "after-drift-next")
    finally:
        runtime.close()


def test_b11_append_refuses_an_unprovable_target_without_touching_it(tmp_path: Path) -> None:
    """Every refusal above is the one seam: append raises and publishes nothing."""

    state = _state(tmp_path)
    runtime = CommitRuntime(state)
    try:
        _file(runtime, "refuse-one", b"b11 refuse one")
        before = _index_bytes(state)
        entries = runtime.journal.entries()  # type: ignore[union-attr]
        with Projection(state) as projection:
            with pytest.raises(ProjectionError):
                projection.append((), runtime.records)
            with pytest.raises(ProjectionError):
                projection.append((entries[0],), runtime.records)  # already-held sequence
        assert _index_bytes(state) == before
    finally:
        runtime.close()


# ------------------------------------------------------- failure isolation


def test_b11_refresh_refusal_never_fails_the_committed_event(tmp_path: Path) -> None:
    """B9's contract is unchanged: neither driver may break a durable commit."""

    state = _state(tmp_path)
    runtime = CommitRuntime(state)
    try:
        first = _file(runtime, "isolated-one", b"b11 isolated one")
        with _refresh_refused() as attempts:
            second = _file(runtime, "isolated-two", b"b11 isolated two")
        assert attempts == ["append", "rebuild"]
        assert second["ok"] is True
        assert [entry["entry_id"] for entry in runtime.journal.entries()] == first["entry_ids"] + second["entry_ids"]  # type: ignore[union-attr]
        assert verify_store(state, projection=False)["valid"] is True
        assert _entry_ids(state) == first["entry_ids"]

        third = _file(runtime, "isolated-three", b"b11 isolated three")
        assert _entry_ids(state) == first["entry_ids"] + second["entry_ids"] + third["entry_ids"]
        _assert_equals_rebuild(state, tmp_path / "rebuild")
        assert verify_store(state)["valid"] is True
    finally:
        runtime.close()


def test_b11_crash_between_journal_append_and_refresh_recovers(tmp_path: Path) -> None:
    """A real process death in the refresh window still recovers, with a prior journal."""

    state = _state(tmp_path)
    runtime = CommitRuntime(state)
    try:
        for index in range(2):
            _file(runtime, f"prior-{index}", f"b11 prior {index}".encode())
        prior = [entry["entry_id"] for entry in runtime.journal.entries()]  # type: ignore[union-attr]
    finally:
        runtime.close()

    script = f"""
import os, sys
sys.path.insert(0, {str(Path(__file__).parents[1] / "src")!r})
sys.path.insert(0, {str(Path(__file__).parent)!r})
from houndd.commit_runtime import CommitRuntime
from test_b11_incremental_projection import _file

runtime = CommitRuntime({str(state)!r}, fault_hook=lambda phase: os._exit(9) if phase == "after_journal" else None)
_file(runtime, "crash", b"b11 crash")
"""
    killed = subprocess.run([sys.executable, "-c", script], capture_output=True)
    assert killed.returncode == 9, killed.stderr.decode()

    # The journal already holds the event; only the disposable index lags.
    assert verify_store(state, projection=False)["valid"] is True
    assert _entry_ids(state) == prior

    recovered = CommitRuntime(state)
    try:
        with _derivations() as derived:
            assert [entry["outcome"] for entry in recovered.reconcile()] == ["completed"]
        # The lag is exactly one entry, so recovery appends rather than rebuilds.
        assert len(derived) == 1
        assert _entry_ids(state) == [entry["entry_id"] for entry in recovered.journal.entries()]  # type: ignore[union-attr]
        _assert_equals_rebuild(state, tmp_path / "rebuild")
        assert verify_store(state)["valid"] is True
    finally:
        recovered.close()
