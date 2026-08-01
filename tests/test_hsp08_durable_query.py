"""HSP-08: durable canonical journal queries without projection state."""

from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import stat
from pathlib import Path

import pytest

from houndd.access import AuthenticatedPrincipal, EventSelector, PrincipalScope, ProducerSelector
from houndd.contracts import make_journal_envelope
from houndd.cursor import CursorRejected
from houndd.journal import Journal, JournalError
from houndd.query_contracts import QueryContractError, QueryRequest, parse_query_filter, parse_query_request
from houndd.query_engine import EMPTY_QUERY_PAGE, QuerySnapshotError
from houndd.service_identity import ServiceIdentity
from houndd.snapshot import (
    DurableJournalQueryAdapter,
    QueryFilterNotAvailable,
    build_journal_query_snapshot,
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _event(
    sequence: int,
    *,
    when: str,
    owner: str = "owner",
    capability: str = "capture",
    run_id: str | None = None,
    provider: str = "exa",
    url: str | None = None,
    access: str = "public",
    outcome: str = "completed",
    evidence_status: str = "evidence",
    policy_id: str = "policy",
) -> dict[str, object]:
    return make_journal_envelope(
        sequence=sequence,
        appended_at=when,
        producer={"owner_id": owner, "capability": capability, "run_id": run_id or f"run-{sequence}"},
        artifact={
            "kind": "capture",
            "schema": "houndd.capture.v1",
            "record_id": f"record-{sequence}",
            "hash": _digest(f"record-{sequence}"),
            "authorized_uri": f"houndd://records/{sequence}",
        },
        lineage={"relation": "none", "record_id": f"lineage-{sequence}", "lead_id": "none"},
        source={
            "provider": provider,
            "native_id": f"native-{sequence}",
            "canonical_url": url or f"https://example.test/{sequence}",
        },
        classification={"outcome": outcome, "evidence_status": evidence_status},
        access=access,
        policy_id=policy_id,
        dedupe={"object_key": f"object-{sequence}", "content_sha256": _digest(f"content-{sequence}")},
        usage={},
    )


def _events(*, later: bool = False) -> list[dict[str, object]]:
    values = [
        _event(0, when="2026-07-31T03:00:00Z", run_id="run-a", provider="exa", access="public"),
        _event(1, when="2026-07-31T01:30:00Z", run_id="run-b", provider="firecrawl", access="workspace", outcome="partial", evidence_status="partial"),
        _event(2, when="2026-07-31T02:00:00Z", run_id="run-c", provider="exa", access="restricted"),
        _event(3, when="2026-07-31T02:00:00Z", run_id="run-d", provider="firecrawl", access="public", outcome="failed", evidence_status="failure"),
        _event(4, when="2026-07-31T04:00:00Z", run_id="run-e", provider="exa", access="workspace"),
    ]
    if later:
        values.append(
            _event(5, when="2026-07-31T00:30:00Z", run_id="run-later", provider="exa", access="restricted")
        )
    return values


def _scope(subject: str = "peer:reader") -> PrincipalScope:
    return PrincipalScope(
        AuthenticatedPrincipal(subject),
        frozenset({"public", "workspace", "restricted"}),
        (
            EventSelector(
                "policy",
                ProducerSelector(owner_id="owner", capability="capture"),
                frozenset({"public", "workspace", "restricted"}),
            ),
        ),
    )


def _store(root: Path, *, later: bool = False) -> tuple[Journal, ServiceIdentity, DurableJournalQueryAdapter, list[dict[str, object]]]:
    journal = Journal(root)
    values = _events(later=later)
    for event in values:
        journal.append(event)
    identity = ServiceIdentity(root, create=True)
    return journal, identity, DurableJournalQueryAdapter(journal, identity, nonce_source=lambda size: b"N" * size), values


def _ids(page) -> list[str]:
    return [item.event["entry_id"] for item in page.items]


def _tree_manifest(root: Path) -> tuple[tuple[object, ...], ...]:
    result: list[tuple[object, ...]] = []
    for path in sorted((root, *root.rglob("*")), key=lambda item: os.fspath(item.relative_to(root))):
        info = path.lstat()
        relative = "." if path == root else os.fspath(path.relative_to(root))
        kind = "symlink" if stat.S_ISLNK(info.st_mode) else "directory" if stat.S_ISDIR(info.st_mode) else "file"
        digest = hashlib.sha256(path.read_bytes()).hexdigest() if kind == "file" else None
        result.append(
            (
                relative,
                kind,
                os.readlink(path) if kind == "symlink" else None,
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


def test_durable_query_uses_exact_persisted_chain_and_all_canonical_filter_families(tmp_path: Path) -> None:
    journal, identity, adapter, events = _store(tmp_path / "store")
    snapshot = build_journal_query_snapshot(journal.verified_snapshot())
    assert [event["entry_id"] for event in snapshot.events] == [event["entry_id"] for event in events]
    chronological = [1, 2, 3, 0, 4]
    cases = (
        ({}, chronological),
        ({"time_range": {"from": "2026-07-31T02:00:00Z", "to": "2026-07-31T04:00:00Z"}}, [2, 3, 0]),
        ({"producer": {"owner_id": ["owner"], "capability": ["capture"], "run_id": ["run-b"]}}, [1]),
        ({"source": {"provider": ["firecrawl"]}}, [1, 3]),
        ({"source": {"canonical_url": ["https://example.test/2"]}}, [2]),
        ({"entry_id": [events[3]["entry_id"]]}, [3]),
        ({"record_id": ["record-4"]}, [4]),
        ({"object_key": ["object-0"]}, [0]),
        ({"content_sha256": [_digest("content-2")]}, [2]),
        ({"classification": {"outcome": ["completed"]}}, [2, 0, 4]),
        ({"classification": {"evidence_status": ["failure"]}}, [3]),
        ({"access": ["workspace", "restricted"]}, [1, 2, 4]),
        (
            {
                "time_range": {"from": "2026-07-31T01:30:00Z", "to": "2026-07-31T03:00:00Z"},
                "source": {"provider": ["exa", "firecrawl"]},
                "classification": {"outcome": ["completed", "failed"]},
            },
            [2, 3],
        ),
    )
    for filter_value, expected in cases:
        page = adapter.execute(QueryRequest(parse_query_filter(filter_value), limit=100), _scope())
        assert _ids(page) == [events[index]["entry_id"] for index in expected]
        assert all(item.provenance.lane is None and not item.provenance.topics and not item.provenance.entities for item in page.items)
    identity.close()
    journal.close()


@pytest.mark.parametrize(
    "filter_value",
    [
        {"lane": ["pulse"]},
        {"topic": ["care"]},
        {"entity": ["entity"]},
        {"entity": ["entity"], "lane": ["pulse"], "topic": ["care"]},
    ],
)
def test_projection_filters_fail_explicitly_before_identity_or_journal_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    filter_value: dict[str, object],
) -> None:
    journal, identity, adapter, _ = _store(tmp_path / "store")

    def forbidden(*_args, **_kwargs):
        raise AssertionError("unsupported filters reached durable evaluation")

    monkeypatch.setattr(journal, "verified_snapshot", forbidden)
    monkeypatch.setattr(identity, "lease", forbidden)
    with pytest.raises(QueryFilterNotAvailable) as raised:
        adapter.execute(QueryRequest(parse_query_filter(filter_value)), _scope())
    assert raised.value.code == "filter_not_available"
    assert raised.value.filters == tuple(sorted(filter_value))
    assert "cursor" not in vars(raised.value)
    identity.close()
    journal.close()


def test_none_scope_is_auth_first_and_dereferences_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    journal, identity, adapter, _ = _store(tmp_path / "store")

    def forbidden(*_args, **_kwargs):
        raise AssertionError("unresolved scope reached query evaluation")

    monkeypatch.setattr(journal, "verified_snapshot", forbidden)
    monkeypatch.setattr(identity, "lease", forbidden)
    assert adapter.execute(object(), None) is EMPTY_QUERY_PAGE  # type: ignore[arg-type]
    identity.close()
    journal.close()


def test_query_is_sqlite_independent_and_never_rebuilds_or_opens_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "store"
    journal, identity, adapter, _ = _store(root)
    request = QueryRequest(parse_query_filter({}), limit=2)
    baseline = _ids(adapter.execute(request, _scope()))
    index = root / "index.sqlite"
    index.write_bytes(b"not sqlite and not canonical truth")
    index.chmod(0o600)
    before = (index.lstat(), index.read_bytes())

    monkeypatch.setattr(sqlite3, "connect", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("SQLite opened")))
    assert _ids(adapter.execute(request, _scope())) == baseline
    after = (index.lstat(), index.read_bytes())
    assert after[1] == before[1]
    assert (after[0].st_dev, after[0].st_ino, after[0].st_mode, after[0].st_size, after[0].st_mtime_ns, after[0].st_ctime_ns) == (
        before[0].st_dev,
        before[0].st_ino,
        before[0].st_mode,
        before[0].st_size,
        before[0].st_mtime_ns,
        before[0].st_ctime_ns,
    )
    index.unlink()
    assert _ids(adapter.execute(request, _scope())) == baseline
    assert not index.exists()
    identity.close()
    journal.close()


def test_fixed_hwm_cursor_resumes_after_append_and_full_restart_with_limit_change(tmp_path: Path) -> None:
    root = tmp_path / "store"
    journal, identity, adapter, events = _store(root)
    first = adapter.execute(QueryRequest(parse_query_filter({}), limit=2), _scope())
    assert first.next_cursor is not None
    journal.append(_event(5, when="2026-07-31T00:30:00Z", run_id="run-later", access="restricted"))
    first_ids = _ids(first)
    identity.close()
    journal.close()

    restarted_journal = Journal(root, create=False)
    restarted_identity = ServiceIdentity(root)
    restarted = DurableJournalQueryAdapter(
        restarted_journal,
        restarted_identity,
        nonce_source=lambda size: b"R" * size,
    )
    seen = list(first_ids)
    cursor = first.next_cursor
    while cursor is not None:
        page = restarted.execute(QueryRequest(parse_query_filter({}), limit=1, cursor=cursor), _scope())
        seen.extend(_ids(page))
        cursor = page.next_cursor

    expected = [events[index]["entry_id"] for index in (1, 2, 3, 0, 4)]
    assert seen == expected
    assert _event(5, when="2026-07-31T00:30:00Z", run_id="run-later", access="restricted")["entry_id"] not in seen
    fresh = restarted.execute(QueryRequest(parse_query_filter({}), limit=100), _scope())
    assert fresh.items[0].event["sequence"] == 5

    with pytest.raises(CursorRejected, match="cursor rejected"):
        restarted.execute(
            QueryRequest(parse_query_filter({"access": ["public"]}), limit=1, cursor=first.next_cursor),
            _scope(),
        )
    with pytest.raises(CursorRejected, match="cursor rejected"):
        restarted.execute(QueryRequest(parse_query_filter({}), limit=1, cursor=first.next_cursor), _scope("peer:other"))
    restarted_identity.close()
    restarted_journal.close()


def test_identity_rotation_overlap_retirement_and_generation_roll_control_cursor_validity(tmp_path: Path) -> None:
    root = tmp_path / "store"
    journal, identity, adapter, _ = _store(root)
    request = QueryRequest(parse_query_filter({}), limit=1)
    initial_kid = identity.state.active_kid
    old_page = adapter.execute(request, _scope())
    assert old_page.next_cursor is not None

    identity.rotate_cursor_key()
    assert adapter.execute(QueryRequest(parse_query_filter({}), limit=1, cursor=old_page.next_cursor), _scope()).items
    new_page = adapter.execute(request, _scope())
    assert new_page.next_cursor is not None
    identity.retire_cursor_key(initial_kid)
    with pytest.raises(CursorRejected, match="cursor rejected"):
        adapter.execute(QueryRequest(parse_query_filter({}), limit=1, cursor=old_page.next_cursor), _scope())
    assert adapter.execute(QueryRequest(parse_query_filter({}), limit=1, cursor=new_page.next_cursor), _scope()).items

    identity.roll_generation()
    with pytest.raises(CursorRejected, match="cursor rejected"):
        adapter.execute(QueryRequest(parse_query_filter({}), limit=1, cursor=new_page.next_cursor), _scope())
    identity.close()
    journal.close()


def test_queries_and_replay_persist_no_server_read_state(tmp_path: Path) -> None:
    root = tmp_path / "store"
    journal, identity, adapter, _ = _store(root)
    before = _tree_manifest(root)
    first = adapter.execute(QueryRequest(parse_query_filter({}), limit=1), _scope())
    assert first.next_cursor is not None
    replay = adapter.execute(QueryRequest(parse_query_filter({}), limit=1, cursor=first.next_cursor), _scope())
    assert replay.items
    adapter.execute(QueryRequest(parse_query_filter({"source": {"provider": ["absent"]}}), limit=10), _scope())
    adapter.execute(QueryRequest(parse_query_filter({}), limit=1), _scope("peer:second"))
    assert _tree_manifest(root) == before
    forbidden_names = ("query", "cursor", "receipt", "ack", "subscriber", "cache", "hwm")
    assert not any(any(token in path.name.lower() for token in forbidden_names) for path in root.rglob("*"))
    with pytest.raises(QueryContractError):
        parse_query_request({"filter": {}, "idempotency_key": "read-state-is-forbidden"})
    identity.close()
    journal.close()


def test_request_time_query_rejects_missing_suffix_without_repair_and_empty_query_creates_no_head(tmp_path: Path) -> None:
    root = tmp_path / "store"
    journal, identity, adapter, _ = _store(root)
    pristine_chain = journal.chain_path.read_bytes()
    pristine_head = journal.head_path.read_bytes()
    journal.chain_path.write_bytes(b"".join(pristine_chain.splitlines(keepends=True)[:-1]))
    journal.head_path.unlink()
    damaged = _tree_manifest(root)
    with pytest.raises(JournalError):
        adapter.execute(QueryRequest(parse_query_filter({})), _scope())
    assert _tree_manifest(root) == damaged
    journal.reconcile()
    assert journal.chain_path.read_bytes() == pristine_chain
    assert journal.head_path.read_bytes() == pristine_head
    identity.close()
    journal.close()

    empty_root = tmp_path / "empty"
    empty_journal = Journal(empty_root)
    empty_identity = ServiceIdentity(empty_root, create=True)
    empty_adapter = DurableJournalQueryAdapter(empty_journal, empty_identity)
    before = _tree_manifest(empty_root)
    assert empty_adapter.execute(QueryRequest(parse_query_filter({})), _scope()) is EMPTY_QUERY_PAGE
    assert not empty_journal.head_path.exists()
    assert _tree_manifest(empty_root) == before
    empty_identity.close()
    empty_journal.close()


def test_restore_relocation_preserves_query_cursor_and_has_no_absolute_identity(tmp_path: Path) -> None:
    original_root = tmp_path / "location-a"
    journal, identity, adapter, _ = _store(original_root)
    first = adapter.execute(QueryRequest(parse_query_filter({}), limit=1), _scope())
    assert first.next_cursor is not None
    expected_resume = _ids(adapter.execute(QueryRequest(parse_query_filter({}), limit=1, cursor=first.next_cursor), _scope()))
    identity.close()
    journal.close()

    relocated_root = tmp_path / "location-b"
    shutil.copytree(original_root, relocated_root)
    (relocated_root / "index.sqlite").write_bytes(b"discardable")
    (relocated_root / "index.sqlite").chmod(0o600)
    (relocated_root / "index.sqlite").unlink()
    relocated_journal = Journal(relocated_root, create=False)
    relocated_identity = ServiceIdentity(relocated_root)
    relocated = DurableJournalQueryAdapter(relocated_journal, relocated_identity)
    assert _ids(relocated.execute(QueryRequest(parse_query_filter({}), limit=1, cursor=first.next_cursor), _scope())) == expected_resume
    absolute_a = os.fspath(original_root).encode("utf-8")
    absolute_b = os.fspath(relocated_root).encode("utf-8")
    canonical_files = (
        relocated_journal.events_path,
        relocated_journal.chain_path,
        relocated_journal.head_path,
        relocated_root / "service" / "identity.json",
    )
    assert all(absolute_a not in path.read_bytes() and absolute_b not in path.read_bytes() for path in canonical_files)
    relocated_identity.roll_generation()
    with pytest.raises(CursorRejected):
        relocated.execute(QueryRequest(parse_query_filter({}), limit=1, cursor=first.next_cursor), _scope())
    relocated_identity.close()
    relocated_journal.close()

    original_journal = Journal(original_root, create=False)
    original_identity = ServiceIdentity(original_root)
    original_adapter = DurableJournalQueryAdapter(original_journal, original_identity)
    assert _ids(original_adapter.execute(QueryRequest(parse_query_filter({}), limit=1, cursor=first.next_cursor), _scope())) == expected_resume
    original_identity.close()
    original_journal.close()


def test_snapshot_builder_defensively_rejects_noncanonical_rows(tmp_path: Path) -> None:
    journal, identity, _, _ = _store(tmp_path / "store")
    persisted = journal.verified_snapshot()
    malformed = type(persisted)(
        (persisted.event_rows[0].replace(b"{", b"{ ", 1), *persisted.event_rows[1:]),
        persisted.chain_rows,
        persisted.head_bytes,
    )
    with pytest.raises(QuerySnapshotError):
        build_journal_query_snapshot(malformed)
    identity.close()
    journal.close()
