"""HSP-08: durable canonical journal queries without projection state."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import sqlite3
import stat
from pathlib import Path

import pytest

from houndd import HounddStore, verify_store
from houndd.access import AuthenticatedPrincipal, EventSelector, PrincipalScope, ProducerSelector
from houndd.contracts import make_journal_envelope
from houndd.cursor import CursorBindings, CursorCodec, CursorRejected
from houndd.journal import Journal, JournalError
from houndd.query_contracts import (
    ClassificationFilter,
    ProducerFilter,
    QueryContractError,
    QueryFilter,
    QueryRequest,
    SourceFilter,
    TimeRange,
    parse_query_filter,
    parse_query_request,
)
from houndd.query_engine import EMPTY_QUERY_PAGE, QueryEngineError, QuerySnapshotError
from houndd.service_identity import ServiceIdentity, ServiceIdentityState
from houndd.snapshot import (
    DurableJournalQueryAdapter,
    DurableQueryError,
    QueryFilterNotAvailable,
    build_journal_query_snapshot,
)
from houndd.provenance import ProvenanceProjection
import houndd.provenance as provenance_module


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
    fixture = json.loads((Path(__file__).parent / "fixtures" / "hsp14_legacy_record.json").read_text())
    legacy_bytes = base64.b64decode(fixture["bytes_base64"])
    assert hashlib.sha256(legacy_bytes).hexdigest() == fixture["sha256"]

    original_store = HounddStore(original_root)
    reference = original_store.mirror_legacy(
        fixture["record_id"],
        legacy_bytes,
        expected_sha256=fixture["sha256"],
    )
    blob = original_store.records.blob(legacy_bytes)
    for sequence in range(2):
        original_store.journal.append(
            make_journal_envelope(
                sequence=sequence,
                appended_at=f"2026-07-31T0{sequence}:00:00Z",
                producer={"owner_id": "owner", "capability": "capture", "run_id": f"legacy-{sequence}"},
                artifact={
                    "kind": "import",
                    "schema": "legacy.record.v1",
                    "record_id": reference.record_id,
                    "hash": reference.content_sha256,
                    "authorized_uri": "houndd://legacy/legacy-record-01",
                },
                lineage={"relation": "none", "record_id": reference.record_id, "lead_id": "none"},
                source={"provider": "legacy", "native_id": reference.record_id, "canonical_url": "none"},
                classification={"outcome": "completed", "evidence_status": "evidence"},
                access="workspace",
                policy_id="policy",
                dedupe={"object_key": f"legacy-record-{sequence}", "content_sha256": blob},
                usage={"bytes": len(legacy_bytes)},
            )
        )
    original_store.rebuild_index()
    projection_before = original_store.projection.rows()
    assert original_store.verify()["valid"] is True

    identity = ServiceIdentity(original_root, create=True)
    adapter = DurableJournalQueryAdapter(original_store.journal, identity)
    first = adapter.execute(QueryRequest(parse_query_filter({}), limit=1), _scope())
    assert first.next_cursor is not None
    expected_resume = _ids(adapter.execute(QueryRequest(parse_query_filter({}), limit=1, cursor=first.next_cursor), _scope()))
    identity.close()
    original_store.close()

    relocated_root = tmp_path / "location-b"
    shutil.copytree(original_root, relocated_root)
    (relocated_root / "index.sqlite").unlink()
    restored = HounddStore(relocated_root)
    assert not (relocated_root / "index.sqlite").exists()
    assert verify_store(relocated_root, projection=False)["valid"] is True
    relocated_identity = ServiceIdentity(relocated_root)
    relocated = DurableJournalQueryAdapter(restored.journal, relocated_identity)
    assert _ids(relocated.execute(QueryRequest(parse_query_filter({}), limit=1, cursor=first.next_cursor), _scope())) == expected_resume
    assert restored.records.read(fixture["record_id"]) == legacy_bytes
    assert restored.records.verify_record(fixture["record_id"], fixture["sha256"]) is True
    restored.rebuild_index()
    assert restored.projection.rows() == projection_before
    assert restored.verify()["valid"] is True

    absolute_a = os.fspath(original_root).encode("utf-8")
    absolute_b = os.fspath(relocated_root).encode("utf-8")
    canonical_files = (
        restored.journal.events_path,
        restored.journal.chain_path,
        restored.journal.head_path,
        relocated_root / "service" / "identity.json",
        relocated_root / "legacy" / f"{fixture['record_id']}.json",
        relocated_root / "records" / f"{fixture['record_id']}.bin",
    )
    assert all(absolute_a not in path.read_bytes() and absolute_b not in path.read_bytes() for path in canonical_files)
    relocated_identity.roll_generation()
    with pytest.raises(CursorRejected):
        relocated.execute(QueryRequest(parse_query_filter({}), limit=1, cursor=first.next_cursor), _scope())
    relocated_identity.close()
    restored.close()

    original_store = HounddStore(original_root)
    original_identity = ServiceIdentity(original_root)
    original_adapter = DurableJournalQueryAdapter(original_store.journal, original_identity)
    assert _ids(original_adapter.execute(QueryRequest(parse_query_filter({}), limit=1, cursor=first.next_cursor), _scope())) == expected_resume
    original_identity.close()
    original_store.close()


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


def test_adapter_rejects_journal_and_identity_subclasses_before_overridden_hooks(
    tmp_path: Path,
) -> None:
    calls: list[str] = []

    class HostileJournal(Journal):
        def verified_snapshot(self):
            calls.append("journal")
            raise AssertionError("journal subclass hook reached")

    class HostileIdentity(ServiceIdentity):
        def lease(self):
            calls.append("identity")
            raise AssertionError("identity subclass hook reached")

    hostile_journal = HostileJournal(tmp_path / "journal")
    exact_identity = ServiceIdentity(tmp_path / "journal", create=True)
    with pytest.raises(DurableQueryError):
        DurableJournalQueryAdapter(hostile_journal, exact_identity)
    exact_identity.close()
    hostile_journal.close()

    exact_journal = Journal(tmp_path / "identity")
    hostile_identity = HostileIdentity(tmp_path / "identity", create=True)
    with pytest.raises(DurableQueryError):
        DurableJournalQueryAdapter(exact_journal, hostile_identity)
    hostile_identity.close()
    exact_journal.close()
    assert calls == []


def test_adapter_invokes_trusted_unbound_durable_methods(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "store"
    source = Journal(tmp_path / "source")
    source.append(_event(0, when="2026-07-31T00:00:00Z"))
    forged = source.verified_snapshot()
    journal = Journal(root)
    identity = ServiceIdentity(root, create=True)
    calls: list[str] = []

    def forged_snapshot():
        calls.append("journal")
        return forged

    monkeypatch.setattr(journal, "verified_snapshot", forged_snapshot)
    page = DurableJournalQueryAdapter(journal, identity).execute(QueryRequest(parse_query_filter({})), _scope())

    assert page is EMPTY_QUERY_PAGE
    assert calls == []
    identity.close()
    journal.close()
    source.close()


class _RequestSubclass(QueryRequest):
    hook_calls = 0

    @property
    def filter_hash(self) -> str:
        type(self).hook_calls += 1
        return "f" * 64


class _ScopeSubclass(PrincipalScope):
    hook_calls = 0

    def __getattribute__(self, name: str):
        if name in {"principal", "readable_tiers", "permitted_event_selectors"}:
            type(self).hook_calls += 1
        return super().__getattribute__(name)


class _FilterSubclass(QueryFilter):
    hook_calls = 0

    def __getattribute__(self, name: str):
        if name in {"entity", "lane", "topic", "filter_hash", "canonical"}:
            type(self).hook_calls += 1
        return super().__getattribute__(name)


class _PrincipalSubclass(AuthenticatedPrincipal):
    hook_calls = 0

    def __getattribute__(self, name: str):
        if name == "subject":
            type(self).hook_calls += 1
        return super().__getattribute__(name)


class _SelectorSubclass(EventSelector):
    hook_calls = 0

    def permits(self, access, policy_id, producer):
        type(self).hook_calls += 1
        return True


class _ProducerSelectorSubclass(ProducerSelector):
    hook_calls = 0

    def matches(self, claim):
        type(self).hook_calls += 1
        return True


@pytest.mark.parametrize("kind", ["request", "scope", "filter", "principal", "selector", "producer_selector"])
def test_adapter_rejects_subclasses_across_the_complete_request_and_scope_graph_before_hooks(
    tmp_path: Path,
    kind: str,
) -> None:
    journal, identity, adapter, _ = _store(tmp_path / kind)
    request: QueryRequest = QueryRequest(parse_query_filter({}), limit=1)
    scope = _scope()
    hostile_type: type
    if kind == "request":
        request = _RequestSubclass(request.filter, request.limit, request.cursor)
        hostile_type = _RequestSubclass
    elif kind == "scope":
        scope = _ScopeSubclass(scope.principal, scope.readable_tiers, scope.permitted_event_selectors)
        hostile_type = _ScopeSubclass
    elif kind == "filter":
        request = QueryRequest(_FilterSubclass())
        hostile_type = _FilterSubclass
    elif kind == "principal":
        principal = _PrincipalSubclass(scope.principal.subject)
        scope = PrincipalScope(principal, scope.readable_tiers, scope.permitted_event_selectors)
        hostile_type = _PrincipalSubclass
    elif kind == "selector":
        selector = scope.permitted_event_selectors[0]
        hostile = _SelectorSubclass(selector.policy_id, selector.producer_selector, selector.readable_tiers)
        scope = PrincipalScope(scope.principal, scope.readable_tiers, (hostile,))
        hostile_type = _SelectorSubclass
    else:
        selector = scope.permitted_event_selectors[0]
        producer = selector.producer_selector
        hostile = _ProducerSelectorSubclass(producer.owner_id, producer.capability, producer.run_id)
        scope = PrincipalScope(
            scope.principal,
            scope.readable_tiers,
            (EventSelector(selector.policy_id, hostile, selector.readable_tiers),),
        )
        hostile_type = _ProducerSelectorSubclass
    hostile_type.hook_calls = 0

    with pytest.raises(QueryEngineError):
        adapter.execute(request, scope)

    assert hostile_type.hook_calls == 0
    identity.close()
    journal.close()


@pytest.mark.parametrize("nested_type", [TimeRange, ProducerFilter, SourceFilter, ClassificationFilter])
def test_adapter_rejects_nested_filter_model_subclasses(tmp_path: Path, nested_type: type) -> None:
    journal, identity, adapter, _ = _store(tmp_path / nested_type.__name__)
    if nested_type is TimeRange:
        value = parse_query_filter({"time_range": {"from": "2026-07-30T00:00:00Z", "to": "2026-08-01T00:00:00Z"}}).time_range
        assert value is not None
        hostile = type("HostileTimeRange", (TimeRange,), {})(value.lower, value.upper)
        query_filter = QueryFilter(time_range=hostile)
    elif nested_type is ProducerFilter:
        hostile = type("HostileProducerFilter", (ProducerFilter,), {})(owner_id=("owner",))
        query_filter = QueryFilter(producer=hostile)
    elif nested_type is SourceFilter:
        hostile = type("HostileSourceFilter", (SourceFilter,), {})(provider=("exa",))
        query_filter = QueryFilter(source=hostile)
    else:
        hostile = type("HostileClassificationFilter", (ClassificationFilter,), {})(outcome=("completed",))
        query_filter = QueryFilter(classification=hostile)

    with pytest.raises(QueryEngineError):
        adapter.execute(QueryRequest(query_filter), _scope())

    identity.close()
    journal.close()


def test_adapter_reconstructs_exact_request_and_scope_before_durable_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "store"
    journal = Journal(root)
    journal.append(_event(0, when="2026-07-31T00:00:00Z", access="restricted"))
    identity = ServiceIdentity(root, create=True)
    adapter = DurableJournalQueryAdapter(journal, identity)
    request = QueryRequest(parse_query_filter({}))
    scope = PrincipalScope(
        AuthenticatedPrincipal("peer:reader"),
        frozenset({"public"}),
        (EventSelector("policy", ProducerSelector(owner_id="owner", capability="capture"), frozenset({"public"})),),
    )
    real_snapshot = Journal.verified_snapshot

    def mutate_call(self):
        object.__setattr__(scope, "readable_tiers", frozenset({"public", "restricted"}))
        object.__setattr__(
            scope,
            "permitted_event_selectors",
            (EventSelector("policy", ProducerSelector(owner_id="owner", capability="capture"), frozenset({"restricted"})),),
        )
        object.__setattr__(request, "filter", parse_query_filter({"access": ["restricted"]}))
        return real_snapshot(self)

    monkeypatch.setattr(Journal, "verified_snapshot", mutate_call)
    assert adapter.execute(request, scope) is EMPTY_QUERY_PAGE
    identity.close()
    journal.close()


def test_hostile_cursor_rejects_before_provenance_prefix_work(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "store"
    journal = Journal(root)
    for sequence in range(100):
        journal.append(_event(sequence, when=f"2026-07-31T00:{sequence // 60:02d}:{sequence % 60:02d}Z"))
    identity = ServiceIdentity(root, create=True)
    adapter = DurableJournalQueryAdapter(journal, identity)
    project_calls = 0
    real_project = ProvenanceProjection.project

    def observed_project(self, scope, event):
        nonlocal project_calls
        project_calls += 1
        return real_project(self, scope, event)

    monkeypatch.setattr(ProvenanceProjection, "project", observed_project)
    with pytest.raises(CursorRejected, match="cursor rejected"):
        adapter.execute(QueryRequest(parse_query_filter({}), limit=1, cursor="hostile"), _scope())
    assert project_calls == 0
    identity.close()
    journal.close()


def test_authenticated_wrong_context_cursor_rejection_has_linear_bounded_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "store"
    journal = Journal(root)
    for sequence in range(40):
        journal.append(_event(sequence, when=f"2026-07-31T00:00:{sequence:02d}Z"))
    identity = ServiceIdentity(root, create=True)
    scope = _scope()
    base_request = QueryRequest(parse_query_filter({}), limit=1)
    snapshot = build_journal_query_snapshot(journal.verified_snapshot())
    candidates = snapshot.cursor_recovery_snapshot.candidates
    state = identity.state
    forged_context = CursorBindings(
        state.generation,
        base_request.filter_hash,
        scope.principal.subject,
        "f" * 64,
    )
    token = CursorCodec(state.keyring, nonce_source=lambda size: b"W" * size).issue(
        forged_context,
        last=candidates[0],
        high_watermark=candidates[-1],
    )
    context_hash_calls = 0
    recovery_scans = 0
    real_context_hash = provenance_module.canonical_hash
    real_recover_positions = CursorCodec._recover_positions

    def observed_context_hash(value):
        nonlocal context_hash_calls
        context_hash_calls += 1
        return real_context_hash(value)

    def observed_recover_positions(decoded, secret, bindings, recovery_snapshot, *, scan_observer):
        nonlocal recovery_scans
        recovery_scans += len(recovery_snapshot.candidates)
        return real_recover_positions(
            decoded,
            secret,
            bindings,
            recovery_snapshot,
            scan_observer=scan_observer,
        )

    monkeypatch.setattr(provenance_module, "canonical_hash", observed_context_hash)
    monkeypatch.setattr(CursorCodec, "_recover_positions", staticmethod(observed_recover_positions))
    adapter = DurableJournalQueryAdapter(journal, identity)
    with pytest.raises(CursorRejected, match="cursor rejected"):
        adapter.execute(QueryRequest(base_request.filter, limit=1, cursor=token), scope)
    assert context_hash_calls <= 41
    assert recovery_scans == 0
    identity.close()
    journal.close()


def test_valid_old_cursor_context_recovery_is_linear_after_append(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "store"
    journal = Journal(root)
    for sequence in range(100):
        journal.append(_event(sequence, when=f"2026-07-31T00:{sequence // 60:02d}:{sequence % 60:02d}Z"))
    identity = ServiceIdentity(root, create=True)
    adapter = DurableJournalQueryAdapter(journal, identity, nonce_source=lambda size: b"N" * size)
    first = adapter.execute(QueryRequest(parse_query_filter({}), limit=1), _scope())
    assert first.next_cursor is not None
    journal.append(_event(100, when="2026-07-31T02:00:00Z"))
    project_calls = 0
    context_hash_calls = 0
    recovery_scans = 0
    real_project = ProvenanceProjection.project
    real_context_hash = provenance_module.canonical_hash
    real_recover_positions = CursorCodec._recover_positions

    def observed_project(self, scope, event):
        nonlocal project_calls
        project_calls += 1
        return real_project(self, scope, event)

    def observed_context_hash(value):
        nonlocal context_hash_calls
        context_hash_calls += 1
        return real_context_hash(value)

    def observed_recover_positions(decoded, secret, bindings, snapshot, *, scan_observer):
        nonlocal recovery_scans
        recovery_scans += len(snapshot.candidates)
        return real_recover_positions(
            decoded,
            secret,
            bindings,
            snapshot,
            scan_observer=scan_observer,
        )

    monkeypatch.setattr(ProvenanceProjection, "project", observed_project)
    monkeypatch.setattr(provenance_module, "canonical_hash", observed_context_hash)
    monkeypatch.setattr(CursorCodec, "_recover_positions", staticmethod(observed_recover_positions))
    resumed = adapter.execute(QueryRequest(parse_query_filter({}), limit=1, cursor=first.next_cursor), _scope())
    assert resumed.items
    assert project_calls <= 3 * 101
    assert context_hash_calls <= 2 * (101 + 1)
    assert recovery_scans == 2 * 101
    identity.close()
    journal.close()
