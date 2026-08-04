"""GOALIE B12: the journal chain is verified once per persisted prefix.

Every chain access — ``high_watermark``, ``get``, ``entries``, ``append``,
``verified_snapshot`` — re-derived and re-checked the whole hash chain, so a
commit paid for every entry behind it and a startup that recovers, reconciles,
rebuilds, and verifies paid for the journal once per pass through it.  At 859
entries that made the daemon spend minutes at full CPU before it could publish
its socket, and the cost grew with the square of the journal.

These tests pin the two claims that let an access stop paying that, and the
detection contract that reuse must not weaken:

* the verified prefix is derived once, so N commits cost O(N) chain-entry
  verifications and a whole startup sequence costs exactly one pass;
* reuse is gated on the persisted bytes proving byte-identical over that
  prefix, so any mutation of an already-verified entry is caught on the next
  access — by the same instance, by a new one, and with the file's timestamps
  restored, because the gate is a byte comparison and not a stat heuristic.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any, Callable

import pytest

from houndd import HounddStore
from houndd import journal as journal_module
from houndd.commit_runtime import CommitRuntime
from houndd.contracts import make_journal_envelope
from houndd.journal import Journal, JournalError
from houndd.verify import verify_store

from tests.test_b11_incremental_projection import _file, _state


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _event(sequence: int) -> dict[str, Any]:
    return make_journal_envelope(
        sequence=sequence,
        appended_at=f"2026-08-04T00:00:{sequence % 60:02d}Z",
        producer={"owner_id": "owner", "capability": "capture", "run_id": f"run-{sequence}"},
        artifact={
            "kind": "capture",
            "schema": "houndd.capture.v1",
            "record_id": f"record-{sequence}",
            "hash": _digest(f"record-{sequence}"),
            "authorized_uri": f"houndd://records/{sequence}",
        },
        lineage={"relation": "none", "record_id": f"record-{sequence}", "lead_id": "none"},
        source={"provider": "provider", "native_id": f"native-{sequence}", "canonical_url": f"https://example.test/{sequence}"},
        classification={"outcome": "completed", "evidence_status": "evidence"},
        access="workspace",
        policy_id="policy",
        dedupe={"object_key": f"object-{sequence}", "content_sha256": _digest(f"content-{sequence}")},
        usage={},
    )


class _Verifications:
    """Count chain-entry hash verifications, the per-entry cost of a pass."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.count = 0
        real = Journal._chain_value

        def counting(event: dict[str, Any], previous: str) -> dict[str, Any]:
            self.count += 1
            return real(event, previous)

        monkeypatch.setattr(Journal, "_chain_value", staticmethod(counting))

    def since(self, mark: int) -> int:
        return self.count - mark


def _cold() -> None:
    """Drop every in-memory verification, exactly as starting a process does."""

    journal_module._MEMOS.clear()


def _rewrite(path: Path, mutate: Callable[[bytes], bytes]) -> None:
    """Rewrite a journal file in place, restoring its timestamps.

    Restoring atime/mtime is the point: detection may not lean on a file
    changing timestamp, size, or inode, so every tamper here leaves all three
    exactly as the verified read saw them where the mutation allows it.
    """

    info = path.stat()
    raw = path.read_bytes()
    mutated = mutate(raw)
    path.write_bytes(mutated)
    os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))


def _flip(raw: bytes, needle: bytes) -> bytes:
    """Replace one hex digit inside ``needle`` without changing any length."""

    index = raw.index(needle)
    replacement = b"f" if raw[index : index + 1] != b"f" else b"e"
    return raw[:index] + replacement + raw[index + 1 :]


def _commits(runtime: CommitRuntime, start: int, count: int) -> None:
    for index in range(start, start + count):
        _file(runtime, f"key-{index}", f"payload-{index}".encode())


def test_commit_path_chain_verification_is_linear_in_journal_length(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """N commits on one runtime cost O(N) chain-entry verifications."""

    state = _state(tmp_path)
    verifications = _Verifications(monkeypatch)
    runtime = CommitRuntime(state)
    try:
        first = verifications.count
        _commits(runtime, 0, 20)
        head = verifications.since(first)
        second = verifications.count
        _commits(runtime, 20, 20)
        tail = verifications.since(second)
    finally:
        runtime.close()

    # A per-commit full pass would make the second twenty commits cost about
    # three times the first; a bounded commit pays the same for both.
    assert tail == head
    assert head <= 4 * 20
    assert verify_store(state)["valid"] is True


def test_startup_recovery_performs_exactly_one_full_chain_verification(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Recover, reconcile, rebuild, and verify share one verified journal."""

    state = _state(tmp_path)
    runtime = CommitRuntime(state)
    try:
        _commits(runtime, 0, 24)
    finally:
        runtime.close()

    verifications = _Verifications(monkeypatch)
    _cold()
    store = HounddStore(state)
    recovery = CommitRuntime(state)
    try:
        store.recover()
        assert store.verify()["valid"] is True
        recovery.reconcile()
        store.rebuild_index()
        assert verify_store(state)["valid"] is True
    finally:
        recovery.close()
        store.close()

    assert verifications.count == 24


def test_cold_start_verifies_every_entry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Nothing is persisted, so a process that has proven nothing proves all."""

    root = tmp_path / "store"
    with Journal(root) as writer:
        for sequence in range(6):
            writer.append(_event(sequence))

    verifications = _Verifications(monkeypatch)
    _cold()
    with Journal(root, create=False) as journal:
        assert journal.high_watermark() == 5
        first = verifications.count
        assert journal.entries()[3]["sequence"] == 3
        assert journal.get(journal.entries()[0]["entry_id"]) is not None
        assert journal.verified_snapshot().head_bytes is not None

    assert first == 6
    assert verifications.since(first) == 0


@pytest.mark.parametrize(
    ("target", "needle"),
    (
        pytest.param("chain", b"chain_sha256", id="chain-row"),
        pytest.param("events", b"entry_id", id="event-row"),
    ),
)
def test_tamper_inside_the_verified_prefix_is_caught_on_the_next_access(
    tmp_path: Path,
    target: str,
    needle: bytes,
) -> None:
    """A rewritten byte behind the high watermark fails the very next access."""

    root = tmp_path / "store"
    with Journal(root) as journal:
        for sequence in range(4):
            journal.append(_event(sequence))
        assert journal.high_watermark() == 3
        path = journal.chain_path if target == "chain" else journal.events_path
        before = path.stat()
        _rewrite(path, lambda raw: _flip(raw, needle))
        after = path.stat()
        assert (after.st_size, after.st_mtime_ns, after.st_ino) == (before.st_size, before.st_mtime_ns, before.st_ino)

        with pytest.raises(JournalError):
            journal.entries()
        with pytest.raises(JournalError):
            journal.high_watermark()
        with pytest.raises(JournalError):
            journal.verified_snapshot()
        with pytest.raises(JournalError):
            journal.append(_event(4))


def test_tamper_inside_the_verified_prefix_is_caught_by_a_new_instance(tmp_path: Path) -> None:
    """A journal opened after the mutation is no weaker than the one that verified it."""

    root = tmp_path / "store"
    with Journal(root) as writer:
        for sequence in range(4):
            writer.append(_event(sequence))
        assert writer.entries()[0]["sequence"] == 0
        _rewrite(writer.chain_path, lambda raw: _flip(raw, b"event_sha256"))

        with Journal(root, create=False) as reader:
            with pytest.raises(JournalError):
                reader.entries()
            with pytest.raises(JournalError):
                reader.verified_snapshot()


def test_truncated_verified_prefix_is_rejected_not_reused(tmp_path: Path) -> None:
    """A shortened chain is not a prefix extension, so nothing is carried over."""

    root = tmp_path / "store"
    with Journal(root) as journal:
        for sequence in range(3):
            journal.append(_event(sequence))
        rows = journal.chain_path.read_bytes().splitlines(keepends=True)
        # The one shape a crash can leave: the chain and head suffix an
        # interrupted append never wrote.
        _rewrite(journal.chain_path, lambda raw: b"".join(rows[:2]))
        journal.head_path.unlink()

        with pytest.raises(JournalError, match="incomplete"):
            journal.entries()
        with pytest.raises(JournalError, match="incomplete"):
            journal.verified_snapshot()
        # Only the crash-left suffix is repairable, and repair still re-derives it.
        assert journal.reconcile() == {"valid": True, "sequence": 2, "entries": 3, "chain_entries": 3}
        assert journal.chain_path.read_bytes() == b"".join(rows)


def test_head_tamper_behind_the_watermark_is_caught(tmp_path: Path) -> None:
    """The head is never carried over; it is compared on every access."""

    root = tmp_path / "store"
    with Journal(root) as journal:
        for sequence in range(3):
            journal.append(_event(sequence))
        assert journal.high_watermark() == 2
        _rewrite(journal.head_path, lambda raw: _flip(raw, b"chain_sha256"))

        with pytest.raises(JournalError):
            journal.entries()
        with pytest.raises(JournalError):
            journal.verified_snapshot()


def test_a_valid_append_by_another_instance_costs_only_the_new_entry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Two journals over one directory share the proven prefix, not the reader."""

    root = tmp_path / "store"
    verifications = _Verifications(monkeypatch)
    with Journal(root) as writer, Journal(root, create=False) as reader:
        for sequence in range(5):
            writer.append(_event(sequence))
        assert reader.high_watermark() == 4
        mark = verifications.count
        writer.append(_event(5))
        assert reader.entries()[5]["sequence"] == 5
        # One derivation to build the appended chain row, one to verify it.
        assert verifications.since(mark) == 2


def test_returned_entries_do_not_alias_the_verified_prefix(tmp_path: Path) -> None:
    """A caller cannot reshape what the next access treats as proven."""

    root = tmp_path / "store"
    with Journal(root) as journal:
        for sequence in range(3):
            journal.append(_event(sequence))
        entries = journal.entries()
        entries.pop()
        entries.append({"sequence": 99})
        assert [event["sequence"] for event in journal.entries()] == [0, 1, 2]
        assert journal.high_watermark() == 2
