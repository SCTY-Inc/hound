"""HSP-05: serialized append-only journal with sequence and chain integrity."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator

from .contracts import canonical_bytes, canonical_hash, validate_journal_envelope
from ._safety import AnchoredRoot, check_private_stat
from .store import StoreError, UnsafeStoreError

try:
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None


class JournalError(StoreError):
    """The journal is invalid, unavailable, or cannot preserve ordering."""


FaultHook = Callable[[str], None]

_CHAIN_FIELDS = frozenset(
    {"sequence", "entry_id", "event_sha256", "previous_chain_sha256", "chain_sha256"}
)
_HEAD_FIELDS = frozenset({"sequence", "entry_id", "chain_sha256"})
_EMPTY_CHAIN_SHA256 = "0" * 64
_SHA256_CHARACTERS = frozenset("0123456789abcdef")
_EMPTY_HEAD_BYTES = canonical_bytes({"sequence": -1, "chain_sha256": _EMPTY_CHAIN_SHA256, "entry_id": ""})


@dataclass(frozen=True, slots=True)
class PersistedJournalSnapshot:
    """Exact persisted journal rows captured at one lock linearization point."""

    event_rows: tuple[bytes, ...]
    chain_rows: tuple[bytes, ...]
    head_bytes: bytes | None


@dataclass(slots=True)
class _VerifiedChain:
    """One verification of an exact persisted journal byte prefix.

    Every field is derived from ``events_raw`` and ``chains_raw`` alone, so
    holding it is memoizing a pure function of persisted bytes.  A reader
    reuses it only after the bytes it has just read under the journal lock
    prove byte-identical over that prefix, which makes reuse exactly as strong
    as deriving it again and leaves the first read of any prefix — every cold
    start — a full verification.  Nothing here is ever persisted.
    """

    events_raw: bytes
    chains_raw: bytes
    events: list[dict[str, Any]]
    expected: list[dict[str, Any]]
    # Persisted chain rows are proven equal to ``expected`` as they arrive, so
    # only how many of them have been proven is worth keeping.
    chains: int
    entry_ids: set[str]
    event_hashes: set[str]
    chain_hashes: set[str]

    def extends(self, events_raw: bytes, chains_raw: bytes) -> bool:
        return events_raw.startswith(self.events_raw) and chains_raw.startswith(self.chains_raw)


# The journal is append-only, so the same bytes are read again on every
# access.  Verifications are shared per journal directory rather than per
# ``Journal`` object because a single process holds several journals over one
# directory (store, transactions, commit runtime, verification) and the memo
# is a function of the bytes, not of the reader.  The bound keeps a long-lived
# process from retaining journals it has stopped reading.
_MEMO_LIMIT = 8
_MEMOS: dict[tuple[int, int], _VerifiedChain] = {}


def _fresh_memo(identity: tuple[int, int]) -> _VerifiedChain:
    memo = _VerifiedChain(b"", b"", [], [], 0, set(), set(), set())
    _MEMOS[identity] = memo
    while len(_MEMOS) > _MEMO_LIMIT:
        del _MEMOS[next(iter(_MEMOS))]
    return memo


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in _SHA256_CHARACTERS for character in value)
    )


def _validate_persisted_chain_value(value: object) -> dict[str, Any]:
    if (
        type(value) is not dict
        or len(value) != len(_CHAIN_FIELDS)
        or any(type(key) is not str for key in value)
        or frozenset(value) != _CHAIN_FIELDS
    ):
        raise ValueError("journal chain row has invalid fields")
    if type(value["sequence"]) is not int or value["sequence"] < 0:
        raise ValueError("journal chain sequence must be a non-negative exact integer")
    if any(
        not _is_sha256(value[field])
        for field in ("entry_id", "event_sha256", "previous_chain_sha256", "chain_sha256")
    ):
        raise ValueError("journal chain identity and hashes must be exact lowercase SHA-256 strings")
    return value


def _validate_persisted_head_value(value: object) -> dict[str, Any]:
    if (
        type(value) is not dict
        or len(value) != len(_HEAD_FIELDS)
        or any(type(key) is not str for key in value)
        or frozenset(value) != _HEAD_FIELDS
    ):
        raise ValueError("journal head has invalid fields")
    sequence = value["sequence"]
    entry_id = value["entry_id"]
    chain_sha256 = value["chain_sha256"]
    if type(sequence) is not int or sequence < -1:
        raise ValueError("journal head sequence must be an exact integer no smaller than -1")
    if type(entry_id) is not str or not _is_sha256(chain_sha256):
        raise ValueError("journal head identity and chain hash must be exact canonical strings")
    if sequence == -1:
        if entry_id != "" or chain_sha256 != _EMPTY_CHAIN_SHA256:
            raise ValueError("empty journal head has invalid identity or chain hash")
    elif not _is_sha256(entry_id):
        raise ValueError("journal head entry ID must be an exact lowercase SHA-256 string")
    return value


def _private_directory(path: Path, *, create: bool = True) -> None:
    if path.is_symlink():
        raise UnsafeStoreError(f"{path} must not be a symlink")
    existed = path.exists()
    if create:
        path.mkdir(exist_ok=existed)
        if not existed:
            path.chmod(0o700)
    elif not existed:
        raise UnsafeStoreError(f"{path} is missing")
    info = path.stat()
    check_private_stat(info, path, directory=True, error_type=UnsafeStoreError)


def _atomic_bytes(anchor: AnchoredRoot, *parts: str, data: bytes) -> None:
    anchor.write_bytes_atomic(*parts, data=data)


class Journal:
    """A single-writer logical journal backed by a process-safe file lock."""

    def __init__(self, root: str | os.PathLike[str], *, create: bool = True) -> None:
        try:
            self.anchor = AnchoredRoot(root, error_type=UnsafeStoreError, create=create)
            self.root = self.anchor.path
            self.directory = self.root / "journal"
            self.events_path = self.directory / "events.jsonl"
            self.chain_path = self.directory / "chain.jsonl"
            self.head_path = self.directory / "head.json"
            self.lock_path = self.directory / "lock"
            with self.anchor.operation():
                self.anchor.mkdir("journal", create=create)
                for name, path in (("events.jsonl", self.events_path), ("chain.jsonl", self.chain_path), ("lock", self.lock_path)):
                    try:
                        flags = os.O_WRONLY | ((os.O_CREAT | os.O_EXCL) if create else 0)
                        descriptor = self.anchor.open_file("journal", name, flags=flags)
                    except UnsafeStoreError:
                        descriptor = self.anchor.open_file("journal", name, flags=os.O_WRONLY)
                    try:
                        check_private_stat(os.fstat(descriptor), path, directory=False, error_type=UnsafeStoreError)
                    finally:
                        os.close(descriptor)
                if "head.json" in self.anchor.listdir("journal"):
                    check_private_stat(self.anchor.stat("journal", "head.json"), self.head_path, directory=False, error_type=UnsafeStoreError)
                info = self.anchor.stat("journal")
                self._identity = (info.st_dev, info.st_ino)
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        anchor = getattr(self, "anchor", None)
        if anchor is not None:
            anchor.close()

    def __enter__(self) -> "Journal":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @contextmanager
    def _lock(self) -> Iterator[None]:
        if fcntl is None:
            raise JournalError("journal locking is unavailable")
        with self.anchor.operation():
            descriptor = self.anchor.open_file("journal", "lock", flags=os.O_RDWR)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                yield
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

    def _raw_unlocked(self, name: str, path: Path) -> bytes:
        try:
            return self.anchor.read_bytes("journal", name)
        except OSError as error:
            raise JournalError(f"cannot read journal file {path}") from error

    @staticmethod
    def _validated_envelopes(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
        try:
            return [validate_journal_envelope(value) for value in values]
        except ValueError as error:
            raise JournalError(f"journal envelope is invalid: {error}") from error

    @staticmethod
    def _validated_chain_rows(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
        try:
            return [_validate_persisted_chain_value(value) for value in values]
        except ValueError as error:
            raise JournalError(str(error)) from error

    def _persisted_bytes_unlocked(self) -> tuple[bytes, bytes, bytes | None]:
        """Read events, chain, and head exactly once in canonical order."""

        try:
            events_raw = self.anchor.read_bytes("journal", "events.jsonl")
            chains_raw = self.anchor.read_bytes("journal", "chain.jsonl")
            head_raw = (
                self.anchor.read_bytes("journal", "head.json")
                if self.anchor.exists("journal", "head.json")
                else None
            )
        except (OSError, StoreError) as error:
            raise JournalError("cannot read persisted journal snapshot") from error
        return events_raw, chains_raw, head_raw

    @staticmethod
    def _read_lines_from_raw(path: Path, raw: bytes) -> list[dict[str, Any]]:
        if raw and not raw.endswith(b"\n"):
            raise JournalError(f"journal file {path} has a partial final line")
        result = []
        rows = raw.split(b"\n")
        if rows[-1] != b"":  # Guarded above; retained as an exact-LF invariant.
            raise JournalError(f"journal file {path} has a partial final line")
        for line in rows[:-1]:
            try:
                value = json.loads(line.decode("utf-8"))
            except (UnicodeError, ValueError) as error:
                raise JournalError(f"journal file {path} has invalid JSON") from error
            if not isinstance(value, dict):
                raise JournalError(f"journal file {path} contains a non-object")
            try:
                canonical = canonical_bytes(value)
            except ValueError as error:
                raise JournalError(f"journal file {path} contains non-canonical JSON") from error
            if canonical != line:
                raise JournalError(f"journal file {path} contains non-canonical JSON")
            result.append(value)
        return result

    @staticmethod
    def _chain_value(event: dict[str, Any], previous: str) -> dict[str, Any]:
        body = {
            "sequence": event["sequence"],
            "entry_id": event["entry_id"],
            "event_sha256": hashlib.sha256(canonical_bytes(event)).hexdigest(),
            "previous_chain_sha256": previous,
        }
        return {**body, "chain_sha256": canonical_hash(body)}

    @staticmethod
    def _head_from_raw(raw: bytes) -> dict[str, Any]:
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeError, ValueError) as error:
            raise JournalError("journal head is unreadable") from error
        try:
            canonical = canonical_bytes(value) if isinstance(value, dict) else None
        except ValueError as error:
            raise JournalError("journal head is not canonical JSON") from error
        if canonical != raw:
            raise JournalError("journal head is not canonical JSON")
        try:
            return _validate_persisted_head_value(value)
        except ValueError as error:
            raise JournalError(str(error)) from error

    def _verified_chain(
        self,
        events_raw: bytes,
        chains_raw: bytes,
        *,
        allow_short_chain: bool,
        chain_lines_first: bool = False,
    ) -> _VerifiedChain:
        """Prove the persisted chain, deriving only what is not already proven.

        A journal only ever grows, so a read normally sees the exact bytes an
        earlier read already proved valid followed by a suffix.  One
        byte-for-byte comparison against the memoized prefix establishes that;
        every other state — a byte rewritten inside the prefix, a truncation,
        the first read of this directory in this process — discards the memo
        and re-derives every entry exactly as an unmemoized reader would.  The
        entry checks below are therefore run against the same bytes, in the
        same order, with the same first failure as before.

        ``chain_lines_first`` preserves each caller's existing first-error
        precedence between a malformed chain line and an invalid envelope.
        """

        memo = _MEMOS.get(self._identity)
        if memo is None or not memo.extends(events_raw, chains_raw):
            memo = _fresh_memo(self._identity)
        event_tail = events_raw[len(memo.events_raw) :]
        chain_tail = chains_raw[len(memo.chains_raw) :]
        if chain_lines_first:
            event_values = self._read_lines_from_raw(self.events_path, event_tail)
            chain_values = self._read_lines_from_raw(self.chain_path, chain_tail)
            new_events = self._validated_envelopes(event_values)
            new_chains = self._validated_chain_rows(chain_values)
        else:
            new_events = self._validated_envelopes(self._read_lines_from_raw(self.events_path, event_tail))
            new_chains = self._validated_chain_rows(self._read_lines_from_raw(self.chain_path, chain_tail))
        events_count = len(memo.events) + len(new_events)
        chains_count = memo.chains + len(new_chains)
        if chains_count > events_count:
            raise JournalError("journal chain has entries without events")
        if chains_count < events_count and not allow_short_chain:
            raise JournalError("journal chain is incomplete")

        start = min(len(memo.events), memo.chains)
        previous = memo.expected[start - 1]["chain_sha256"] if start else _EMPTY_CHAIN_SHA256
        expected_tail: list[dict[str, Any]] = []
        entry_ids: set[str] = set()
        event_hashes: set[str] = set()
        chain_hashes: set[str] = set()
        for index in range(start, events_count):
            proven = index < len(memo.events)
            if proven:
                expected = memo.expected[index]
            else:
                event = new_events[index - len(memo.events)]
                event_hash = hashlib.sha256(canonical_bytes(event)).hexdigest()
                if (
                    event["sequence"] != index
                    or event["entry_id"] in memo.entry_ids
                    or event["entry_id"] in entry_ids
                    or event_hash in memo.event_hashes
                    or event_hash in event_hashes
                ):
                    raise JournalError("journal sequence, entry IDs, or event hashes are not strictly ordered")
                expected = self._chain_value(event, previous)
            if memo.chains <= index < chains_count:
                if canonical_bytes(new_chains[index - memo.chains]) != canonical_bytes(expected):
                    raise JournalError(f"journal chain mismatch at sequence {index}")
            if not proven:
                if expected["chain_sha256"] in memo.chain_hashes or expected["chain_sha256"] in chain_hashes:
                    raise JournalError("journal chain hashes are not unique")
                entry_ids.add(event["entry_id"])
                event_hashes.add(event_hash)
                chain_hashes.add(expected["chain_sha256"])
                expected_tail.append(expected)
            previous = expected["chain_sha256"]

        # Nothing is memoized until the whole suffix has proved valid, so a
        # rejected read leaves the previously proven prefix exactly as it was.
        memo.events.extend(new_events)
        memo.expected.extend(expected_tail)
        memo.chains = chains_count
        memo.entry_ids.update(entry_ids)
        memo.event_hashes.update(event_hashes)
        memo.chain_hashes.update(chain_hashes)
        memo.events_raw = events_raw
        memo.chains_raw = chains_raw
        return memo

    def verified_snapshot(self) -> PersistedJournalSnapshot:
        """Read and verify persisted journal truth without repairing or writing."""

        with self._lock():
            events_raw, chains_raw, head_raw = self._persisted_bytes_unlocked()
            verified = self._verified_chain(events_raw, chains_raw, allow_short_chain=False, chain_lines_first=True)
            events = verified.events
            if events:
                if head_raw is None:
                    raise JournalError("journal head is missing")
                self._head_from_raw(head_raw)
                if head_raw != self._head_bytes(events, verified.expected, len(events) - 1):
                    raise JournalError("journal head does not match journal chain")
            elif head_raw is not None:
                self._head_from_raw(head_raw)
                if head_raw != _EMPTY_HEAD_BYTES:
                    raise JournalError("empty journal head is invalid")
            return PersistedJournalSnapshot(
                tuple(row + b"\n" for row in events_raw.split(b"\n")[:-1]),
                tuple(row + b"\n" for row in chains_raw.split(b"\n")[:-1]),
                head_raw,
            )

    @staticmethod
    def _head_bytes(events: list[dict[str, Any]], expected_chains: list[dict[str, Any]], index: int) -> bytes:
        return canonical_bytes(
            {
                "sequence": events[index]["sequence"],
                "chain_sha256": expected_chains[index]["chain_sha256"],
                "entry_id": events[index]["entry_id"],
            }
        )

    def _validate_chain_unlocked(self, *, repair_missing: bool = False) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        verified = self._verified_chain(
            self._raw_unlocked("events.jsonl", self.events_path),
            self._raw_unlocked("chain.jsonl", self.chain_path),
            allow_short_chain=repair_missing,
        )
        events = verified.events
        expected_chains = verified.expected
        persisted_count = verified.chains
        head_bytes = self._head_bytes(events, expected_chains, len(events) - 1) if events else _EMPTY_HEAD_BYTES
        head_needs_repair = False
        if self.anchor.exists("journal", "head.json"):
            try:
                raw_head = self.anchor.read_bytes("journal", "head.json")
                head = self._head_from_raw(raw_head)
            except (OSError, StoreError) as error:
                raise JournalError("journal head is unreadable") from error
            if raw_head == head_bytes and persisted_count == len(events):
                pass
            elif repair_missing and self._is_stale_head(raw_head, head, events, expected_chains, persisted_count):
                head_needs_repair = True
            else:
                raise JournalError("journal head does not match journal chain")
        elif events:
            if not repair_missing:
                raise JournalError("journal head is missing")
            head_needs_repair = True
        elif repair_missing:
            head_needs_repair = True

        # No persistent repair begins until every existing event, chain row,
        # and head has proved either valid or an accepted stale/missing suffix.
        for expected in expected_chains[persisted_count:]:
            self.anchor.append_bytes("journal", "chain.jsonl", data=canonical_bytes(expected) + b"\n")
        if head_needs_repair:
            _atomic_bytes(self.anchor, "journal", "head.json", data=head_bytes)
        return list(events), list(expected_chains)

    @classmethod
    def _is_stale_head(
        cls,
        raw_head: bytes,
        head: dict[str, Any],
        events: list[dict[str, Any]],
        expected_chains: list[dict[str, Any]],
        persisted_count: int,
    ) -> bool:
        """Accept only a head this journal published for an already-chained event.

        Every event's sequence is its index, so the one candidate a head can
        match is the head of its own declared sequence; comparing that one
        candidate is the whole recoverable set, without rebuilding it.
        """

        sequence = head["sequence"]
        if sequence == -1:
            return raw_head == _EMPTY_HEAD_BYTES
        return 0 <= sequence < persisted_count and raw_head == cls._head_bytes(events, expected_chains, sequence)

    def reconcile(self) -> dict[str, Any]:
        """Repair only crash-left chain/head suffixes; reject content tampering."""

        with self._lock():
            events, chains = self._validate_chain_unlocked(repair_missing=True)
            return {"valid": True, "sequence": events[-1]["sequence"] if events else -1, "entries": len(events), "chain_entries": len(chains)}

    def append(self, envelope: dict[str, Any], *, before_fsync: FaultHook | None = None) -> dict[str, Any]:
        """Append one validated envelope and fsync event, chain, and head."""

        try:
            envelope = validate_journal_envelope(envelope)
        except ValueError as error:
            raise JournalError(str(error)) from error
        with self._lock():
            events, chains = self._validate_chain_unlocked(repair_missing=True)
            if any(item["entry_id"] == envelope["entry_id"] for item in events):
                return envelope
            expected_sequence = events[-1]["sequence"] + 1 if events else 0
            if envelope["sequence"] != expected_sequence:
                raise JournalError(f"expected sequence {expected_sequence}, got {envelope['sequence']}")
            event_bytes = canonical_bytes(envelope) + b"\n"
            parent_fd = self.anchor.dirfd("journal")
            fd: int | None = None
            try:
                fd = os.open(
                    "events.jsonl",
                    os.O_WRONLY | os.O_APPEND | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=parent_fd,
                )
                check_private_stat(os.fstat(fd), self.events_path, directory=False, error_type=UnsafeStoreError)
                stream = os.fdopen(fd, "wb")
                fd = None
                with stream:
                    stream.write(event_bytes)
                    stream.flush()
                    if before_fsync is not None:
                        before_fsync("after_record_publish_before_journal_fsync")
                    os.fsync(stream.fileno())
                os.fsync(parent_fd)
            finally:
                try:
                    if fd is not None:
                        os.close(fd)
                finally:
                    os.close(parent_fd)
            previous = chains[-1]["chain_sha256"] if chains else _EMPTY_CHAIN_SHA256
            chain = self._chain_value(envelope, previous)
            self.anchor.append_bytes("journal", "chain.jsonl", data=canonical_bytes(chain) + b"\n")
            head = {"sequence": envelope["sequence"], "chain_sha256": chain["chain_sha256"], "entry_id": envelope["entry_id"]}
            _atomic_bytes(self.anchor, "journal", "head.json", data=canonical_bytes(head))
            return envelope

    def entries(self) -> list[dict[str, Any]]:
        with self._lock():
            events, _ = self._validate_chain_unlocked(repair_missing=False)
            previous = -1
            seen: set[str] = set()
            for event in events:
                if event["sequence"] != previous + 1 or event["entry_id"] in seen:
                    raise JournalError("journal sequence or entry IDs are not strictly ordered")
                previous = event["sequence"]
                seen.add(event["entry_id"])
            return events

    def get(self, entry_id: str) -> dict[str, Any] | None:
        return next((event for event in self.entries() if event["entry_id"] == entry_id), None)

    def high_watermark(self) -> int:
        events = self.entries()
        return events[-1]["sequence"] if events else -1


__all__ = ["FaultHook", "Journal", "JournalError", "PersistedJournalSnapshot"]
