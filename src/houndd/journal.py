"""HSP-05: serialized append-only journal with sequence and chain integrity."""

from __future__ import annotations

import hashlib
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


@dataclass(frozen=True, slots=True)
class PersistedJournalSnapshot:
    """Exact persisted journal rows captured at one lock linearization point."""

    event_rows: tuple[bytes, ...]
    chain_rows: tuple[bytes, ...]
    head_bytes: bytes | None


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

    def _event_values_unlocked(self) -> list[dict[str, Any]]:
        try:
            raw = self.anchor.read_bytes("journal", "events.jsonl")
        except OSError as error:
            raise JournalError(f"cannot read journal file {self.events_path}") from error
        values = self._read_lines_from_raw(self.events_path, raw)
        try:
            return [validate_journal_envelope(value) for value in values]
        except ValueError as error:
            raise JournalError(f"journal envelope is invalid: {error}") from error

    def _chain_values_unlocked(self) -> list[dict[str, Any]]:
        try:
            raw = self.anchor.read_bytes("journal", "chain.jsonl")
        except OSError as error:
            raise JournalError(f"cannot read journal file {self.chain_path}") from error
        values = self._read_lines_from_raw(self.chain_path, raw)
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
                import json

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
            import json

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

    @classmethod
    def _validate_persisted_values(
        cls,
        events: list[dict[str, Any]],
        chains: list[dict[str, Any]],
        head_raw: bytes | None,
    ) -> None:
        try:
            chains = [_validate_persisted_chain_value(chain) for chain in chains]
        except ValueError as error:
            raise JournalError(str(error)) from error
        if len(chains) != len(events):
            if len(chains) < len(events):
                raise JournalError("journal chain is incomplete")
            raise JournalError("journal chain has entries without events")

        previous = _EMPTY_CHAIN_SHA256
        seen_entry_ids: set[str] = set()
        seen_event_hashes: set[str] = set()
        seen_chain_hashes: set[str] = set()
        for expected_sequence, (event, chain) in enumerate(zip(events, chains, strict=True)):
            entry_id = event["entry_id"]
            event_hash = hashlib.sha256(canonical_bytes(event)).hexdigest()
            if event["sequence"] != expected_sequence or entry_id in seen_entry_ids or event_hash in seen_event_hashes:
                raise JournalError("journal sequence, entry IDs, or event hashes are not strictly ordered")
            expected_chain = cls._chain_value(event, previous)
            if (
                canonical_bytes(chain) != canonical_bytes(expected_chain)
                or expected_chain["chain_sha256"] in seen_chain_hashes
            ):
                raise JournalError(f"journal chain mismatch at sequence {event['sequence']}")
            seen_entry_ids.add(entry_id)
            seen_event_hashes.add(event_hash)
            seen_chain_hashes.add(expected_chain["chain_sha256"])
            previous = expected_chain["chain_sha256"]

        if events:
            expected_head = {
                "sequence": events[-1]["sequence"],
                "chain_sha256": previous,
                "entry_id": events[-1]["entry_id"],
            }
            if head_raw is None:
                raise JournalError("journal head is missing")
            cls._head_from_raw(head_raw)
            if head_raw != canonical_bytes(expected_head):
                raise JournalError("journal head does not match journal chain")
            return

        if head_raw is not None:
            empty_head = {"sequence": -1, "chain_sha256": _EMPTY_CHAIN_SHA256, "entry_id": ""}
            cls._head_from_raw(head_raw)
            if head_raw != canonical_bytes(empty_head):
                raise JournalError("empty journal head is invalid")

    def verified_snapshot(self) -> PersistedJournalSnapshot:
        """Read and verify persisted journal truth without repairing or writing."""

        with self._lock():
            events_raw, chains_raw, head_raw = self._persisted_bytes_unlocked()
            event_values = self._read_lines_from_raw(self.events_path, events_raw)
            chain_values = self._read_lines_from_raw(self.chain_path, chains_raw)
            try:
                events = [validate_journal_envelope(value) for value in event_values]
            except ValueError as error:
                raise JournalError(f"journal envelope is invalid: {error}") from error
            self._validate_persisted_values(events, chain_values, head_raw)
            return PersistedJournalSnapshot(
                tuple(row + b"\n" for row in events_raw.split(b"\n")[:-1]),
                tuple(row + b"\n" for row in chains_raw.split(b"\n")[:-1]),
                head_raw,
            )

    def _validate_chain_unlocked(self, *, repair_missing: bool = False) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        events = self._event_values_unlocked()
        persisted_chains = self._chain_values_unlocked()
        if len(persisted_chains) > len(events):
            raise JournalError("journal chain has entries without events")
        if len(persisted_chains) < len(events) and not repair_missing:
            raise JournalError("journal chain is incomplete")
        previous = _EMPTY_CHAIN_SHA256
        seen_entry_ids: set[str] = set()
        seen_event_hashes: set[str] = set()
        seen_chain_hashes: set[str] = set()
        expected_chains: list[dict[str, Any]] = []
        for index, event in enumerate(events):
            event_hash = hashlib.sha256(canonical_bytes(event)).hexdigest()
            if event["sequence"] != index or event["entry_id"] in seen_entry_ids or event_hash in seen_event_hashes:
                raise JournalError("journal sequence, entry IDs, or event hashes are not strictly ordered")
            expected = self._chain_value(event, previous)
            if index < len(persisted_chains):
                if canonical_bytes(persisted_chains[index]) != canonical_bytes(expected):
                    raise JournalError(f"journal chain mismatch at sequence {event['sequence']}")
            if expected["chain_sha256"] in seen_chain_hashes:
                raise JournalError("journal chain hashes are not unique")
            expected_chains.append(expected)
            seen_entry_ids.add(event["entry_id"])
            seen_event_hashes.add(event_hash)
            seen_chain_hashes.add(expected["chain_sha256"])
            previous = expected["chain_sha256"]
        if events:
            head = {"sequence": events[-1]["sequence"], "chain_sha256": previous, "entry_id": events[-1]["entry_id"]}
        else:
            head = {"sequence": -1, "chain_sha256": _EMPTY_CHAIN_SHA256, "entry_id": ""}
        head_bytes = canonical_bytes(head)
        empty_head = {"sequence": -1, "chain_sha256": _EMPTY_CHAIN_SHA256, "entry_id": ""}
        recoverable_head_bytes = [canonical_bytes(empty_head)]
        recoverable_head_bytes.extend(
            canonical_bytes(
                {
                    "sequence": events[index]["sequence"],
                    "chain_sha256": expected_chains[index]["chain_sha256"],
                    "entry_id": events[index]["entry_id"],
                }
            )
            for index in range(len(persisted_chains))
        )
        head_needs_repair = False
        if self.anchor.exists("journal", "head.json"):
            try:
                raw_head = self.anchor.read_bytes("journal", "head.json")
                self._head_from_raw(raw_head)
            except (OSError, StoreError) as error:
                raise JournalError("journal head is unreadable") from error
            if raw_head == head_bytes and len(persisted_chains) == len(events):
                pass
            elif repair_missing and raw_head in recoverable_head_bytes:
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
        for expected in expected_chains[len(persisted_chains) :]:
            self.anchor.append_bytes("journal", "chain.jsonl", data=canonical_bytes(expected) + b"\n")
        if head_needs_repair:
            _atomic_bytes(self.anchor, "journal", "head.json", data=canonical_bytes(head))
        return events, expected_chains

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
