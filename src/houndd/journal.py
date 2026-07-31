"""HSP-05: serialized append-only journal with sequence and chain integrity."""

from __future__ import annotations

import hashlib
import os
import stat
from contextlib import contextmanager
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
        return self._read_lines_from_raw(self.chain_path, raw)

    @staticmethod
    def _read_lines_from_raw(path: Path, raw: bytes) -> list[dict[str, Any]]:
        if raw and not raw.endswith(b"\n"):
            raise JournalError(f"journal file {path} has a partial final line")
        result = []
        for line in raw.splitlines():
            try:
                import json

                value = json.loads(line.decode("utf-8"))
            except (UnicodeError, ValueError) as error:
                raise JournalError(f"journal file {path} has invalid JSON") from error
            if not isinstance(value, dict):
                raise JournalError(f"journal file {path} contains a non-object")
            if canonical_bytes(value) != line:
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

    def _validate_chain_unlocked(self, *, repair_missing: bool = False) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        events = self._event_values_unlocked()
        chains = self._chain_values_unlocked()
        if len(chains) > len(events):
            raise JournalError("journal chain has entries without events")
        if len(chains) < len(events) and not repair_missing:
            raise JournalError("journal chain is incomplete")
        previous = "0" * 64
        for index, event in enumerate(events):
            expected = self._chain_value(event, previous)
            if index < len(chains):
                if chains[index] != expected:
                    raise JournalError(f"journal chain mismatch at sequence {event['sequence']}")
            else:
                self.anchor.append_bytes("journal", "chain.jsonl", data=canonical_bytes(expected) + b"\n")
                chains.append(expected)
            previous = expected["chain_sha256"]
        if events:
            head = {"sequence": events[-1]["sequence"], "chain_sha256": previous, "entry_id": events[-1]["entry_id"]}
        else:
            head = {"sequence": -1, "chain_sha256": "0" * 64, "entry_id": ""}
        if self.anchor.exists("journal", "head.json"):
            try:
                import json

                persisted = json.loads(self.anchor.read_bytes("journal", "head.json").decode("utf-8"))
            except (OSError, UnicodeError, ValueError) as error:
                raise JournalError("journal head is unreadable") from error
            if persisted != head:
                if not repair_missing:
                    raise JournalError("journal head does not match journal chain")
                _atomic_bytes(self.anchor, "journal", "head.json", data=canonical_bytes(head))
        elif events:
            if not repair_missing:
                raise JournalError("journal head is missing")
            _atomic_bytes(self.anchor, "journal", "head.json", data=canonical_bytes(head))
        else:
            _atomic_bytes(self.anchor, "journal", "head.json", data=canonical_bytes(head))
        return events, chains

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
            try:
                fd = os.open(
                    "events.jsonl",
                    os.O_WRONLY | os.O_APPEND | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=parent_fd,
                )
                check_private_stat(os.fstat(fd), self.events_path, directory=False, error_type=UnsafeStoreError)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(event_bytes)
                    stream.flush()
                    if before_fsync is not None:
                        before_fsync("after_record_publish_before_journal_fsync")
                    os.fsync(stream.fileno())
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
            previous = chains[-1]["chain_sha256"] if chains else "0" * 64
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


__all__ = ["FaultHook", "Journal", "JournalError"]
