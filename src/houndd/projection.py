"""HSP-20: disposable SQLite projection rebuilt only from journal truth."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any, Callable

from ._safety import AnchoredRoot, check_private_stat
from .journal import Journal
from .store import RecordStore, StoreError, UnsafeStoreError


class ProjectionError(StoreError):
    """The disposable projection cannot be rebuilt safely."""


class Projection:
    """A query aid whose rows are never used as canonical truth."""

    def __init__(self, root: str | os.PathLike[str], *, create: bool = False) -> None:
        root_path = Path(root)
        if root_path.is_symlink():
            raise UnsafeStoreError(f"{root_path} must not be a symlink")
        self.root = root_path.resolve(strict=False)
        self.path = self.root / "index.sqlite"
        self.anchor: AnchoredRoot | None = None
        try:
            if self.root.exists():
                info = self.root.stat()
                if hasattr(os, "getuid") and info.st_uid != os.getuid():
                    raise UnsafeStoreError(f"{self.root} is not owned by the current user")
                if info.st_mode & 0o077:
                    raise UnsafeStoreError(f"{self.root} has group/world permissions")
                self.anchor = AnchoredRoot(self.root, error_type=UnsafeStoreError)
            elif create:
                self.root.mkdir(exist_ok=True)
                self.root.chmod(0o700)
                self.anchor = AnchoredRoot(self.root, error_type=UnsafeStoreError)
            if self.anchor is not None:
                if "index.sqlite" in self.anchor.listdir():
                    check_private_stat(self.anchor.stat("index.sqlite"), self.path, directory=False, error_type=UnsafeStoreError)
        except Exception:
            self.close()
            raise

    def _ensure_anchor(self, *, create: bool = False) -> AnchoredRoot:
        if self.anchor is not None:
            return self.anchor
        if not self.root.exists():
            if not create:
                raise UnsafeStoreError(f"{self.root} is missing")
            self.root.mkdir(exist_ok=True)
            self.root.chmod(0o700)
        self.anchor = AnchoredRoot(self.root, error_type=UnsafeStoreError)
        return self.anchor

    def close(self) -> None:
        anchor = getattr(self, "anchor", None)
        if anchor is not None:
            anchor.close()

    def __enter__(self) -> "Projection":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _open_index(self, anchor: AnchoredRoot, *, writable: bool, create: bool = False) -> tuple[int, os.stat_result]:
        """Open the projection leaf once, without ever handing SQLite its name.

        SQLite canonicalizes ``/proc/self/fd/<fd>`` before opening it, which
        reintroduces a leaf-name race.  We therefore copy bytes between this
        held descriptor and an in-memory SQLite connection instead.
        """

        flags = os.O_RDWR if writable else os.O_RDONLY
        if create:
            flags |= os.O_CREAT
        descriptor = anchor.open_file("index.sqlite", flags=flags, mode=0o600)
        try:
            if writable:
                os.fchmod(descriptor, 0o600)
            info = os.fstat(descriptor)
            check_private_stat(info, self.path, directory=False, error_type=UnsafeStoreError)
            return descriptor, info
        except Exception:
            os.close(descriptor)
            raise

    @staticmethod
    def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
        return left.st_dev == right.st_dev and left.st_ino == right.st_ino

    def _visible_index_stat(self, anchor: AnchoredRoot) -> os.stat_result:
        """lstat the visible leaf from the anchored directory, never following it."""

        directory_fd = anchor.dirfd()
        try:
            info = os.stat("index.sqlite", dir_fd=directory_fd, follow_symlinks=False)
        finally:
            os.close(directory_fd)
        check_private_stat(info, self.path, directory=False, error_type=UnsafeStoreError)
        return info

    def _assert_index_absent(self, anchor: AnchoredRoot) -> None:
        check_private_stat(anchor.stat(), self.root, directory=True, error_type=UnsafeStoreError)
        try:
            self._visible_index_stat(anchor)
        except FileNotFoundError:
            check_private_stat(anchor.stat(), self.root, directory=True, error_type=UnsafeStoreError)
            return
        raise UnsafeStoreError(f"{self.path} unexpectedly exists")

    def _validate_bound_index(self, anchor: AnchoredRoot, descriptor: int, opened: os.stat_result) -> None:
        """Reject replacement, symlink, or swap-back races before acknowledging work."""

        check_private_stat(anchor.stat(), self.root, directory=True, error_type=UnsafeStoreError)
        held = os.fstat(descriptor)
        check_private_stat(held, self.path, directory=False, error_type=UnsafeStoreError)
        # A rename-away/rename-back changes ctime even if dev/ino are restored.
        if not self._same_file(held, opened) or held.st_ctime_ns != opened.st_ctime_ns:
            raise UnsafeStoreError(f"{self.path} changed while it was in use")
        visible = self._visible_index_stat(anchor)
        if not self._same_file(visible, held) or visible.st_ctime_ns != held.st_ctime_ns:
            raise UnsafeStoreError(f"{self.path} is no longer the opened projection")
        check_private_stat(anchor.stat(), self.root, directory=True, error_type=UnsafeStoreError)

    @staticmethod
    def _read_descriptor(descriptor: int, size: int) -> bytes:
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        if remaining:
            raise ProjectionError("projection changed while it was being read")
        return b"".join(chunks)

    @staticmethod
    def _write_descriptor(descriptor: int, data: bytes) -> None:
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.ftruncate(descriptor, 0)
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:  # pragma: no cover - os.write either writes or raises
                raise OSError("could not write projection")
            view = view[written:]
        os.fsync(descriptor)

    def _connect(self, descriptor: int, opened: os.stat_result, *, read_only: bool) -> sqlite3.Connection:
        """Use SQLite in memory, with the store database held by ``descriptor``.

        The descriptor remains open until its connection is closed by the
        caller.  This avoids SQLite's pathname canonicalization and also
        prevents on-disk journal/WAL sidecars from being created through a
        mutable leaf name.
        """

        connection = sqlite3.connect(":memory:")
        try:
            if read_only:
                connection.deserialize(self._read_descriptor(descriptor, opened.st_size))
                connection.execute("PRAGMA query_only=ON")
            else:
                connection.execute("PRAGMA secure_delete=ON")
            connection.row_factory = sqlite3.Row
            return connection
        except Exception:
            connection.close()
            raise

    def rebuild(
        self,
        journal: Journal,
        records: RecordStore,
        *,
        fault: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        """Replace all rows in one SQLite transaction from committed events."""

        anchor = self._ensure_anchor(create=True)
        check_private_stat(anchor.stat(), self.root, directory=True, error_type=UnsafeStoreError)
        events = journal.entries()
        descriptor, opened = self._open_index(anchor, writable=True, create=True)
        connection: sqlite3.Connection | None = None
        try:
            connection = self._connect(descriptor, opened, read_only=False)
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DROP TABLE IF EXISTS entries")
            connection.execute("DROP TABLE IF EXISTS blobs")
            connection.execute(
                """CREATE TABLE entries (
                    sequence INTEGER NOT NULL,
                    entry_id TEXT PRIMARY KEY,
                    appended_at TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    record_hash TEXT NOT NULL,
                    object_key TEXT NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    access TEXT NOT NULL,
                    policy_id TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    evidence_status TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    capability TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    canonical_url TEXT NOT NULL
                )"""
            )
            connection.execute(
                """CREATE TABLE blobs (
                    content_sha256 TEXT PRIMARY KEY,
                    byte_length INTEGER NOT NULL
                )"""
            )
            for event in events:
                if fault is not None:
                    fault("during_projection_rebuild")
                record_id = event["artifact"]["record_id"]
                if not records.verify_record(record_id, event["artifact"]["hash"]):
                    raise ProjectionError(f"record {record_id} failed before projection")
                content_sha256 = event["dedupe"]["content_sha256"]
                blob = records.blobs.get(content_sha256)
                producer = event["producer"]
                source = event["source"]
                classification = event["classification"]
                connection.execute(
                    "INSERT INTO entries VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        event["sequence"],
                        event["entry_id"],
                        event["appended_at"],
                        record_id,
                        event["artifact"]["hash"],
                        event["dedupe"]["object_key"],
                        content_sha256,
                        event["access"],
                        event["policy_id"],
                        classification["outcome"],
                        classification["evidence_status"],
                        producer["owner_id"],
                        producer["capability"],
                        producer["run_id"],
                        source["provider"],
                        source["canonical_url"],
                    ),
                )
                connection.execute(
                    "INSERT OR IGNORE INTO blobs VALUES (?, ?)",
                    (content_sha256, len(blob)),
                )
            connection.commit()
            self._validate_bound_index(anchor, descriptor, opened)
            self._write_descriptor(descriptor, connection.serialize())
            # Writing changes ctime, so take a new held snapshot for the
            # visible-name check required before returning success.
            written = os.fstat(descriptor)
            check_private_stat(written, self.path, directory=False, error_type=UnsafeStoreError)
            visible = self._visible_index_stat(anchor)
            held = os.fstat(descriptor)
            if (
                not self._same_file(visible, written)
                or not self._same_file(held, written)
                or visible.st_ctime_ns != written.st_ctime_ns
                or held.st_ctime_ns != written.st_ctime_ns
            ):
                raise UnsafeStoreError(f"{self.path} is no longer the opened projection")
            check_private_stat(anchor.stat(), self.root, directory=True, error_type=UnsafeStoreError)
            return {"valid": True, "entries": len(events), "database": str(self.path)}
        except Exception:
            if connection is not None:
                connection.rollback()
            raise
        finally:
            if connection is not None:
                connection.close()
            os.close(descriptor)

    def rows(self) -> list[dict[str, Any]]:
        if not self.root.exists():
            return []
        anchor = self._ensure_anchor()
        check_private_stat(anchor.stat(), self.root, directory=True, error_type=UnsafeStoreError)
        if "index.sqlite" not in anchor.listdir():
            self._assert_index_absent(anchor)
            return []
        descriptor, opened = self._open_index(anchor, writable=False)
        connection: sqlite3.Connection | None = None
        try:
            connection = self._connect(descriptor, opened, read_only=True)
            rows = [dict(row) for row in connection.execute("SELECT * FROM entries ORDER BY sequence, entry_id")]
            self._validate_bound_index(anchor, descriptor, opened)
            return rows
        except sqlite3.Error as error:
            raise ProjectionError("projection is unreadable") from error
        finally:
            if connection is not None:
                connection.close()
            os.close(descriptor)

    def delete(self) -> None:
        if not self.root.exists():
            return
        anchor = self._ensure_anchor()
        check_private_stat(anchor.stat(), self.root, directory=True, error_type=UnsafeStoreError)
        if "index.sqlite" not in anchor.listdir():
            self._assert_index_absent(anchor)
            return
        descriptor, opened = self._open_index(anchor, writable=False)
        directory_fd = anchor.dirfd()
        try:
            self._validate_bound_index(anchor, descriptor, opened)
            os.unlink("index.sqlite", dir_fd=directory_fd)
            check_private_stat(anchor.stat(), self.root, directory=True, error_type=UnsafeStoreError)
            held = os.fstat(descriptor)
            if held.st_nlink != 0:
                raise UnsafeStoreError(f"{self.path} was not unlinked")
            try:
                self._visible_index_stat(anchor)
            except FileNotFoundError:
                pass
            else:
                raise UnsafeStoreError(f"{self.path} still exists after deletion")
        finally:
            os.close(directory_fd)
            os.close(descriptor)


__all__ = ["Projection", "ProjectionError"]
