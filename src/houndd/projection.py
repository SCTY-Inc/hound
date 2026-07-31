"""HSP-20: disposable SQLite projection rebuilt only from journal truth."""

from __future__ import annotations

import os
import sqlite3
import stat
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

    def _connect(self, *, normalize_mode: bool, read_only: bool = False) -> sqlite3.Connection:
        if read_only:
            connection = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True)
        else:
            connection = sqlite3.connect(self.path)
        if normalize_mode:
            self.path.chmod(0o600)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA secure_delete=ON")
        return connection

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
        connection = self._connect(normalize_mode=True)
        try:
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
            return {"valid": True, "entries": len(events), "database": str(self.path)}
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def rows(self) -> list[dict[str, Any]]:
        if not self.root.exists():
            return []
        anchor = self._ensure_anchor()
        check_private_stat(anchor.stat(), self.root, directory=True, error_type=UnsafeStoreError)
        if "index.sqlite" not in anchor.listdir():
            return []
        check_private_stat(anchor.stat("index.sqlite"), self.path, directory=False, error_type=UnsafeStoreError)
        connection = self._connect(normalize_mode=False, read_only=True)
        try:
            return [dict(row) for row in connection.execute("SELECT * FROM entries ORDER BY sequence, entry_id")]
        except sqlite3.Error as error:
            raise ProjectionError("projection is unreadable") from error
        finally:
            connection.close()

    def delete(self) -> None:
        if not self.root.exists():
            return
        anchor = self._ensure_anchor()
        if "index.sqlite" not in anchor.listdir():
            return
        check_private_stat(anchor.stat("index.sqlite"), self.path, directory=False, error_type=UnsafeStoreError)
        directory_fd = anchor.dirfd()
        try:
            os.unlink("index.sqlite", dir_fd=directory_fd)
        finally:
            os.close(directory_fd)


__all__ = ["Projection", "ProjectionError"]
